from __future__ import annotations

import asyncio
import ctypes
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

if sys.platform == "win32":
    ctypes.windll.kernel32.SetErrorMode(0x8003)

CREATE_NO_WINDOW = 0x08000000

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from cosmos_mcp.core import exec as exec_ops  # noqa: E402
from cosmos_mcp.core import fs as fs_ops  # noqa: E402
from cosmos_mcp.core import net_power, proc, sandbox_hook, web  # noqa: E402
from cosmos_mcp.core.guard import WorkspaceGuard  # noqa: E402


class S2CoreExecWebTests(unittest.TestCase):
    """Real-machine verification suite for S2 core execution, sandbox hook, and web extraction."""

    scratch_root: Path
    _tmp_dir_ctx: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp_dir_ctx = tempfile.TemporaryDirectory(prefix=f"cosmos_s2_test_{os.getpid()}_")
        cls.scratch_root = Path(cls._tmp_dir_ctx.name)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_tmp_dir_ctx") and cls._tmp_dir_ctx is not None:
            import gc

            for _ in range(6):
                try:
                    cls._tmp_dir_ctx.cleanup()
                    break
                except OSError:
                    gc.collect()
                    time.sleep(0.15)

    def _make_case_dirs(self, name: str) -> tuple[Path, Path]:
        case_dir = self.scratch_root / name
        ws_dir = case_dir / "workspace"
        st_dir = case_dir / "state_root"
        ws_dir.mkdir(parents=True, exist_ok=True)
        st_dir.mkdir(parents=True, exist_ok=True)
        return ws_dir, st_dir

    def test_01_static_cleanliness_and_job_defaults(self) -> None:
        core_files = [
            SRC_DIR / "cosmos_mcp" / "core" / "proc.py",
            SRC_DIR / "cosmos_mcp" / "core" / "net_power.py",
            SRC_DIR / "cosmos_mcp" / "core" / "sandbox_hook.py",
            SRC_DIR / "cosmos_mcp" / "core" / "exec.py",
            SRC_DIR / "cosmos_mcp" / "core" / "web.py",
        ]
        forbidden_substrings = (
            "E:" + "\\" + "Anaconda",
            "E:" + "\\\\" + "Anaconda",
            'GOPROXY="off"',
            'CARGO_NET_OFFLINE="true"',
        )
        for fp in core_files:
            content = fp.read_text(encoding="utf-8")
            for bad in forbidden_substrings:
                self.assertNotIn(bad, content, f"Forbidden string {bad!r} found in {fp.name}")

        self.assertEqual(proc.DEFAULT_MAX_PROC_MEM_MB, 16384)
        self.assertEqual(proc.DEFAULT_BG_MAX_TTL_SECONDS, 14400)
        self.assertNotIn("send_input", inspect.signature(exec_ops.bg_command).parameters)
        self.assertNotIn("send_input", inspect.signature(proc.ProcessManager.manage_bg_command).parameters)

        if sys.platform == "win32":
            child = subprocess.Popen(
                [proc.resolve_console_python(sys.executable), "-B", "-c", "import time; time.sleep(0.15)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
            try:
                jh = proc.OwnedJobHandle(proc.assign_win32_job_kill_on_close(child.pid, max_mem_mb=0))
                self.assertIsNotNone(jh.handle)
                child.wait(timeout=5.0)
                jh.close()
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=2.0)

    def test_02_py312_dataclass_unittest_pytest_and_repaired_sandbox_hook(self) -> None:
        ws_dir, st_dir = self._make_case_dirs("case_dataclass_hook")
        guard = WorkspaceGuard(ws_dir, restrict_to_workspace=True, tier="L3", state_root=st_dir)
        pm = proc.ProcessManager(guard=guard, state_root=st_dir)

        # 1) Default L3 execution does NOT inject sys.addaudithook sitecustomize.py
        env_check = asyncio.run(
            exec_ops.run_python(
                "import json, os, sys; print(json.dumps({'l3_ws': os.environ.get('COSMOS_L3_WORKSPACES'), 'has_guard': any('l3_py_guard' in p for p in sys.path)}))",
                cwd=str(ws_dir),
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertTrue(env_check["ok"], env_check)
        env_doc = json.loads(env_check["stdout"].strip())
        self.assertIsNone(env_doc["l3_ws"])
        self.assertFalse(env_doc["has_guard"])

        # 2) Write a real @dataclass test module inside workspace and run both unittest & pytest
        sample_test_file = ws_dir / "test_sample_dc.py"
        sample_test_file.write_text(
            textwrap.dedent(
                """
                from dataclasses import dataclass, replace
                import os
                import unittest

                os.putenv("OMP_NUM_THREADS", "2")
                import numpy as np
                import pandas as pd


                @dataclass
                class HyperParams:
                    lr: float = 1e-3
                    epochs: int = 10
                    tag: str = "baseline"


                @dataclass(kw_only=True)
                class ExperimentSpec:
                    name: str = "exp_a"
                    seed: int = 42


                class DataclassExecTest(unittest.TestCase):
                    def test_dataclass_and_scientific_imports(self) -> None:
                        hp = replace(HyperParams(), epochs=25)
                        spec = ExperimentSpec(seed=7)
                        df = pd.DataFrame({"x": np.arange(4), "y": [1.0, 2.0, 3.0, 4.0]})
                        self.assertEqual(hp.epochs, 25)
                        self.assertEqual(spec.seed, 7)
                        self.assertEqual(int(df["x"].sum()), 6)
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )

        ut_res = asyncio.run(
            exec_ops.run_command(
                "python -B -m unittest discover -s . -p test_sample_dc.py",
                cwd=str(ws_dir),
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertTrue(ut_res["ok"], ut_res)
        self.assertEqual(ut_res["exit_code"], 0)

        pt_res = asyncio.run(
            exec_ops.run_command(
                "python -B -m pytest -q -o cache_dir=.pytest_tmp test_sample_dc.py",
                cwd=str(ws_dir),
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertTrue(pt_res["ok"], pt_res)
        self.assertEqual(pt_res["exit_code"], 0)

        # 3) Explicitly enable strict L3 sandbox hook and verify all 4 fixes:
        #    ① @dataclass (__defaults__/__kwdefaults__) works
        #    ② os.putenv thread vars + import numpy/pandas works
        #    ③ business <workspace>/auth.json is allowed, while <state_root>/secrets/auth.json is blocked
        #    ④ read-only ~/.cache and ~/.matplotlib access is allowed
        sec_dir = st_dir / "secrets"
        sec_dir.mkdir(parents=True, exist_ok=True)
        mcp_secret_auth = sec_dir / "auth.json"
        mcp_secret_auth.write_text('{"local_api_token": "secret_mcp_tok"}', encoding="utf-8")

        biz_auth = ws_dir / "auth.json"
        biz_auth.write_text('{"service": "user_app_oauth_fixture"}', encoding="utf-8")
        probe_cfg_file = ws_dir / "runtime_targets.json"
        probe_cfg_file.write_text(
            json.dumps(
                {
                    "mcp_secret_auth": str(mcp_secret_auth),
                    "cache_dir": str(Path.home() / ".cache"),
                    "mpl_home": str(Path.home() / ".matplotlib"),
                }
            ),
            encoding="utf-8",
        )

        pm_strict = proc.ProcessManager(guard=guard, state_root=st_dir, enable_sandbox_hook=True)
        strict_code = textwrap.dedent(
            """
            import json, os
            from pathlib import Path
            from dataclasses import dataclass, replace

            os.putenv("OMP_NUM_THREADS", "1")
            os.putenv("OPENBLAS_NUM_THREADS", "1")
            import numpy as np
            import pandas as pd

            @dataclass
            class ModelCfg:
                hidden: int = 128
                dropout: float = 0.1

            cfg = replace(ModelCfg(), hidden=256)
            biz_data = json.loads(Path("auth.json").read_text(encoding="utf-8"))
            targets = json.loads(Path("runtime_targets.json").read_text(encoding="utf-8"))

            blocked_mcp_auth = False
            blocked_msg = ""
            try:
                Path(targets["mcp_secret_auth"]).read_text(encoding="utf-8")
            except PermissionError as exc:
                blocked_mcp_auth = True
                blocked_msg = str(exc)

            # Read-only probing of ~/.cache and ~/.matplotlib must succeed, while writing to ~/.cache must fail
            cache_dir = Path(targets["cache_dir"])
            mpl_home = Path(targets["mpl_home"])
            if cache_dir.is_dir():
                _ = os.listdir(cache_dir)[:3]
            if mpl_home.is_dir():
                _ = os.listdir(mpl_home)[:3]

            cache_write_blocked = False
            try:
                (cache_dir / "_cosmos_s2_illegal_write.tmp").write_text("x", encoding="utf-8")
            except PermissionError:
                cache_write_blocked = True

            print(json.dumps({
                "hidden": cfg.hidden,
                "biz_service": biz_data["service"],
                "blocked_mcp_auth": blocked_mcp_auth,
                "blocked_msg": blocked_msg,
                "cache_write_blocked": cache_write_blocked,
                "rows": len(pd.DataFrame({"v": np.ones(3)})),
                "hook_active": bool(os.environ.get("COSMOS_L3_WORKSPACES")),
            }))
            """
        )
        strict_res = asyncio.run(pm_strict.execute_python_stdin(strict_code, cwd=str(ws_dir)))
        self.assertTrue(strict_res["ok"], strict_res)
        strict_doc = json.loads(strict_res["stdout"].strip())
        self.assertTrue(strict_doc["hook_active"])
        self.assertEqual(strict_doc["hidden"], 256)
        self.assertEqual(strict_doc["biz_service"], "user_app_oauth_fixture")
        self.assertTrue(strict_doc["blocked_mcp_auth"])
        self.assertIn("COSMOS L3 SANDBOX", strict_doc["blocked_msg"])
        self.assertTrue(strict_doc["cache_write_blocked"])
        self.assertEqual(strict_doc["rows"], 3)

        # Strict pytest inside hooked child process also passes
        strict_pt = asyncio.run(
            pm_strict.execute(
                "python -B -m pytest -q -o cache_dir=.pytest_tmp test_sample_dc.py",
                cwd=str(ws_dir),
            )
        )
        self.assertTrue(strict_pt["ok"], strict_pt)

        # Read-only batch_probe also permits @dataclass + os.putenv + numpy/pandas + user auth.json while blocking MCP auth.json
        probe_res = exec_ops.batch_probe(
            project_path=ws_dir,
            python_code=textwrap.dedent(
                """
                import os
                os.putenv("OMP_NUM_THREADS", "1")
                from dataclasses import dataclass
                import numpy as np
                import pandas as pd

                @dataclass
                class Item:
                    k: str = "ok"

                biz_txt = (PROJ / "auth.json").read_text(encoding="utf-8")
                t_doc = json.loads((PROJ / "runtime_targets.json").read_text(encoding="utf-8"))
                mcp_blocked = False
                try:
                    Path(t_doc["mcp_secret_auth"]).read_text(encoding="utf-8")
                except PermissionError:
                    mcp_blocked = True

                cache_p = Path(t_doc["cache_dir"])
                if cache_p.is_dir():
                    _ = os.listdir(cache_p)[:2]

                RESULT = {
                    "item": Item().k,
                    "sum": int(pd.Series(np.array([2, 3, 5])).sum()),
                    "has_biz": "user_app_oauth_fixture" in biz_txt,
                    "mcp_blocked": mcp_blocked,
                }
                """
            ),
            proc_mgr=pm,
            guard=guard,
        )
        self.assertTrue(probe_res["ok"], probe_res)
        self.assertEqual(
            probe_res["result"],
            {"item": "ok", "sum": 10, "has_biz": True, "mcp_blocked": True},
        )

    def test_03_matplotlib_3mb_high_res_figure(self) -> None:
        ws_dir, st_dir = self._make_case_dirs("case_matplotlib_3mb")
        guard = WorkspaceGuard(ws_dir, restrict_to_workspace=True, tier="L3", state_root=st_dir)
        pm = proc.ProcessManager(guard=guard, state_root=st_dir)

        out_png = ws_dir / "highres_3mb_spectrum.png"
        saved_mpl = os.environ.pop("MPLCONFIGDIR", None)
        try:
            plot_code = textwrap.dedent(
                f"""
                import json, os
                from pathlib import Path
                import numpy as np
                import matplotlib
                matplotlib.use("Agg")
                import matplotlib.pyplot as plt

                rng = np.random.default_rng(20261123)
                img = rng.random((1350, 1350, 3), dtype=np.float32)
                fig, ax = plt.subplots(figsize=(13.5, 13.5), dpi=100)
                ax.imshow(img, interpolation="nearest")
                ax.set_title("High-Entropy Scientific Calibration Matrix")
                out_p = Path({str(out_png)!r})
                fig.savefig(out_p, format="png", dpi=100)
                plt.close(fig)
                print(json.dumps({{
                    "mplconfigdir": os.environ.get("MPLCONFIGDIR", ""),
                    "bytes": out_p.stat().st_size,
                }}))
                """
            )
            res = asyncio.run(exec_ops.run_python(plot_code, cwd=str(ws_dir), proc_mgr=pm, guard=guard))
        finally:
            if saved_mpl is not None:
                os.environ["MPLCONFIGDIR"] = saved_mpl

        self.assertTrue(res["ok"], res)
        meta = json.loads(res["stdout"].strip())
        self.assertTrue(out_png.is_file())
        size_bytes = out_png.stat().st_size
        self.assertGreaterEqual(size_bytes, 3 * 1024 * 1024, f"Expected >= 3 MiB PNG, got {size_bytes} bytes")
        with out_png.open("rb") as fh:
            self.assertEqual(fh.read(8), b"\x89PNG\r\n\x1a\n")
        self.assertTrue(meta["mplconfigdir"], "Expected automatic writable MPLCONFIGDIR")
        self.assertTrue(Path(meta["mplconfigdir"]).is_dir())

    def test_04_python_path_venv_conda_and_policy_selection(self) -> None:
        ws_dir, st_dir = self._make_case_dirs("case_python_path")
        guard = WorkspaceGuard(ws_dir, restrict_to_workspace=True, tier="L3", state_root=st_dir)
        pm = proc.ProcessManager(guard=guard, state_root=st_dir)

        host_py = proc.resolve_console_python(sys.executable)

        # 1) Explicit binary path via python_path
        r_bin = asyncio.run(
            exec_ops.run_python(
                "import sys; print(sys.executable)",
                cwd=str(ws_dir),
                python_path=host_py,
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertTrue(r_bin["ok"], r_bin)
        self.assertEqual(os.path.normcase(r_bin["python_exe"]), os.path.normcase(host_py))

        # 2) Real virtual environment created with `python -B -m venv` tested via `venv=` and `policy.python_path`
        custom_env_dir = ws_dir / "custom_sci_env"
        venv_build = subprocess.run(
            [host_py, "-B", "-m", "venv", "--without-pip", str(custom_env_dir)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            creationflags=CREATE_NO_WINDOW,
            timeout=30,
        )
        self.assertEqual(venv_build.returncode, 0, venv_build.stderr)

        r_venv = asyncio.run(
            exec_ops.run_python(
                "import json, sys; print(json.dumps({'prefix': sys.prefix, 'exe': sys.executable}))",
                cwd=str(ws_dir),
                venv=str(custom_env_dir),
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertTrue(r_venv["ok"], r_venv)
        venv_doc = json.loads(r_venv["stdout"].strip())
        self.assertEqual(
            os.path.normcase(str(Path(venv_doc["prefix"]).resolve())),
            os.path.normcase(str(custom_env_dir.resolve())),
        )

        # 3) Policy fallback (`policy={"python_path": ...}`) in both run_python and bg_command
        r_pol = asyncio.run(
            exec_ops.run_python(
                "import sys; print(sys.prefix)",
                cwd=str(ws_dir),
                policy={"python_path": str(custom_env_dir)},
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertTrue(r_pol["ok"], r_pol)
        self.assertEqual(
            os.path.normcase(str(Path(r_pol["stdout"].strip()).resolve())),
            os.path.normcase(str(custom_env_dir.resolve())),
        )

        bg_pol = exec_ops.bg_command(
            action="start",
            command="python -B -c \"import sys; print('BG_PREFIX=' + sys.prefix)\"",
            cwd=str(ws_dir),
            wait_seconds=3.0,
            python_path=str(custom_env_dir),
            proc_mgr=pm,
            guard=guard,
        )
        self.assertTrue(bg_pol["ok"], bg_pol)
        self.assertTrue(bg_pol["log_path"])
        if bg_pol.get("running"):
            bg_pol = exec_ops.bg_command(action="wait", job_id=bg_pol["job_id"], wait_seconds=5.0, proc_mgr=pm, guard=guard)
        prefix_lines = [ln.split("BG_PREFIX=", 1)[1].strip() for ln in bg_pol["log_tail"].splitlines() if "BG_PREFIX=" in ln]
        self.assertTrue(prefix_lines, bg_pol)
        self.assertEqual(
            os.path.normcase(str(proc.canonical_realpath(prefix_lines[-1]))),
            os.path.normcase(str(proc.canonical_realpath(custom_env_dir))),
        )

        # 4) Named Conda environment resolution if host has Conda environments registered
        conda_envs = proc._read_conda_environments_txt()
        named_envs = [p for p in conda_envs if p.parent.name.lower() == "envs" and (p / ("python.exe" if sys.platform == "win32" else "bin/python")).exists()]
        if named_envs:
            target_conda = named_envs[0]
            r_conda = asyncio.run(
                exec_ops.run_python(
                    "import sys; print(sys.executable)",
                    cwd=str(ws_dir),
                    conda_env=target_conda.name,
                    proc_mgr=pm,
                    guard=guard,
                )
            )
            self.assertTrue(r_conda["ok"], r_conda)
            self.assertEqual(
                os.path.normcase(str(Path(r_conda["stdout"].strip()).parent.resolve())),
                os.path.normcase(str(target_conda.resolve())),
            )

    def test_05_bg_promotion_ttl_14400_cr_folding_latest_and_get_status(self) -> None:
        ws_dir, st_dir = self._make_case_dirs("case_bg_observability")
        guard = WorkspaceGuard(ws_dir, restrict_to_workspace=True, tier="L3", state_root=st_dir)
        pm = proc.ProcessManager(guard=guard, state_root=st_dir)

        long_code = textwrap.dedent(
            """
            import sys, time
            sys.stdout.write("Training boot\\n")
            sys.stdout.flush()
            for pct in (10, 40, 75, 100):
                sys.stdout.write(f"\\rEpoch 1: {pct}%|{'#' * (pct // 10)}|")
                sys.stdout.flush()
                time.sleep(0.25)
            sys.stdout.write("\\n")
            for step in (1, 2, 3):
                sys.stdout.write(f"eval_step={step}\\r")
                sys.stdout.flush()
                time.sleep(0.2)
            sys.stdout.write("\\nFINAL_METRIC=0.9912\\n")
            sys.stdout.flush()
            """
        )

        # Default timeout_seconds=90.0 promoted after 0.35s MUST inherit 14400s TTL (never 120s!)
        prom_res = asyncio.run(
            exec_ops.run_python(
                long_code,
                cwd=str(ws_dir),
                timeout_seconds=90.0,
                sync_wait_cap_sec=0.35,
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertTrue(prom_res["ok"], prom_res)
        self.assertTrue(prom_res.get("promoted_to_background"), prom_res)
        self.assertGreaterEqual(int(prom_res["max_ttl_seconds"]), 14400)
        self.assertTrue(prom_res["log_path"])
        promoted_jid = prom_res["job_id"]

        # Empty-arg get_status() while running reports active_jobs
        st_running = exec_ops.get_status(proc_mgr=pm, guard=guard)
        self.assertTrue(st_running["ok"])
        active_ids = [j["job_id"] for j in st_running["active_jobs"]]
        self.assertIn(promoted_jid, active_ids)

        # job_id="latest" resolves to the promoted job and returns log_path
        st_latest = exec_ops.bg_command(action="status", job_id="latest", proc_mgr=pm, guard=guard)
        self.assertTrue(st_latest["ok"], st_latest)
        self.assertEqual(st_latest["job_id"], promoted_jid)
        self.assertEqual(st_latest["log_path"], prom_res["log_path"])
        self.assertGreaterEqual(int(st_latest["max_ttl_seconds"]), 14400)

        # Wait for completion via job_id="latest"
        done_res = exec_ops.bg_command(
            action="wait",
            job_id="latest",
            wait_seconds=8.0,
            tail_lines=30,
            proc_mgr=pm,
            guard=guard,
        )
        self.assertTrue(done_res["ok"], done_res)
        self.assertFalse(done_res["running"], done_res)
        self.assertEqual(done_res["exit_code"], 0)
        self.assertEqual(done_res["log_path"], prom_res["log_path"])

        tail_lines = done_res["log_tail"].splitlines()
        self.assertIn("Epoch 1: 100%|##########|", tail_lines)
        self.assertNotIn("Epoch 1: 10%|#|", tail_lines)
        self.assertNotIn("Epoch 1: 40%|####|", tail_lines)
        self.assertIn("eval_step=3", tail_lines)
        self.assertNotIn("eval_step=1", tail_lines)
        self.assertIn("FINAL_METRIC=0.9912", tail_lines)

        # Empty-arg get_status() after completion populates recent_jobs with folded tail (<=15 lines) & log_path
        st_after = exec_ops.get_status(proc_mgr=pm, guard=guard)
        self.assertEqual(st_after["active_jobs"], [])
        recent_map = {j["job_id"]: j for j in st_after["recent_jobs"]}
        self.assertIn(promoted_jid, recent_map)
        rec_job = recent_map[promoted_jid]
        self.assertEqual(rec_job["status"], "completed")
        self.assertTrue(rec_job["log_path"])
        self.assertGreater(rec_job["elapsed_sec"], 0.0)
        self.assertIn("FINAL_METRIC=0.9912", rec_job["log_tail"])
        self.assertLessEqual(len(rec_job["log_tail"].splitlines()), 15)

        # bg_command(action="start", wait_seconds=..., max_ttl_seconds=28800) preserves log_path & custom TTL
        bg_custom = exec_ops.bg_command(
            action="start",
            command="python -B -c \"print('CUSTOM_TTL_OK')\"",
            cwd=str(ws_dir),
            wait_seconds=2.0,
            max_ttl_seconds=28800,
            proc_mgr=pm,
            guard=guard,
        )
        self.assertTrue(bg_custom["ok"], bg_custom)
        self.assertEqual(bg_custom["action"], "start")
        self.assertTrue(bg_custom["log_path"], f"Missing log_path in {bg_custom}")
        self.assertEqual(bg_custom["max_ttl_seconds"], 28800)

        # Removed broken send_input action is rejected cleanly
        bad_send = exec_ops.bg_command(action="send_input", job_id="latest", proc_mgr=pm, guard=guard)
        self.assertFalse(bad_send["ok"])
        self.assertIn("Unsupported action", bad_send["error"])

    def test_06_web_links_indented_code_tables_pagination_and_ssrf(self) -> None:
        raw_html = textwrap.dedent(
            """
            <!DOCTYPE html>
            <html>
            <head>
              <title>Cosmos SDK Reference</title>
              <style>.hidden { display: none; }</style>
              <script>console.log("ignore_me");</script>
            </head>
            <body>
              <h1>Quickstart Guide</h1>
              <p>Read the <a href="/docs/install">Installation Manual</a> and <a href="../api/runner.html">Runner Spec</a> or visit <a href="https://example.com/releases">Releases</a>.</p>
              <pre><code class="language-python">
            def run_step(items):
                total = 0
                for x in items:
                    if x > 0:
                        total += x
                return total
              </code></pre>
              <table>
                <thead>
                  <tr><th>Option</th><th>Default</th><th>Description</th></tr>
                </thead>
                <tbody>
                  <tr><td><code>max_ttl_seconds</code></td><td>14400</td><td>See <a href="/docs/bg">Background TTL</a></td></tr>
                  <tr><td><code>max_chars</code></td><td>12000</td><td>Chunked page reader</td></tr>
                </tbody>
              </table>
              <p>Section tail: """
            + ("AlphaBetaGammaDelta " * 45)
            + """</p>
            </body>
            </html>
            """
        )

        page_url = "https://docs.example.org/guides/getting-started.html"
        title, extracted = web.html_to_readable_text(raw_html, base_url=page_url)
        self.assertEqual(title, "Cosmos SDK Reference")
        self.assertNotIn("ignore_me", extracted)

        # 1) Markdown links with relative urljoin resolution
        self.assertIn("[Installation Manual](https://docs.example.org/docs/install)", extracted)
        self.assertIn("[Runner Spec](https://docs.example.org/api/runner.html)", extracted)
        self.assertIn("[Releases](https://example.com/releases)", extracted)

        # 2) Fenced Python code block with 4-space & 8-space & 12-space leading indentation preserved
        self.assertIn("```python\ndef run_step(items):\n    total = 0\n    for x in items:\n        if x > 0:\n            total += x\n    return total\n```", extracted)

        # 3) HTML table rows separated by ` | ` and newlines (zero cell gluing)
        self.assertIn("Option | Default | Description", extracted)
        self.assertIn("`max_ttl_seconds` | 14400 | See [Background TTL](https://docs.example.org/docs/bg)", extracted)
        self.assertIn("`max_chars` | 12000 | Chunked page reader", extracted)

        # 4) Segmented pagination (`offset` & `max_chars` -> `has_more` & `next_offset`) + Fake-IP compatibility
        def fake_ip_resolver(host: str, port: int = 443) -> list[str]:
            _ = (host, port)
            return ["198.18.0.55"]

        def mock_transport(url: str, **kwargs: object) -> dict[str, object]:
            _ = kwargs
            return {
                "ok": True,
                "status": 200,
                "url": url,
                "headers": {"Content-Type": "text/html; charset=utf-8"},
                "text": raw_html,
                "truncated": False,
            }

        assembled: list[str] = []
        cur_offset = 0
        hops = 0
        while True:
            hops += 1
            self.assertLessEqual(hops, 20)
            chunk_res = web.run_web_research(
                action="fetch",
                url=page_url,
                max_chars=280,
                offset=cur_offset,
                resolver=fake_ip_resolver,
                transport_fn=mock_transport,
            )
            self.assertTrue(chunk_res["ok"], chunk_res)
            self.assertTrue(chunk_res.get("fake_ip"))
            assembled.append(chunk_res["content"])
            if not chunk_res["has_more"]:
                self.assertIsNone(chunk_res["next_offset"])
                break
            self.assertIsInstance(chunk_res["next_offset"], int)
            self.assertGreater(chunk_res["next_offset"], cur_offset)
            cur_offset = int(chunk_res["next_offset"])

        self.assertGreaterEqual(hops, 3)
        self.assertEqual("".join(assembled), extracted)

        # 5) SSRF protection remains intact against loopback targets without dirtying repo cwd
        _, st_ssrf = self._make_case_dirs("case_web_ssrf")
        from cosmos_mcp.core import guard as guard_mod

        prev_sr = guard_mod.DEFAULT_GUARD.state_root
        guard_mod.DEFAULT_GUARD.state_root = st_ssrf
        try:
            ssrf_res = web.run_web_research(action="fetch", url="http://127.0.0.1:9999/internal")
        finally:
            guard_mod.DEFAULT_GUARD.state_root = prev_sr
        self.assertFalse(ssrf_res["ok"])
        self.assertTrue(ssrf_res.get("blocked_by_ssrf_guard"))

    def test_07_pwsh_quote_rescue_net_power_and_protocol_tools_compat(self) -> None:
        ws_dir, st_dir = self._make_case_dirs("case_rescue_compat")
        guard = WorkspaceGuard(ws_dir, restrict_to_workspace=True, tier="L3", state_root=st_dir)
        pm = proc.ProcessManager(guard=guard, state_root=st_dir)

        if sys.platform == "win32":
            rescued = asyncio.run(
                exec_ops.run_command(
                    'python -c "import json; print(json.dumps({\\"k\\": \\"pwsh_rescued\\"}))"',
                    cwd=str(ws_dir),
                    proc_mgr=pm,
                    guard=guard,
                )
            )
            self.assertTrue(rescued["ok"], rescued)
            self.assertIn("pwsh_rescued", rescued["stdout"])

        # SleepInhibitor lifecycle + Path import regression check in net_power
        with net_power.SleepInhibitor(refresh_interval_sec=5.0) as inh:
            st = inh.status()
            self.assertIn("enabled", st)

        # protocol.tools positional bg_command compatibility check
        from cosmos_mcp.protocol.tools import build_core_tools

        specs, _ = build_core_tools(guard=guard, proc_mgr=pm)
        by_name = {s.base_name: s for s in specs}
        bg_res = asyncio.run(
            by_name["bg_command"].handler(
                action="start",
                command="python -B -c \"print('PROTO_BG_OK')\"",
                cwd=str(ws_dir),
                wait_seconds=2.0,
            )
        )
        self.assertTrue(bg_res["ok"], bg_res)
        self.assertTrue(bg_res["log_path"])
        self.assertEqual(bg_res["max_ttl_seconds"], 14400)

    def test_08_tier4_full_power_cross_directory_run_command_run_python_and_build_clean(self) -> None:
        ws_dir, st_dir = self._make_case_dirs("case_tier4_cross_dir_exec")
        ext_proj = self.scratch_root / "case_tier4_external_proj"
        ext_proj.mkdir(parents=True, exist_ok=True)
        (st_dir / "secrets").mkdir(parents=True, exist_ok=True)
        sec_f = st_dir / "secrets" / "auth.json"
        sec_f.write_text('{"token":"secret"}', encoding="utf-8")

        # Verify standalone `WorkspaceGuard(tier="tier4_full_power")` without `workspace_roots` forces `restrict_to_workspace=False`
        bare_l4 = WorkspaceGuard(tier="tier4_full_power", state_root=st_dir)
        self.assertEqual(bare_l4.tier, "L4")
        self.assertFalse(bare_l4.restrict_to_workspace)

        guard = WorkspaceGuard(ws_dir, restrict_to_workspace=True, tier="L3", state_root=st_dir)
        pm = proc.ProcessManager(guard=guard, state_root=st_dir)
        ext_data = ext_proj / "payload.txt"
        ext_data.write_text("EXTERNAL_OK_123\n", encoding="utf-8")

        # 1) Blocked in L3 (`tier3_workspace_dev`)
        l3_py = asyncio.run(
            exec_ops.run_python(
                f"from pathlib import Path; print(Path({str(ext_data)!r}).read_text('utf-8').strip())",
                cwd=str(ext_proj),
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertFalse(l3_py["ok"])

        l3_cmd = asyncio.run(
            exec_ops.run_command(
                f'python -B -c "print(open({str(ext_data)!r}).read().strip())"',
                cwd=str(ext_proj),
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertFalse(l3_cmd["ok"])

        # 2) Switch to L4 (`tier4_full_power`) -> cross-directory `run_python`, `run_command`, `batch_probe`, and build clean succeed
        guard.set_workspace_policy([ws_dir], restrict_to_workspace=False, tier_key="tier4_full_power", state_root=st_dir)
        self.assertEqual(guard.tier, "L4")
        self.assertFalse(guard.restrict_to_workspace)

        ext_out_py = ext_proj / "from_python.json"
        l4_py = asyncio.run(
            exec_ops.run_python(
                "import json\n"
                "from pathlib import Path\n"
                f"src = Path({str(ext_data)!r}).read_text('utf-8').strip()\n"
                f"Path({str(ext_out_py)!r}).write_text(json.dumps({{'read': src}}), encoding='utf-8')\n"
                "print('PY_CROSS_OK:' + src)\n",
                cwd=str(ext_proj),
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertTrue(l4_py["ok"], l4_py)
        self.assertEqual(l4_py["exit_code"], 0)
        self.assertIn("PY_CROSS_OK:EXTERNAL_OK_123", l4_py["stdout"])
        self.assertEqual(json.loads(ext_out_py.read_text(encoding="utf-8"))["read"], "EXTERNAL_OK_123")

        # Also works when `cwd` is omitted (defaults to primary workspace) while accessing external directory path
        l4_cmd = asyncio.run(
            exec_ops.run_command(
                f'python -B -c "import pathlib; print(\'CMD_CROSS_OK:\' + pathlib.Path(r\'{ext_data}\').read_text(\'utf-8\').strip())"',
                cwd="",
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertTrue(l4_cmd["ok"], l4_cmd)
        self.assertEqual(l4_cmd["exit_code"], 0)
        self.assertIn("CMD_CROSS_OK:EXTERNAL_OK_123", l4_cmd["stdout"])

        # Safe build cache cleanup (`dist`, `__pycache__`) in external project directory works in L4
        ext_dist = ext_proj / "dist"
        ext_dist.mkdir(parents=True, exist_ok=True)
        (ext_dist / "bundle.js").write_text("console.log(1);\n", encoding="utf-8")
        clean_cmd = "Remove-Item -Recurse -Force dist" if sys.platform == "win32" else "rm -rf dist"
        l4_clean = asyncio.run(
            exec_ops.run_command(
                clean_cmd,
                cwd=str(ext_proj),
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertTrue(l4_clean["ok"], l4_clean)
        self.assertFalse(ext_dist.exists())

        # `batch_probe` on external project directory works in L4
        bp_res = exec_ops.batch_probe(
            project_path=str(ext_proj),
            python_code="RESULT = rg('EXTERNAL_OK_123', glob='*.txt')",
            proc_mgr=pm,
            guard=guard,
        )
        self.assertTrue(bp_res["ok"], bp_res)
        self.assertTrue(bp_res["result"])

        # Destructive source deletion and `secrets/` access remain blocked even in L4
        del_src = asyncio.run(
            exec_ops.run_python(
                f"import os; os.remove({str(ext_data)!r})",
                cwd=str(ext_proj),
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertFalse(del_src["ok"])

        sec_py = asyncio.run(
            exec_ops.run_python(
                f"from pathlib import Path; print(Path({str(sec_f)!r}).read_text('utf-8'))",
                cwd=str(ext_proj),
                proc_mgr=pm,
                guard=guard,
            )
        )
        self.assertFalse(sec_py["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
