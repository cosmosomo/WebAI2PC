"""Unit tests for hardened release security, privacy, image integrity, and diff-range gates."""
from __future__ import annotations

import importlib.util
import io
import struct
import subprocess
import sys
import zlib
from pathlib import Path

from PIL import Image

REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_RELEASE_PATH = REPO_ROOT / "scripts" / "build_release.py"


def _load_build_release():
    spec = importlib.util.spec_from_file_location("build_release_sec_test", BUILD_RELEASE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_clean_png_bytes(size=(16, 16), color=(30, 60, 90)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


def _inject_png_text_chunk(png_bytes: bytes, key: str, val: str) -> bytes:
    payload = key.encode("latin1") + b"\x00" + val.encode("latin1")
    chunk = struct.pack(">I", len(payload)) + b"tEXt" + payload + struct.pack(">I", zlib.crc32(b"tEXt" + payload) & 0xFFFFFFFF)
    return png_bytes[:-12] + chunk + png_bytes[-12:]


def test_credential_leak_scanner_catches_all_high_risk_patterns():
    br = _load_build_release()
    samples = [
        ("github_token", "token = " + "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2"),
        ("github_token", "pat = " + "github_" + "pat_" + "11ABCDEFG_0123456789abcdef"),
        ("api_sk_token", "key = " + "sk-" + "proj-9fR4mK8vQ2pL7xZ5wN3bT6yH1jC0dG8s"),
        ("google_api_key", "g = " + "AI" + "za" + "SyD1234567890abcdefghijklmnopqrs"),
        ("slack_token", "s = " + "xox" + "b-1234567890-abcdef123456"),
        ("cf_tunnel_token", "cf = " + "eyJ" + "hIjoiMTIzNDU2Nzg5MCIsInQiOiJhYmNkZWZnaCJ9"),
        ("jwt_token", "j = " + "eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0.signaturePart12345"),
        ("private_key_block", "-----" + "BEGIN " + "OPENSSH " + "PRIVATE KEY" + "-----"),
        ("im_webhook_url", "https://" + "hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX"),
    ]
    for expected_tag, text in samples:
        hits = br.scan_text_credential_leaks(text)
        assert expected_tag in hits, f"Expected `{expected_tag}` for sample, got {hits}"

    assert br.scan_text_credential_leaks("api_key = " + "sk-" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxx") == []
    assert br.scan_text_credential_leaks("Normal documentation text without any secrets.") == []


def test_cross_machine_paths_and_internal_refs_scanner():
    br = _load_build_release()
    hits_win = br.scan_text_cross_machine_and_internal_leaks(r"path = C:\Us" + r"ers\RealDev99\project")
    assert any(h.startswith("user_home_path:") for h in hits_win)

    hits_mac = br.scan_text_cross_machine_and_internal_leaks("/Us" + "ers/realperson/work")
    assert any(h.startswith("user_home_path:") for h in hits_mac)

    assert br.scan_text_cross_machine_and_internal_leaks(r"C:\Users\Alice\Desktop\demo.txt") == []
    assert br.scan_text_cross_machine_and_internal_leaks("/Users/yourname/project") == []

    assert "windows_auto_hostname" in br.scan_text_cross_machine_and_internal_leaks("host=" + "DESK" + "TOP-1F758LV")
    assert "windows_auto_hostname" in br.scan_text_cross_machine_and_internal_leaks("host=" + "LAP" + "TOP-9A8B7C")
    assert br.scan_text_cross_machine_and_internal_leaks('<details id="desktop-local-clients-fold">') == []

    for sample in (
        "HUB-" + "EXP-5B8E7B8B",
        "custom_" + "mcp__d857e44b8551d15e00065fb1d5d5a1bc",
        "path/" + "_work" + "trees/tmp",
        "dir/" + ".run" + "time/handoff.md",
    ):
        hits = br.scan_text_cross_machine_and_internal_leaks(sample)
        assert "internal_agent_or_worktree_ref" in hits, f"Expected internal leak hit for {sample!r}"


def test_image_integrity_and_metadata_gate(monkeypatch):
    br = _load_build_release()
    clean_png = _make_clean_png_bytes()
    assert br.scan_image_bytes_integrity_and_metadata(clean_png, rel_path="assets/clean.png") == []

    # Standard harmless screenshot/editor metadata keys with benign values pass cleanly
    for benign_key, benign_val in (
        ("Software", "Snipaste 2.8.9"),
        ("Creation Time", "2026-11-28T00:00:00Z"),
        ("Description", "UI quickstart diagram"),
        ("Comment", "Exported for docs"),
        ("Author", "WebAI2PC Docs"),
        ("Title", "Studio Console"),
        ("Copyright", "MIT"),
        ("Source", "Display"),
    ):
        benign_png = _inject_png_text_chunk(clean_png, benign_key, benign_val)
        assert br.scan_image_bytes_integrity_and_metadata(benign_png, rel_path="assets/benign.png") == [], benign_key

    # Whitelisted metadata key whose value leaks private path, hostname, email, or custom forbidden token must be blocked
    leak_path_png = _inject_png_text_chunk(clean_png, "Comment", r"Saved from C:\Us" + r"ers\RealDev99\Desktop\shot.png")
    leak_path_issues = br.scan_image_bytes_integrity_and_metadata(leak_path_png, rel_path="assets/leak_path.png")
    assert any("Sensitive" in x and "Comment" in x for x in leak_path_issues), leak_path_issues

    monkeypatch.setenv("COSMOS_EXTRA_FORBIDDEN_TOKENS", "PrivateOwnerHandle99")
    leak_tok_png = _inject_png_text_chunk(clean_png, "Author", "Captured by PrivateOwnerHandle99")
    leak_tok_issues = br.scan_image_bytes_integrity_and_metadata(leak_tok_png, rel_path="assets/leak_tok.png")
    assert any("Sensitive" in x and "Author" in x for x in leak_tok_issues), leak_tok_issues

    # Unknown / non-whitelisted metadata chunk keys are still rejected
    unknown_key_png = _inject_png_text_chunk(clean_png, "Raw profile type exif", "00112233")
    unknown_issues = br.scan_image_bytes_integrity_and_metadata(unknown_key_png, rel_path="assets/unknown.png")
    assert any("Forbidden PNG metadata chunk `tEXt`" in x for x in unknown_issues), unknown_issues

    trunc_png = clean_png[:-20]
    trunc_issues = br.scan_image_bytes_integrity_and_metadata(trunc_png, rel_path="assets/trunc.png")
    assert len(trunc_issues) >= 1


def test_git_diff_range_scanner_catches_added_secret_and_internal_ref(tmp_path: Path):
    br = _load_build_release()
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True)

    f = tmp_path / "README.md"
    f.write_text("# Clean baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=tmp_path, check=True)

    f.write_text(
        "# Updated\n"
        + "leak = " + "gh" + "p_" + "Z9y8X7w6V5u4T3s2R1q0P9o8\n"
        + "ref = " + "HUB-" + "EXP-1234ABCD\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "leak"], cwd=tmp_path, check=True)

    errs = br.scan_git_diff_range(tmp_path, "HEAD~1..HEAD")
    assert any("github_token" in e for e in errs), errs
    assert any("internal_agent_or_worktree_ref" in e for e in errs), errs
