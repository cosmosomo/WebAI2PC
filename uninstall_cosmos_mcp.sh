#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUTF8=1

if [[ ! -f "${SCRIPT_DIR}/src/cosmos_mcp/__init__.py" ]]; then
    echo "未找到 src/cosmos_mcp/__init__.py。请先将压缩包完整解压到任意目录，再进入解压后的目录运行 ./uninstall_cosmos_mcp.sh。" >&2
    exit 1
fi

export COSMOS_REPO_SRC="${SCRIPT_DIR}/src"
export PYTHONPATH="${SCRIPT_DIR}/src:${PYTHONPATH:-}"
STATE_ROOT="${COSMOS_MCP_STATE_DIR:-${LOCALPC_MCP_STATE_DIR:-${HOME}/.cosmos-mcp}}"
export COSMOS_STATE_ROOT="${STATE_ROOT}"

probe_ext_py() {
    local cand="$1"
    [[ -n "${cand}" && -x "${cand}" ]] || return 1
    "${cand}" -B -c "import os,sys; st=os.path.realpath(os.environ.get('COSMOS_STATE_ROOT','')).rstrip('/'); ex=os.path.realpath(sys.executable); in_st=bool(st and (ex==st or ex.startswith(st+'/'))); raise SystemExit(0 if (not in_st) and (3, 10) <= sys.version_info[:2] <= (3, 14) else 1)" >/dev/null 2>&1
}

probe_any_py() {
    local cand="$1"
    [[ -n "${cand}" && -x "${cand}" ]] || return 1
    "${cand}" -B -c "import sys; raise SystemExit(0 if (3, 10) <= sys.version_info[:2] <= (3, 14) else 1)" >/dev/null 2>&1
}

PY_BIN=""
if [[ -n "${PYTHON:-}" ]] && probe_any_py "${PYTHON}"; then
    PY_BIN="${PYTHON}"
elif [[ -x "${SCRIPT_DIR}/python-embed/bin/python3" ]]; then
    PY_BIN="${SCRIPT_DIR}/python-embed/bin/python3"
else
    for cand in \
        "$(command -v python3 2>/dev/null || true)" \
        "/opt/homebrew/bin/python3" \
        "/usr/local/bin/python3" \
        "${HOME}/miniconda3/bin/python3" \
        "${HOME}/anaconda3/bin/python3" \
        "/opt/miniconda3/bin/python3" \
        "/opt/anaconda3/bin/python3"; do
        if probe_ext_py "${cand}"; then
            PY_BIN="${cand}"
            break
        fi
    done
    if [[ -z "${PY_BIN}" && -d "${HOME}/.local/share/uv/python" ]]; then
        for uv_py in "${HOME}/.local/share/uv/python"/cpython-3.1*/bin/python3; do
            if probe_ext_py "${uv_py}"; then
                PY_BIN="${uv_py}"
                break
            fi
        done
    fi
fi

if [[ -z "${PY_BIN}" ]]; then
    if [[ -x "${STATE_ROOT}/python-embed/bin/python3" ]]; then
        PY_BIN="${STATE_ROOT}/python-embed/bin/python3"
    elif [[ -x "${STATE_ROOT}/.venv/bin/python" ]]; then
        PY_BIN="${STATE_ROOT}/.venv/bin/python"
    fi
fi

if [[ -z "${PY_BIN}" ]]; then
    echo "未检测到可用的 Python 3.10~3.14 环境，无法执行卸载脚本。" >&2
    exit 1
fi

run_cli() {
    "${PY_BIN}" -B -c "import os,sys; p=os.environ.get('COSMOS_REPO_SRC',''); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" "$@"
}

if [[ $# -gt 0 ]]; then
    if [[ "${1}" == "uninstall" ]]; then
        exec "${PY_BIN}" -B -c "import os,sys; p=os.environ.get('COSMOS_REPO_SRC',''); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" "$@"
    else
        exec "${PY_BIN}" -B -c "import os,sys; p=os.environ.get('COSMOS_REPO_SRC',''); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" uninstall "$@"
    fi
fi

if [[ -n "${COSMOS_NO_PAUSE:-}" || -n "${PYTEST_CURRENT_TEST:-}" || ! -t 0 ]]; then
    exec "${PY_BIN}" -B -c "import os,sys; p=os.environ.get('COSMOS_REPO_SRC',''); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" uninstall --purge -y
fi

echo "===================================================================="
echo " WebAI2PC (Cosmos MCP) 一键卸载向导"
echo "===================================================================="
echo " 说明：卸载仅清理软件运行环境与本地配置，不会触碰您的个人项目代码目录。"
echo ""
echo " [1] 彻底卸载并粉碎凭据（默认）"
echo "     停止后台服务与连接隧道、取消开机自启、移除桌面快捷方式，"
echo "     以 0x00 覆写销毁全部本地口令/密钥/OAuth 令牌并清空 ${STATE_ROOT}"
echo " [2] 标准卸载（保留修改撤回快照）"
echo "     停止后台服务、取消自启并移除快捷入口，保留 .undo_history 修改撤回快照"
echo " [Q] 取消退出"
echo ""
read -r -p "请输入选项 [1/2/Q] (直接回车默认 1): " CHOICE || CHOICE="1"
CHOICE="${CHOICE:-1}"

case "${CHOICE}" in
    [Qq])
        echo "已取消卸载操作。"
        exit 0
        ;;
    2)
        run_cli uninstall -y
        ;;
    *)
        run_cli uninstall --purge -y
        ;;
esac
