#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUTF8=1

if [[ ! -f "${SCRIPT_DIR}/src/cosmos_mcp/__init__.py" ]]; then
    echo "未找到 src/cosmos_mcp/__init__.py。请先将压缩包完整解压到任意目录，再进入解压后的目录运行 ./start_cosmos_mcp.sh。" >&2
    exit 1
fi

export PYTHONPATH="${SCRIPT_DIR}/src:${PYTHONPATH:-}"
STATE_ROOT="${COSMOS_MCP_STATE_DIR:-${LOCALPC_MCP_STATE_DIR:-${HOME}/.cosmos-mcp}}"

probe_py() {
    local cand="$1"
    [[ -n "${cand}" && -x "${cand}" ]] || return 1
    "${cand}" -B -c "import sys; raise SystemExit(0 if (3, 10) <= sys.version_info[:2] <= (3, 14) else 1)" >/dev/null 2>&1
}

PY_BIN=""
if [[ -n "${PYTHON:-}" ]]; then
    PY_BIN="${PYTHON}"
elif [[ -x "${SCRIPT_DIR}/python-embed/bin/python3" ]]; then
    PY_BIN="${SCRIPT_DIR}/python-embed/bin/python3"
elif [[ -x "${STATE_ROOT}/.venv/bin/python" ]]; then
    PY_BIN="${STATE_ROOT}/.venv/bin/python"
else
    for cand in \
        "$(command -v python3 2>/dev/null || true)" \
        "/opt/homebrew/bin/python3" \
        "/usr/local/bin/python3" \
        "${HOME}/miniconda3/bin/python3" \
        "${HOME}/anaconda3/bin/python3" \
        "/opt/miniconda3/bin/python3" \
        "/opt/anaconda3/bin/python3"; do
        if probe_py "${cand}"; then
            PY_BIN="${cand}"
            break
        fi
    done
    if [[ -z "${PY_BIN}" && -d "${HOME}/.local/share/uv/python" ]]; then
        for uv_py in "${HOME}/.local/share/uv/python"/cpython-3.1*/bin/python3; do
            if probe_py "${uv_py}"; then
                PY_BIN="${uv_py}"
                break
            fi
        done
    fi
fi

if [[ -z "${PY_BIN}" ]]; then
    echo "未检测到可用的 Python 3.10~3.14 环境，请先从 python.org、Homebrew 或 uv 安装 Python 3.12。" >&2
    exit 1
fi

FIRST_ARG="${1:-}"
case "${FIRST_ARG}" in
    start|stop|restart|status|doctor|permissions|agent-setup|reset-password|uninstall|setup|daemon|stdio|bind-desktop|vps-caddy-snippet|update|--help|-h|--version)
        exec "${PY_BIN}" -B -m cosmos_mcp.launcher.cli "$@"
        ;;
esac

if [[ "$(uname -s)" == "Darwin" || ( -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" && -z "${SSH_CONNECTION:-}${SSH_TTY:-}" ) ]]; then
    BROWSER_FLAG="--open-browser"
else
    BROWSER_FLAG="--no-browser"
fi
exec "${PY_BIN}" -B -m cosmos_mcp.launcher.cli start "${BROWSER_FLAG}" "$@"
