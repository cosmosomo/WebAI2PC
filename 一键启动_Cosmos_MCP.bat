@echo off
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0"
set "PYTHONDONTWRITEBYTECODE=1"
set "PYTHONUTF8=1"
set "_COSMOS_SILENT="
set "_COSMOS_PASSTHROUGH="
call :inspect_cli_args %*

if not exist "%~dp0src\cosmos_mcp\__init__.py" (
    echo 检测到您直接在压缩包预览窗口内双击了脚本。请先将压缩包完整解压到桌面或任意文件夹，再进入解压后的文件夹双击运行本脚本。
    if not defined _COSMOS_SILENT pause
    exit /b 1
)

set "COSMOS_REPO_SRC=%~dp0src"
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
set "COSMOS_STATE_ROOT=%COSMOS_MCP_STATE_DIR%"
if not defined COSMOS_STATE_ROOT set "COSMOS_STATE_ROOT=%LOCALPC_MCP_STATE_DIR%"
if not defined COSMOS_STATE_ROOT set "COSMOS_STATE_ROOT=%LOCALAPPDATA%\CosmosMCP"

if not defined _COSMOS_PASSTHROUGH if not defined _COSMOS_SILENT (
    echo 正在启动 Cosmos MCP 本地服务与控制面板（首次运行将自动准备独立运行环境并开启加密连接通道）...
)

REM 1) 优先检查随包附带的绿色免安装解释器 python-embed\python.exe
if exist "%~dp0python-embed\python.exe" (
    if defined _COSMOS_PASSTHROUGH (
        "%~dp0python-embed\python.exe" -B -c "import os,sys; p=os.environ.get('COSMOS_REPO_SRC',''); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" %*
    ) else (
        "%~dp0python-embed\python.exe" -B -c "import os,sys; p=os.environ.get('COSMOS_REPO_SRC',''); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" start --open-browser %*
    )
    goto :after_run
)

REM 2) 其次检查已初始化好的独立环境 .venv\Scripts\python.exe
if exist "%COSMOS_STATE_ROOT%\.venv\Scripts\python.exe" (
    if defined _COSMOS_PASSTHROUGH (
        "%COSMOS_STATE_ROOT%\.venv\Scripts\python.exe" -B -m cosmos_mcp.launcher.cli %*
    ) else (
        "%COSMOS_STATE_ROOT%\.venv\Scripts\python.exe" -B -m cosmos_mcp.launcher.cli start --open-browser %*
    )
    goto :after_run
)

REM 2b) 检查状态目录下已同步的 python-embed\python.exe
if exist "%COSMOS_STATE_ROOT%\python-embed\python.exe" (
    if defined _COSMOS_PASSTHROUGH (
        "%COSMOS_STATE_ROOT%\python-embed\python.exe" -B -c "import os,sys; p=os.environ.get('COSMOS_REPO_SRC',''); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" %*
    ) else (
        "%COSMOS_STATE_ROOT%\python-embed\python.exe" -B -c "import os,sys; p=os.environ.get('COSMOS_REPO_SRC',''); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" start --open-browser %*
    )
    goto :after_run
)

set "COSMOS_PY_LAUNCHER="
set "COSMOS_PY_EXE="

REM 3) 检测 py -3 启动器（严格校验真实解释器路径不含 WindowsApps 且版本 >=3.10）
for /f "delims=" %%L in ('where py 2^>nul') do (
    if not defined COSMOS_PY_LAUNCHER call :probe_py_launcher "%%~fL"
)
if defined COSMOS_PY_LAUNCHER (
    if defined _COSMOS_PASSTHROUGH (
        "%COSMOS_PY_LAUNCHER%" -3 -B -m cosmos_mcp.launcher.cli %*
    ) else (
        "%COSMOS_PY_LAUNCHER%" -3 -B -m cosmos_mcp.launcher.cli start --open-browser %*
    )
    goto :after_run
)

REM 4a) 扫描 PATH 中的 python（跳过 Microsoft\WindowsApps 假空壳，避免退出码 9009 或弹微软商店）
for /f "delims=" %%P in ('where python 2^>nul') do (
    if not defined COSMOS_PY_EXE call :probe_candidate "%%~fP"
)

REM 4b) 自动扫描本机常见真实 Python 安装位置（官方安装包、Conda、uv）
if not defined COSMOS_PY_EXE (
    for %%V in (313 312 311 310 314) do (
        if not defined COSMOS_PY_EXE if defined LOCALAPPDATA call :probe_candidate "%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe"
        if not defined COSMOS_PY_EXE if defined ProgramFiles call :probe_candidate "%ProgramFiles%\Python%%V\python.exe"
        if not defined COSMOS_PY_EXE call :probe_candidate "C:\Python%%V\python.exe"
    )
)
if not defined COSMOS_PY_EXE if defined USERPROFILE call :probe_candidate "%USERPROFILE%\anaconda3\python.exe"
if not defined COSMOS_PY_EXE if defined USERPROFILE call :probe_candidate "%USERPROFILE%\miniconda3\python.exe"
if not defined COSMOS_PY_EXE call :probe_candidate "C:\ProgramData\anaconda3\python.exe"
if not defined COSMOS_PY_EXE call :probe_candidate "C:\ProgramData\miniconda3\python.exe"
if not defined COSMOS_PY_EXE if defined APPDATA (
    if exist "%APPDATA%\uv\python" (
        for /d %%D in ("%APPDATA%\uv\python\cpython-3.1*") do (
            if not defined COSMOS_PY_EXE call :probe_candidate "%%~fD\python.exe"
        )
    )
)
if not defined COSMOS_PY_EXE if defined LOCALAPPDATA (
    if exist "%LOCALAPPDATA%\uv\python" (
        for /d %%D in ("%LOCALAPPDATA%\uv\python\cpython-3.1*") do (
            if not defined COSMOS_PY_EXE call :probe_candidate "%%~fD\python.exe"
        )
    )
)

REM 5) 全部未找到时打印清晰中文指引
if not defined COSMOS_PY_EXE (
    echo 未检测到可用的真实 Python 3.10~3.14 环境（已自动跳过微软商店 WindowsApps 空壳）。
    echo 解决方式 1：前往 https://www.python.org/downloads/ 下载安装 Python 3.12，安装首屏勾选 Add Python to PATH。
    echo 解决方式 2：直接下载带内置运行环境的 Cosmos MCP 完整绿色包解压后双击运行。
    if not defined _COSMOS_SILENT pause
    exit /b 1
)

if defined _COSMOS_PASSTHROUGH (
    "%COSMOS_PY_EXE%" -B -m cosmos_mcp.launcher.cli %*
) else (
    "%COSMOS_PY_EXE%" -B -m cosmos_mcp.launcher.cli start --open-browser %*
)

:after_run
set "_COSMOS_RC=%ERRORLEVEL%"
if not "%_COSMOS_RC%"=="0" (
    if not defined _COSMOS_SILENT (
        echo 启动遇到问题，请查看上方提示信息。
        pause
    )
    exit /b %_COSMOS_RC%
)
exit /b 0

:inspect_cli_args
if defined COSMOS_NO_PAUSE set "_COSMOS_SILENT=1"
if defined LOCALPC_NO_BROWSER set "_COSMOS_SILENT=1"
if defined PYTEST_CURRENT_TEST set "_COSMOS_SILENT=1"
if "%~1"=="" exit /b 0
for %%S in (start stop restart status doctor permissions agent-setup reset-password uninstall setup daemon stdio bind-desktop vps-caddy-snippet --help -h --version) do (
    if /i "%~1"=="%%~S" set "_COSMOS_PASSTHROUGH=1"
)
if defined _COSMOS_PASSTHROUGH if /i not "%~1"=="start" set "_COSMOS_SILENT=1"
:inspect_cli_loop
if "%~1"=="" exit /b 0
if /i "%~1"=="--no-browser" set "_COSMOS_SILENT=1"
if /i "%~1"=="--json" set "_COSMOS_SILENT=1"
shift
goto :inspect_cli_loop

:probe_py_launcher
set "_PYL=%~1"
if not defined _PYL exit /b 1
if not exist "%_PYL%" exit /b 1
echo "%_PYL%" | findstr /i /c:"\WindowsApps\" >nul
if not errorlevel 1 exit /b 1
"%_PYL%" -3 -B -c "import sys; raise SystemExit(0 if 'windowsapps' not in sys.executable.lower() and sys.version_info[:2]>=(3,10) and sys.version_info[:2]<=(3,14) else 1)" >nul 2>nul
if errorlevel 1 exit /b 1
set "COSMOS_PY_LAUNCHER=%_PYL%"
exit /b 0

:probe_candidate
set "_CAND=%~1"
if not defined _CAND exit /b 1
if not exist "%_CAND%" exit /b 1
echo "%_CAND%" | findstr /i /c:"\WindowsApps\" >nul
if not errorlevel 1 exit /b 1
"%_CAND%" -B -c "import sys; raise SystemExit(0 if 'windowsapps' not in sys.executable.lower() and sys.version_info[:2]>=(3,10) and sys.version_info[:2]<=(3,14) else 1)" >nul 2>nul
if errorlevel 1 exit /b 1
set "COSMOS_PY_EXE=%_CAND%"
exit /b 0
