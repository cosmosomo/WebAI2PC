@echo off
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0"
set "PYTHONDONTWRITEBYTECODE=1"
set "PYTHONUTF8=1"
set "_COSMOS_SILENT="
if defined COSMOS_NO_PAUSE set "_COSMOS_SILENT=1"
if defined PYTEST_CURRENT_TEST set "_COSMOS_SILENT=1"
call :scan_silent_flags %*

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

set "COSMOS_PY_LAUNCHER="
set "COSMOS_PY_EXE="

REM 1) 优先探测随包附带的外部绿色解释器 python-embed\python.exe（不占用状态目录 .venv）
if exist "%~dp0python-embed\python.exe" (
    set "COSMOS_PY_EXE=%~dp0python-embed\python.exe"
)

REM 2) 探测系统外部 py -3 启动器（校验真实解释器非 WindowsApps 且不位于待清理 .venv 内）
if not defined COSMOS_PY_EXE (
    for /f "delims=" %%L in ('where py 2^>nul') do (
        if not defined COSMOS_PY_LAUNCHER call :probe_py_launcher "%%~fL"
    )
)

REM 3) 探测 PATH 中的外部真实 Python（跳过 WindowsApps 空壳与待清理 .venv）
if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER (
    for /f "delims=" %%P in ('where python 2^>nul') do (
        if not defined COSMOS_PY_EXE call :probe_ext_candidate "%%~fP"
    )
)

REM 4) 扫描本机常见真实 Python 安装位置（官方安装包、Conda、uv）
if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER (
    for %%V in (313 312 311 310 314) do (
        if not defined COSMOS_PY_EXE if defined LOCALAPPDATA call :probe_ext_candidate "%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe"
        if not defined COSMOS_PY_EXE if defined ProgramFiles call :probe_ext_candidate "%ProgramFiles%\Python%%V\python.exe"
        if not defined COSMOS_PY_EXE call :probe_ext_candidate "C:\Python%%V\python.exe"
    )
)
if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER if defined USERPROFILE call :probe_ext_candidate "%USERPROFILE%\anaconda3\python.exe"
if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER if defined USERPROFILE call :probe_ext_candidate "%USERPROFILE%\miniconda3\python.exe"
if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER call :probe_ext_candidate "C:\ProgramData\anaconda3\python.exe"
if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER call :probe_ext_candidate "C:\ProgramData\miniconda3\python.exe"
if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER if defined APPDATA (
    if exist "%APPDATA%\uv\python" (
        for /d %%D in ("%APPDATA%\uv\python\cpython-3.1*") do (
            if not defined COSMOS_PY_EXE call :probe_ext_candidate "%%~fD\python.exe"
        )
    )
)
if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER if defined LOCALAPPDATA (
    if exist "%LOCALAPPDATA%\uv\python" (
        for /d %%D in ("%LOCALAPPDATA%\uv\python\cpython-3.1*") do (
            if not defined COSMOS_PY_EXE call :probe_ext_candidate "%%~fD\python.exe"
        )
    )
)

REM 5) 仅在外部真实 Python 与随包 python-embed 均不存在时，才回退状态目录内的解释器
if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER (
    if exist "%COSMOS_STATE_ROOT%\python-embed\python.exe" (
        set "COSMOS_PY_EXE=%COSMOS_STATE_ROOT%\python-embed\python.exe"
    )
)
if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER (
    if exist "%COSMOS_STATE_ROOT%\.venv\Scripts\python.exe" (
        set "COSMOS_PY_EXE=%COSMOS_STATE_ROOT%\.venv\Scripts\python.exe"
    )
)

if not defined COSMOS_PY_EXE if not defined COSMOS_PY_LAUNCHER (
    echo 未检测到可用的 Python 3.10~3.14 环境（已自动跳过微软商店 WindowsApps 空壳）。
    if not defined _COSMOS_SILENT pause
    exit /b 1
)

if not "%~1"=="" goto :passthrough_mode
if defined COSMOS_NO_PAUSE goto :auto_purge_mode
if defined PYTEST_CURRENT_TEST goto :auto_purge_mode

echo ====================================================================
echo  WebAI2PC (Cosmos MCP) 一键卸载向导
echo ====================================================================
echo  说明：卸载仅清理软件运行环境与本地配置，不会触碰您的个人项目代码目录。
echo.
echo  [1] 彻底卸载并粉碎凭据（默认）
echo      停止后台服务与连接隧道、取消开机自启、移除桌面快捷方式与系统应用列表项，
echo      以 0x00 覆写销毁全部本地口令/密钥/OAuth 令牌并清空 %COSMOS_STATE_ROOT%
echo  [2] 标准卸载（保留修改撤回快照）
echo      停止后台服务、取消自启并移除快捷入口，保留 .undo_history 修改撤回快照
echo  [Q] 取消退出
echo.
set "_COSMOS_UN_SEL=1"
set /p "_COSMOS_UN_SEL=请输入选项 [1/2/Q] (直接回车默认 1): "
if /i "%_COSMOS_UN_SEL%"=="Q" goto :cancel_exit
if "%_COSMOS_UN_SEL%"=="2" goto :interactive_standard
goto :interactive_purge

:cancel_exit
echo 已取消卸载操作。
exit /b 0

:interactive_standard
call :run_cli uninstall -y
set "_COSMOS_RC=%ERRORLEVEL%"
if not defined _COSMOS_SILENT pause
exit /b %_COSMOS_RC%

:interactive_purge
call :run_cli uninstall --purge -y
set "_COSMOS_RC=%ERRORLEVEL%"
if not defined _COSMOS_SILENT pause
exit /b %_COSMOS_RC%

:auto_purge_mode
call :run_cli uninstall --purge -y
exit /b %ERRORLEVEL%

:passthrough_mode
if /i "%~1"=="uninstall" goto :passthrough_subcmd
call :run_cli uninstall %*
exit /b %ERRORLEVEL%

:passthrough_subcmd
call :run_cli %*
exit /b %ERRORLEVEL%

:run_cli
if defined COSMOS_PY_LAUNCHER (
    "%COSMOS_PY_LAUNCHER%" -3 -B -c "import os,sys; p=os.environ.get('COSMOS_REPO_SRC',''); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" %*
    exit /b %ERRORLEVEL%
)
"%COSMOS_PY_EXE%" -B -c "import os,sys; p=os.environ.get('COSMOS_REPO_SRC',''); p and p not in sys.path and sys.path.insert(0,p); from cosmos_mcp.launcher.cli import main; raise SystemExit(main(sys.argv[1:]))" %*
exit /b %ERRORLEVEL%

:scan_silent_flags
if "%~1"=="" exit /b 0
if /i "%~1"=="--json" set "_COSMOS_SILENT=1"
if /i "%~1"=="-y" set "_COSMOS_SILENT=1"
if /i "%~1"=="--yes" set "_COSMOS_SILENT=1"
if /i "%~1"=="--dry-run" set "_COSMOS_SILENT=1"
shift
goto :scan_silent_flags

:probe_py_launcher
set "_PYL=%~1"
if not defined _PYL exit /b 1
if not exist "%_PYL%" exit /b 1
echo "%_PYL%" | findstr /i /c:"\WindowsApps\" >nul
if not errorlevel 1 exit /b 1
"%_PYL%" -3 -B -c "import os,sys; st=os.path.normcase(os.path.abspath(os.environ.get('COSMOS_STATE_ROOT',''))).rstrip('\\/'); ex=os.path.normcase(os.path.abspath(sys.executable)); in_st=bool(st and (ex==st or ex.startswith(st+os.sep))); raise SystemExit(0 if (not in_st) and 'windowsapps' not in ex.lower() and (3,10)<=sys.version_info[:2]<=(3,14) else 1)" >nul 2>nul
if errorlevel 1 exit /b 1
set "COSMOS_PY_LAUNCHER=%_PYL%"
exit /b 0

:probe_ext_candidate
set "_CAND=%~1"
if not defined _CAND exit /b 1
if not exist "%_CAND%" exit /b 1
echo "%_CAND%" | findstr /i /c:"\WindowsApps\" >nul
if not errorlevel 1 exit /b 1
"%_CAND%" -B -c "import os,sys; st=os.path.normcase(os.path.abspath(os.environ.get('COSMOS_STATE_ROOT',''))).rstrip('\\/'); ex=os.path.normcase(os.path.abspath(sys.executable)); in_st=bool(st and (ex==st or ex.startswith(st+os.sep))); raise SystemExit(0 if (not in_st) and 'windowsapps' not in ex.lower() and (3,10)<=sys.version_info[:2]<=(3,14) else 1)" >nul 2>nul
if errorlevel 1 exit /b 1
set "COSMOS_PY_EXE=%_CAND%"
exit /b 0
