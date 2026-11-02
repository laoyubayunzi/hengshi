@echo off
setlocal
cd /d "%~dp0"
echo.
echo ============================================================
echo   琛℃椂 hengshi - 甯搁噺鏃堕棿鎬ф娴嬩笌瀵嗛挜娉勬紡瀹氫綅
echo ============================================================
echo.
if not exist hengshi.exe (
    echo [1/4] 鏈壘鍒?hengshi.exe锛屽紑濮嬬紪璇?..
    powershell -ExecutionPolicy Bypass -File "%~dp0build.ps1"
    if errorlevel 1 (
        echo 缂栬瘧澶辫触锛岀粓姝€?
        pause
        exit /b 1
    )
) else (
    echo [1/4] 浣跨敤宸茬紪璇戠殑 hengshi.exe
)
echo.
echo [2/4] 璺戝疄楠岋紙绾?60 绉掞級...
echo ------------------------------------------------------------
.\hengshi.exe verify
echo.
.\hengshi.exe libs 40000 3
echo.
.\hengshi.exe compare 40000
echo.
.\hengshi.exe ttest 40000
echo.
.\hengshi.exe converge
echo.
.\hengshi.exe attack 64 200 32
echo.
.\hengshi.exe attack 4 200 4
echo.
.\hengshi.exe sweep 10 20000
echo.
echo [3/4] 鐢熸垚鎶ュ憡涓庡浘琛?..
where python >nul 2>&1
if errorlevel 1 (
    echo   鏈壘鍒?python锛岃烦杩囨姤鍛婄敓鎴愶紙瀹為獙杈撳嚭宸插湪涓婇潰锛?
) else (
    python make_report.py
    python sync_readme.py
    python make_findings.py
    python viz.py
    python make_docx.py
)
echo.
echo [4/4] 瀹屾垚銆備骇鐗╋細
echo   report.md      瀹為獙鎶ュ憡
echo   findings.md    妫€娴嬪彂鐜版姤鍛?
echo   viz\*.png      鍥捐〃
echo.
pause
