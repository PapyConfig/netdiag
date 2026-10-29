@echo off
REM Construit dist\NetDiag\NetDiag.exe (Windows, Python 3.10+ requis)
setlocal
if not exist .venv (
    py -3 -m venv .venv || goto :err
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul
pip install -r requirements-build.txt || goto :err
pyinstaller --noconfirm --clean --windowed --name NetDiag ^
    --collect-submodules scapy.layers --collect-submodules dns ^
    --add-data "netdiag\ui\netdiag.svg;netdiag\ui" ^
    main.py || goto :err
echo.
echo OK : dist\NetDiag\NetDiag.exe
goto :eof
:err
echo ECHEC du build
exit /b 1
