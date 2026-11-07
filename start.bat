@echo off
rem netscan: pornire dintr-un dublu-click (Windows).
rem Fara drepturi de administrator, fara comenzi de retea, fara instalari: doar interfata locala pe 127.0.0.1.
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"

python -c "import netscan" >nul 2>&1
if errorlevel 1 (
  echo netscan nu e instalat. Urmeaza pasii din README, sectiunea Setup.
  echo netscan is not installed. Follow the Setup steps in README.
  pause
  exit /b 1
)

echo Pornesc netscan pe http://127.0.0.1:5055/ . Inchide aceasta fereastra ca sa opresti.
echo Starting netscan on http://127.0.0.1:5055/ . Close this window to stop it.
start "" /min cmd /c "timeout /t 3 /nobreak >nul & start http://127.0.0.1:5055/"
python -m netscan ui --port 5055
pause
