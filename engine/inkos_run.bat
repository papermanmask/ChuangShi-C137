@echo off
setlocal EnableDelayedExpansion
REM === Managed runtimes ===
set "PY=C:\Users\wywnh\.workbuddy\binaries\python\versions\3.13.12\python.exe"
set "NODE=C:\Users\wywnh\.workbuddy\binaries\node\versions\22.22.2"
set "CRYPTO=C:\w-136\inkos-smoke\crypto_helper.py"
set "KEYFILE=C:\w-136\inkos-smoke\.inkos_key.enc"
set "PROJ=C:\w-136\inkos-smoke\dream-crystal"
set "PROXY=C:\w-136\inkos-smoke\proxy.py"
set "PORT=8787"

REM === Prepend managed node to PATH so the local inkos bin resolves ===
set "PATH=%NODE%;C:\w-136\inkos-smoke\node_modules\.bin;%PATH%"

REM === Start the local proxy + usage dashboard in the background ===
REM (it decrypts the key in memory, captures token usage, serves the live UI)
if not defined INKOS_NO_PROXY (
  start "" /b "%PY%" "%PROXY%" > "C:\w-136\inkos-smoke\proxy.log" 2>&1
)

REM === Decrypt API key into process memory ONLY (never written to disk) ===
for /f "delims=" %%k in ('"%PY%" "%CRYPTO%" decrypt "%KEYFILE%"') do set "INKOS_LLM_API_KEY=%%k"

cd /d "%PROJ%"
REM === Point InkOS at the local proxy so every call is captured ===
set "INKOS_LLM_BASE_URL=http://127.0.0.1:%PORT%"
inkos %*
endlocal
