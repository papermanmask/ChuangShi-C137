@echo off
setlocal enabledelayedexpansion
title 创世 C-137 - 创作工作台

REM ============================================================
REM  创世 C-137 - 一键启动
REM  全部路径基于 %~dp0（本脚本所在目录），可整体搬家到任意位置
REM  编码：GBK / 无 BOM / 不加 chcp（控制台默认即 GBK，最稳）
REM ============================================================

set "HERE=%~dp0"
set "APP=%HERE%app"
set "PROJECT=%HERE%project"
set "ENGINE=%HERE%engine"
set "PY=%HERE%runtime\python\python.exe"
set "NODE=%HERE%runtime\node"
set "PORT=8787"

REM ---- 环境变量：代理与引擎全部指向包内相对路径 ----
set "INKOS_BOOK_ROOT=%PROJECT%"
set "INKOS_NODE_DIR=%NODE%"
set "INKOS_BIN=%ENGINE%\node_modules\.bin"
set "INKOS_LLM_BASE_URL=http://127.0.0.1:8787"
set "INKOS_LLM_API_KEY=sk-local-proxy-placeholder"
set "INKOS_LLM_MODEL=deepseek-v4-flash"
set "INKOS_LLM_API_FORMAT=chat"
set "INKOS_LLM_STREAM=true"
set "PATH=%NODE%;%ENGINE%\node_modules\.bin;%PATH%"

echo ============================================
echo   创世 C-137 - 创作工作台
echo ============================================
echo.

REM ---- 检查 Python 运行时 ----
if not exist "%PY%" (
  echo [错误] 未找到内置 Python 运行时：%PY%
  echo         请确认 runtime\python\python.exe 存在。
  echo.
  pause
  exit /b 1
)

REM ---- 检查 API Key ----
if not exist "%APP%\key.enc" (
  echo [警告] 尚未配置 DeepSeek API Key！
  echo         请先双击「配置密钥.bat」完成密钥配置，否则无法调用 AI。
  echo.
)

REM ---- 检查端口占用并启动代理 ----
set "PORT_BUSY=0"
for /f "tokens=*" %%a in ('netstat -ano 2^>nul ^| findstr ":%PORT%" ^| findstr "LISTENING"') do set "PORT_BUSY=1"
if "%PORT_BUSY%"=="1" (
  echo [提示] 端口 %PORT% 已被占用，可能创世代理已在运行，直接打开工作台。
) else (
  echo [启动] 正在启动创世代理服务（端口 %PORT%）...
  pushd "%APP%"
  start "创世代理" /min "%PY%" app.py
  popd
  timeout /t 3 /nobreak >nul
)

REM ---- 打开工作台 ----
echo [打开] 工作台地址：http://localhost:%PORT%/workbench
start "" "http://localhost:%PORT%/workbench"
echo.
echo 已启动。若浏览器打不开，请改用 http://localhost:%PORT%/workbench 或 127.0.0.1 访问
echo （某些 VPN/代理的 TUN 模式会拦截 127.0.0.1 回环流量）。
echo 本窗口可以关闭，代理服务会在后台继续运行。
echo.
pause
endlocal
