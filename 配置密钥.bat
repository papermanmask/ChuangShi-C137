@echo off
setlocal EnableExtensions
title 创世 C-137 - 配置 DeepSeek API Key

REM ============================================================
REM  创世 C-137 - 配置 API Key
REM  在目标机器上运行一次：输入 DeepSeek API Key，
REM  用本机 Windows 账户（DPAPI）加密保存到 app\key.enc。
REM  DPAPI 加密与「本机 + 当前用户」绑定，换机器/换账户需重新配置。
REM  编码：GBK / 无 BOM / 不加 chcp
REM ============================================================

set "HERE=%~dp0"
set "PY=%HERE%runtime\python\python.exe"
set "APP=%HERE%app"

echo ============================================
echo   创世 C-137 - 配置 DeepSeek API Key
echo ============================================
echo.
echo 说明：
echo   - 请输入 DeepSeek API Key（形如 sk-xxxx...）
echo   - 密钥用本机 Windows 账户加密保存，仅本机当前账户可解密
echo   - 加密文件不落明文，请放心输入
echo.
echo 获取 Key：platform.deepseek.com -^> API Keys -^> 创建
echo.

set "KEY="
set /p "KEY=请输入 API Key: "

if "%KEY%"=="" (
  echo.
  echo [错误] 未输入任何内容，已取消。
  pause
  exit /b 1
)

REM 无尾随换行写入，加密后 base64 保存
echo|set /p="%KEY%" | "%PY%" "%APP%\crypto_dpapi.py" encrypt > "%APP%\key.enc"

if errorlevel 1 (
  echo.
  echo [错误] 密钥加密失败，请确认 runtime\python 完整。
) else (
  echo.
  echo [成功] 密钥已加密保存到 app\key.enc
  echo        现在双击「一键启动.bat」即可开始使用创世。
)
echo.
pause
endlocal
