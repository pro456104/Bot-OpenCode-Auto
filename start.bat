@echo off
title Bot OpenCode Auto
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel% neq 0 (
  echo Python not found in PATH - install Python 3.10+ from python.org
  pause
  exit /b 1
)
python vpn_bot.py
if %errorlevel% neq 0 pause
