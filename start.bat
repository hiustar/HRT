@echo off
cd /d "%~dp0"
echo 正在启动 绪山真寻 HRT Tracker 本地多设备互通服务...
start http://localhost:3000
python server.py
pause
