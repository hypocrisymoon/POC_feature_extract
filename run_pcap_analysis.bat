@echo off
echo PCAP流量分析器
echo ================

REM 检查是否有PCAP文件
if not exist "*.pcap" (
    echo 错误：当前目录没有找到PCAP文件
    pause
    exit /b 1
)

echo 找到以下PCAP文件：
dir /b *.pcap

echo.
echo 开始分析所有PCAP文件...
echo.

REM 运行分析脚本
python run_analysis.py

echo.
echo 分析完成！请检查生成的CSV和JSON文件。
pause
