#!/bin/bash

# 检查3000端口是否被占用
check_and_kill_port() {
    echo "正在检查端口3000..."
    if lsof -i :3000 > /dev/null 2>&1; then
        echo "端口3000被占用，正在结束进程..."
        lsof -ti :3000 | xargs kill -9
        if [ $? -eq 0 ]; then
            echo "端口3000的进程已被终止"
            sleep 1  # 等待端口完全释放
        else
            echo "无法终止端口3000的进程，请手动检查"
            exit 1
        fi
    else
        echo "端口3000未被占用"
    fi
}

# 设置日志文件路径
logfile="$HOME/go/log/log_$(date +\%Y-\%m-\%d).log"

# 确保日志目录存在
mkdir -p "$HOME/go/log"

# 检查端口并启动应用
check_and_kill_port
echo "正在启动应用..."
nohup ./main > "$logfile" 2>&1 &

# 打印进程ID
echo "应用已在后台启动，进程ID: $!"
echo "日志文件位置: $logfile"
