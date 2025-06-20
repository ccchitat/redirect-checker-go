#!/bin/bash

# 检查3000端口是否被占用
check_and_kill_port() {
    echo "检查端口3000..."
    if lsof -i :3000 > /dev/null 2>&1; then
        echo "端口3000被占用，正在结束进程..."
        lsof -ti :3000 | xargs kill -9
        echo "端口3000的进程已被终止"
    else
        echo "端口3000未被占用"
    fi
}

# 运行主程序
run_app() {
    check_and_kill_port
    echo "正在启动应用..."
    go run main.go
}

# 执行主函数
run_app 