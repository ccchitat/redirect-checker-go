#!/bin/bash

# 设置Go的交叉编译环境变量
export GOOS=linux
export GOARCH=amd64

echo "开始编译Linux版本..."

# 编译程序
go build -o main main.go

# 检查编译结果
if [ $? -eq 0 ]; then
    echo "编译成功！输出文件：main"
    echo "文件大小：$(ls -lh main | awk '{print $5}')"
else
    echo "编译失败！"
    exit 1
fi

# 恢复本地环境变量
export GOOS=darwin
export GOARCH=amd64

echo "编译完成！" 