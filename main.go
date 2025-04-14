package main

import (
	"log"
	"net/http"
	"redirect-checker-go/api"
)

func main() {
	// 设置路由处理函数
	http.HandleFunc("/", api.Listen)

	// 启动服务器
	log.Printf("服务器启动在默认端口")
	if err := http.ListenAndServe("", nil); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
