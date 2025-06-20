# Redirect Checker

一个强大的重定向链接检查工具，支持多种重定向方式的检测。

## 当前版本

- 版本号：v1.0.1
- 更新日期：2024-03-21
- [查看更新日志](CHANGELOG.md)

## 功能特点

- 支持多种重定向检测：
  - HTTP 状态码重定向 (301, 302, 303, 307, 308)
  - HTML Meta 刷新重定向
  - JavaScript location 重定向
    - window.location 跳转
    - location.replace() 跳转
    - 变量赋值跳转
- 支持代理配置
- 支持无头浏览器模式
- IP 信息查询
- 超时控制
- 自定义请求头

## 安装

```bash
go get github.com/yourusername/redirect-checker-go
```

## 使用方法

### 启动服务

```bash
go run main.go
```

### API 调用示例

```bash
curl -X POST http://localhost:3000/redirect-check \
  -H "Content-Type: application/json" \
  -d '{
    "link": "https://example.com",
    "enable_proxy": true,
    "use_browser": false,
    "timeout": 30,
    "proxy": {
      "username": "user",
      "password": "pass",
      "host": "proxy.example.com",
      "port": "8080"
    }
  }'
```

## 版本管理

本项目使用语义化版本进行版本管理。版本号格式：主版本号.次版本号.修订号

- 主版本号：做了不兼容的 API 修改
- 次版本号：做了向下兼容的功能性新增
- 修订号：做了向下兼容的问题修正

## 贡献指南

1. Fork 本仓库
2. 创建您的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交您的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启一个 Pull Request

## 开源协议

MIT License - 详见 [LICENSE](LICENSE) 文件 