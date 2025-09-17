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

### 服务器白名单（启动前校验）

为防止程序在未授权的服务器上运行，程序在启动时会读取当前目录的 `whitelist.txt` 并校验“服务器的公网 IPv4”是否在名单中。不在名单则直接退出。

- 文件路径：`./whitelist.txt`
- 文件格式：每行一个 IP 或 CIDR；目前匹配以“公网 IPv4”为主；空行与以 `#`、`//`、`;` 开头的行为注释，将被忽略。

示例 `whitelist.txt`：

```
# 生产服务器
10.0.12.34
10.0.0.0/16

# IPv6 样例
fd00::/8
2001:db8::1
```

注意：本校验仅匹配服务器“公网 IPv4”。若服务器位于 NAT/出口网关之后，请在 `whitelist.txt` 写入该服务器对外的“公网 IP”（或对应 CIDR）。

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
