# 更新日志

所有重要的更改都会记录在这个文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
并且本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.1] - 2024-03-21

### 改进
- 增强了 location 重定向检测功能
  - 新增支持不带 window 前缀的 location 跳转
  - 新增支持变量赋值方式的 location 跳转
  - 新增支持多种 location 跳转语法

## [1.0.0] - 2024-03-21

### 新增
- 基础重定向检查功能
  - HTTP 重定向检测
  - Meta 刷新重定向检测
  - Window.location 重定向检测
- 支持代理配置
- 支持浏览器模式
- IP 信息查询
- 超时控制
- 请求头定制 