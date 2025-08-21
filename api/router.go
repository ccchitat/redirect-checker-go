package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/gin-gonic/gin"
)

const (
	// VERSION 当前版本号，每次修改代码后手动更新
	VERSION = "1.0.2"
)

var router *gin.Engine

type ProxyConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     string `json:"port"`
}

// 请求结构体
type RedirectCheckRequest struct {
	EnableProxy  *bool       `json:"enable_proxy"` // 是否启用代理，未传入时默认为true
	UseBrowser   *bool       `json:"use_browser"`  // 是否使用浏览器模式追踪重定向，未传入时默认为false
	Proxy        ProxyConfig `json:"proxy"`
	Link         string      `json:"link" binding:"required"`
	Timeout      int         `json:"timeout"`       // 超时时间（秒）
	Referer      string      `json:"referer"`       // 请求来源
	ReverseIndex int         `json:"reverse_index"` // 取倒数第N条（默认0表示最后一条，1表示倒数第二条）
}

// IP信息响应结构体
type IPInfoResponse struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
}

// 响应结构体
type RedirectCheckResponse struct {
	Status           int            `json:"status"`
	Error            string         `json:"error,omitempty"`
	IPInfo           IPInfoResponse `json:"ip_info"`
	RedirectPath     []string       `json:"redirect_path"`
	TargetURL        string         `json:"target_url"`
	TrackingTemplate string         `json:"tracking_template"`
}

// IPInfo 结构体
type IPInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
	Timezone string `json:"timezone"`
}

func checkWindowLocation(body string) string {
	// log.Printf("检查Window刷新重定向")
	// log.Printf(body)

	// 定义多个正则表达式来匹配不同的location跳转格式
	patterns := []string{
		`window\.location\.(replace|href)\s*\(\s*['"](.*?)['"]\s*\)`,             // window.location.replace('...') 或 window.location.href('...')
		`window\.location\s*=\s*['"](.*?)['"]`,                                   // window.location = '...'
		`location\.(replace|href)\s*\(\s*['"](.*?)['"]\s*\)`,                     // location.replace('...') 或 location.href('...')
		`location\s*=\s*['"](.*?)['"]`,                                           // location = '...'
		`var\s+\w+\s*=\s*['"](https?://.*?)['"][\s\S]*?location\.replace\(\w+\)`, // var u = '...' + location.replace(u)
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(body)

		if len(matches) > 0 {
			// 对于最后一种模式（变量赋值），直接返回第一个捕获组
			if strings.Contains(pattern, "var") && len(matches) > 1 {
				url := matches[1]
				url = strings.ReplaceAll(url, `\/`, `/`)
				return url
			}
			// 对于其他模式，返回最后一个捕获组
			url := matches[len(matches)-1]
			url = strings.ReplaceAll(url, `\/`, `/`)
			return url
		}
	}
	return ""
}

// 检查Meta刷新重定向
func checkMetaRefresh(body string) string {
	// log.Printf("检查Meta刷新重定向")
	// log.Printf(body)
	patterns := []string{
		`<meta\s+http-equiv="refresh"\s+content="0;\s*url=(.*?)"`,
		`<meta\s+http-equiv="refresh"\s+content="0;url=(.*?)"`,
		`<meta\s+http-equiv=refresh\s+content="0;\s*url=(.*?)"`,
		`<meta\s+http-equiv=refresh\s+content="0;url=(.*?)"`,
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		// 使用 FindStringSubmatchIndex 获取匹配的索引
		matchesIndices := re.FindStringSubmatchIndex(bodyLower)

		// matchesIndices 包含整个匹配的开始和结束，以及每个捕获组的开始和结束
		// 我们关心的是第一个捕获组 (url=...)
		if len(matchesIndices) > 3 { // 0,1 是整个匹配, 2,3 是第一个捕获组
			// 从原始 body 中根据索引提取 URL，以保留大小写
			urlStartIndex := matchesIndices[2]
			urlEndIndex := matchesIndices[3]
			extractedURL := body[urlStartIndex:urlEndIndex]
			return strings.Trim(extractedURL, `"'`)
		}
	}
	return ""
}

// 基于上下文区分 window.location 是自动还是手动触发（启发式）
// kind 取值: "auto", "manual", "legacy_auto", "unknown"
func detectWindowLocation(body string) (string, string) {
	patterns := []string{
		`window\.location\.(replace|href)\s*\(\s*['\"](.*?)['\"]\s*\)`,
		`window\.location\s*=\s*['\"](.*?)['\"]`,
		`location\.(replace|href)\s*\(\s*['\"](.*?)['\"]\s*\)`,
		`location\s*=\s*['\"](.*?)['\"]`,
	}

	lower := strings.ToLower(body)
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		idx := re.FindStringSubmatchIndex(lower)
		if len(idx) == 0 {
			continue
		}
		// 捕获组对应的 URL 在最后一个分组
		var urlStr string
		// 提取原始大小写 URL
		if len(idx) >= 4 {
			urlStr = body[idx[len(idx)-2]:idx[len(idx)-1]]
		}
		// 上下文窗口
		start := idx[0] - 300
		if start < 0 {
			start = 0
		}
		end := idx[1] + 300
		if end > len(lower) {
			end = len(lower)
		}
		ctx := lower[start:end]

		// IE 兼容判断: document.documentMode
		if strings.Contains(ctx, "document.documentmode") {
			return strings.ReplaceAll(urlStr, `\/`, `/`), "legacy_auto"
		}
		// 事件绑定/用户交互线索
		if strings.Contains(ctx, "addeventlistener(\"click\"") || strings.Contains(ctx, "addeventlistener('click'") ||
			strings.Contains(ctx, ".onclick") || strings.Contains(ctx, " onlick") || strings.Contains(ctx, "on('click'") ||
			strings.Contains(ctx, "=>") || strings.Contains(ctx, "function(") {
			return strings.ReplaceAll(urlStr, `\/`, `/`), "manual"
		}
		// 其它默认判为自动（启发式）
		return strings.ReplaceAll(urlStr, `\/`, `/`), "auto"
	}
	return "", ""
}

// 获取域名的IP地址
func getHostIP(hostname string) string {
	ips, err := net.LookupHost(hostname)
	if err != nil {
		return "无法解析IP"
	}
	return strings.Join(ips, ", ")
}

// 获取IP信息
func getIPInfo(client *http.Client) (*IPInfo, error) {
	// 创建请求
	req, err := http.NewRequest("GET", "https://ipinfo.io/json", nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求IP信息失败: %v", err)
	}
	defer resp.Body.Close()

	// 打印响应信息
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	log.Printf("IP信息响应: Status=%d, Body=%s", resp.StatusCode, string(body))

	var ipInfo IPInfo
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&ipInfo); err != nil {
		return nil, fmt.Errorf("解析IP信息失败: %v", err)
	}

	return &ipInfo, nil
}

// func init() {
// 	// 创建一个默认的路由引擎
// 	router = gin.Default()

// 	// 根路由 - 测试连通性
// 	router.GET("/", func(c *gin.Context) {
// 		c.JSON(http.StatusOK, gin.H{
// 			"message": "服务器运行正常",
// 		})
// 	})

// 		c.JSON(http.StatusOK, response)
// 	})

// 	// 启动服务器
// 	// log.Printf("服务器启动在端口 3001")
// 	// r.Run(":3001")
// 	router.Run()
// }

func init() {
	router = gin.Default()

	// 根路由 - 测试连通性
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "服务器运行正常",
			"version": VERSION,
		})
	})

	// 重定向检查服务
	router.POST("/redirect-check", func(c *gin.Context) {
		startTime := time.Now()
		clientIP := getClientIP(c)
		reqID := fmt.Sprintf("RID-%d", startTime.UnixNano())
		log.Printf("[%s] 开始处理请求: %v, 客户端IP: %s", reqID, startTime, clientIP)

		var req RedirectCheckRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("请求参数解析失败: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求参数: " + err.Error()})
			return
		}

		// 解析目标URL的主机名
		targetURL, err := url.Parse(req.Link)
		if err == nil {
			targetIP := getHostIP(targetURL.Hostname())
			log.Printf("[%s] 请求参数: URL=%s (IP: %s), EnableProxy=%v, UseBrowser=%v, Timeout=%d, ReverseIndex=%d",
				reqID, req.Link, targetIP, req.EnableProxy, req.UseBrowser, req.Timeout, req.ReverseIndex)
		} else {
			log.Printf("[%s] 请求参数: URL=%s (URL解析失败), EnableProxy=%v, UseBrowser=%v, Timeout=%d, ReverseIndex=%d",
				reqID, req.Link, req.EnableProxy, req.UseBrowser, req.Timeout, req.ReverseIndex)
		}

		// 设置默认超时时间为60秒
		if req.Timeout <= 0 {
			req.Timeout = 60
			log.Printf("[%s] 使用默认超时时间: %d秒", reqID, req.Timeout)
		}

		// 设置默认启用代理
		if req.EnableProxy == nil {
			defaultValue := true
			req.EnableProxy = &defaultValue
			log.Printf("[%s] 默认启用代理", reqID)
		}

		// 设置默认不使用浏览器
		if req.UseBrowser == nil {
			defaultValue := false
			req.UseBrowser = &defaultValue
			log.Printf("[%s] 默认不使用浏览器模式", reqID)
		}

		// 创建HTTP客户端（默认使用系统代理设置）
		transport := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   time.Duration(req.Timeout) * time.Second,
			ResponseHeaderTimeout: time.Duration(req.Timeout) * time.Second,
			ExpectContinueTimeout: time.Duration(req.Timeout) * time.Second,
			DisableKeepAlives:     false, // 启用连接重用，提升与CDN交互稳定性
			ForceAttemptHTTP2:     true,
		}

		// 如果启用代理，设置代理配置
		if *req.EnableProxy {
			// 设置代理URL
			proxyURL := fmt.Sprintf("http://%s:%s@%s:%s",
				req.Proxy.Username,
				req.Proxy.Password,
				req.Proxy.Host,
				req.Proxy.Port)

			// 解析代理服务器IP
			proxyIP := getHostIP(req.Proxy.Host)
			log.Printf("[%s] 使用代理: %s (IP: %s)",
				reqID,
				strings.Replace(proxyURL, req.Proxy.Password, "****", 1),
				proxyIP)

			// 创建代理URL
			proxy, err := url.Parse(proxyURL)
			if err != nil {
				log.Printf("代理URL解析失败: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "代理URL格式错误"})
				return
			}

			transport.Proxy = http.ProxyURL(proxy)
		} else {
			// 未显式启用代理时，沿用系统代理（HTTP_PROXY/HTTPS_PROXY）
			log.Printf("[%s] 未指定自定义代理，使用系统代理（若已在环境中配置）", reqID)
		}

		jar, _ := cookiejar.New(nil)
		client := &http.Client{
			Transport: transport,
			Timeout:   time.Duration(req.Timeout) * time.Second,
			Jar:       jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// 获取IP信息
		ipInfo, err := getIPInfo(client)
		if err != nil {
			log.Printf("[%s] 获取IP信息失败: %v，使用默认值继续执行", reqID, err)
			ipInfo = &IPInfo{
				IP:      "未知",
				Country: "未知",
				Region:  "未知",
				City:    "未知",
			}
		} else {
			log.Printf("[%s] 当前IP信息: IP=%s, 国家=%s, 地区=%s, 城市=%s",
				reqID, ipInfo.IP, ipInfo.Country, ipInfo.Region, ipInfo.City)
		}

		redirectPath := []string{req.Link}

		// 根据是否使用浏览器模式选择不同的重定向检查方法
		if *req.UseBrowser {
			log.Printf("[%s] 使用无头浏览器模式跟踪重定向，URL: %s, 超时: %d秒", reqID, req.Link, req.Timeout)

			// 根据是否启用代理决定传入的代理配置
			var proxyConfig *ProxyConfig
			if *req.EnableProxy {
				proxyConfig = &req.Proxy
				log.Printf("[%s] 无头浏览器模式启用代理", reqID)
			} else {
				log.Printf("[%s] 无头浏览器模式不使用代理", reqID)
			}

			// 使用chromedp进行重定向跟踪
			paths, err := traceWithChromedp(req.Link, req.Timeout, proxyConfig)
			if err != nil {
				log.Printf("[%s] 无头浏览器跟踪失败: %v", reqID, err)
				c.JSON(http.StatusOK, RedirectCheckResponse{
					Status: 0,
					Error:  "浏览器跟踪失败: " + err.Error(),
					IPInfo: IPInfoResponse{
						IP:      ipInfo.IP,
						Country: ipInfo.Country,
						Region:  ipInfo.Region,
						City:    ipInfo.City,
					},
					TargetURL: req.Link,
				})
				return
			}

			redirectPath = paths
			log.Printf("[%s] 无头浏览器跟踪完成，共发现 %d 个重定向路径", reqID, len(redirectPath))
		} else {
			// 使用标准HTTP客户端模式跟踪重定向
			log.Printf("[%s] 使用标准HTTP客户端模式跟踪重定向，URL: %s, 超时: %d秒", reqID, req.Link, req.Timeout)

			// 检查重定向
			stepCount := 0
			for i := 0; i < 10; i++ {
				parsedURL, _ := url.Parse(redirectPath[len(redirectPath)-1])
				currentIP := getHostIP(parsedURL.Hostname())
				reqStartTime := time.Now()
				currentURL := redirectPath[len(redirectPath)-1]

				reqObj, err := http.NewRequest("GET", currentURL, nil)
				if err != nil {
					log.Printf("创建请求失败: %v", err)
					c.JSON(http.StatusOK, RedirectCheckResponse{
						Status: 0,
						Error:  "创建请求失败",
						IPInfo: IPInfoResponse{
							IP:      ipInfo.IP,
							Country: ipInfo.Country,
							Region:  ipInfo.Region,
							City:    ipInfo.City,
						},
					})
					return
				}

				// 设置默认请求头
				reqObj.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
				reqObj.Header.Set("Accept-Language", "en-US,en;q=0.9")
				// 与浏览器一致：不强制关闭连接
				if req.Referer != "" {
					reqObj.Header.Set("Referer", req.Referer)
				}

				// 根据是否使用浏览器模式设置不同的User-Agent
				// 默认移动设备User-Agent
				reqObj.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)")

				log.Printf("[%s] 开始第 %d 次请求: %s (IP: %s) Referer: %s", reqID, i+1, currentURL, currentIP, req.Referer)

				resp, err := client.Do(reqObj)
				reqDuration := time.Since(reqStartTime)
				log.Printf("[%s] 请求耗时: %v", reqID, reqDuration)

				if err != nil {
					log.Printf("[%s] 请求失败: %v (类型: %T)", reqID, err, err)
					errorMsg := "网络连接错误"
					if strings.Contains(err.Error(), "timeout") {
						errorMsg = "网络连接错误"
					} else if strings.Contains(err.Error(), "EOF") {
						errorMsg = "网络连接错误"
					}
					c.JSON(http.StatusOK, RedirectCheckResponse{
						Status: 0,
						Error:  errorMsg,
						IPInfo: IPInfoResponse{
							IP:      ipInfo.IP,
							Country: ipInfo.Country,
							Region:  ipInfo.Region,
							City:    ipInfo.City,
						},
						TargetURL: currentURL,
					})
					return
				}

				log.Printf("[%s] 收到响应: 状态码=%d, URL=%s", reqID, resp.StatusCode, currentURL)

				// 检查HTTP重定向
				if resp.StatusCode >= 300 && resp.StatusCode < 400 {
					location := resp.Header.Get("Location")
					if location != "" {
						log.Printf("[%s] 发现HTTP重定向: %s", reqID, location)

						// 对重定向URL进行编码处理
						location = encodeRedirectURL(location)
						log.Printf("[%s] 编码后的重定向URL: %s", reqID, location)

						nextURL, err := url.Parse(location)
						if err != nil {
							log.Printf("解析重定向URL失败: %v", err)
							break
						}

						if !nextURL.IsAbs() {
							currentURLParsed, err := url.Parse(currentURL)
							if err != nil {
								log.Printf("[%s] 解析当前URL失败: %v", reqID, err)
								break
							}
							nextURL = currentURLParsed.ResolveReference(nextURL)
						}

						// 去重防循环
						if containsURL(redirectPath, nextURL.String()) {
							log.Printf("[%s] 目标URL已在链路中，跳过重复: %s", reqID, nextURL.String())
							resp.Body.Close()
							break
						}

						nextIP := getHostIP(nextURL.Hostname())
						stepCount++
						log.Printf("[%s] STEP %d [HTTP %d]: %s (IP: %s) -> %s (IP: %s)", reqID, stepCount, resp.StatusCode, currentURL, currentIP, nextURL.String(), nextIP)
						redirectPath = append(redirectPath, nextURL.String())
						resp.Body.Close()
						continue
					}
				}

				// 检查meta刷新重定向
				if resp.StatusCode == 200 {
					contentType := strings.ToLower(resp.Header.Get("Content-Type"))
					if contentType == "" || strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml") {
						const maxPeekBytes = 256 * 1024
						limited := io.LimitReader(resp.Body, maxPeekBytes)
						body, err := io.ReadAll(limited)
						if err != nil {
							log.Printf("[%s] 读取响应体失败: %v", reqID, err)
							resp.Body.Close()
							break
						}
						resp.Body.Close()
						log.Printf("[%s] 已读取页面前 %d 字节用于重定向检测, Content-Type=%s", reqID, len(body), contentType)

						// window.location（仅自动/IE兼容自动）
						if loc, kind := detectWindowLocation(string(body)); loc != "" {
							log.Printf("[%s] 发现Window.location(%s): %s", reqID, kind, loc)
							// 仅自动/IE兼容的自动跳转会跟随；manual 只记录不跟随
							if kind == "auto" || kind == "legacy_auto" {
								locationURL := encodeRedirectURL(loc)
								log.Printf("[%s] 编码后的Window.location重定向URL: %s", reqID, locationURL)
								nextURL, err := url.Parse(locationURL)
								if err == nil {
									if !nextURL.IsAbs() {
										currentURLParsed, err := url.Parse(currentURL)
										if err == nil {
											nextURL = currentURLParsed.ResolveReference(nextURL)
										}
									}
									if !containsURL(redirectPath, nextURL.String()) {
										nextIP := getHostIP(nextURL.Hostname())
										stepCount++
										log.Printf("[%s] STEP %d [WINDOW-%s]: %s (IP: %s) -> %s (IP: %s)", reqID, stepCount, kind, currentURL, currentIP, nextURL.String(), nextIP)
										redirectPath = append(redirectPath, nextURL.String())
										continue
									}
								}
							}
						}

						if metaLocation := checkMetaRefresh(string(body)); metaLocation != "" {
							log.Printf("[%s] 发现Meta刷新重定向: %s", reqID, metaLocation)
							metaLocation = encodeRedirectURL(metaLocation)
							log.Printf("[%s] 编码后的Meta重定向URL: %s", reqID, metaLocation)
							nextURL, err := url.Parse(metaLocation)
							if err != nil {
								log.Printf("解析Meta重定向URL失败: %v", err)
								break
							}
							if !nextURL.IsAbs() {
								currentURLParsed, err := url.Parse(currentURL)
								if err != nil {
									log.Printf("[%s] 解析当前URL失败: %v", reqID, err)
									break
								}
								nextURL = currentURLParsed.ResolveReference(nextURL)
							}
							// 去重防循环
							if containsURL(redirectPath, nextURL.String()) {
								log.Printf("[%s] 目标URL已在链路中，跳过重复: %s", reqID, nextURL.String())
								continue
							}
							nextIP := getHostIP(nextURL.Hostname())
							stepCount++
							log.Printf("[%s] STEP %d [META]: %s (IP: %s) -> %s (IP: %s)", reqID, stepCount, currentURL, currentIP, nextURL.String(), nextIP)
							redirectPath = append(redirectPath, nextURL.String())
							continue
						}
					} // HTML only
				}

				resp.Body.Close()
				break
			}
		}

		// 根据 reverse_index 选择倒数第 N 条的 URL
		selectedFromEnd := req.ReverseIndex
		if selectedFromEnd < 0 {
			selectedFromEnd = 0
		}
		if selectedFromEnd >= len(redirectPath) {
			selectedFromEnd = len(redirectPath) - 1
		}
		selectedIndex := len(redirectPath) - 1 - selectedFromEnd
		if selectedIndex < 0 {
			selectedIndex = 0
		}
		selectedURL := redirectPath[selectedIndex]
		// 链路总结
		log.Printf("[%s] 重定向链路 (共 %d 步):", reqID, len(redirectPath)-1)
		for idx, u := range redirectPath {
			parsed, err := url.Parse(u)
			ip := ""
			if err == nil {
				ip = getHostIP(parsed.Hostname())
			}
			log.Printf("[%s]   [%d] %s (IP: %s)", reqID, idx, u, ip)
		}

		log.Printf("[%s] 根据 reverse_index=%d 选取 URL: %s (索引: %d/%d)", reqID, req.ReverseIndex, selectedURL, selectedIndex, len(redirectPath)-1)

		// 成功响应
		response := RedirectCheckResponse{
			Status: 1,
			IPInfo: IPInfoResponse{
				IP:      ipInfo.IP,
				Country: ipInfo.Country,
				Region:  ipInfo.Region,
				City:    ipInfo.City,
			},
			RedirectPath:     redirectPath,
			TargetURL:        selectedURL,
			TrackingTemplate: createTrackingTemplate(selectedURL),
		}

		totalDuration := time.Since(startTime)
		log.Printf("[%s] 请求处理完成，总耗时: %v, 重定向总数: %d, 最终URL: %s",
			reqID, totalDuration, len(redirectPath)-1, selectedURL)

		c.JSON(http.StatusOK, response)
	})

}

func getClientIP(c *gin.Context) string {
	// 按优先级检查多个 Header
	if ip := c.GetHeader("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For 可能包含多个 IP，取第一个
		ips := strings.Split(ip, ",")
		return strings.TrimSpace(ips[0])
	}

	if ip := c.GetHeader("X-Real-IP"); ip != "" {
		return ip
	}

	if ip := c.GetHeader("True-Client-IP"); ip != "" {
		return ip
	}

	// 如果都没有，则使用 RemoteAddr
	ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	return ip
}

func Listen(w http.ResponseWriter, r *http.Request) {
	router.ServeHTTP(w, r)
}

// 验证URL是否有效
func isValidURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return parsedURL.Scheme != "" && parsedURL.Host != ""
}

// 创建跟踪模板
func createTrackingTemplate(urlStr string) string {
	if !isValidURL(urlStr) {
		return ""
	}

	// 分割 URL 的基础部分和查询参数
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	// 获取查询参数部分
	queryPart := ""
	if parsedURL.RawQuery != "" {
		queryPart = "?" + parsedURL.RawQuery
	}

	// 返回 {lpurl} 加上查询参数
	return "{lpurl}" + queryPart
}

// 处理重定向URL，对特殊字符进行编码
func encodeRedirectURL(urlStr string) string {
	// 如果URL中包含空格，需要进行编码
	if strings.Contains(urlStr, " ") {
		// 分解URL为基础部分和查询参数
		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			return urlStr
		}

		// 编码路径部分
		path := parsedURL.Path
		if strings.Contains(path, " ") {
			segments := strings.Split(path, "/")
			for i, segment := range segments {
				segments[i] = url.PathEscape(segment)
			}
			parsedURL.Path = strings.Join(segments, "/")
		}

		// 编码查询参数，确保空格编码为 %20 而不是 +
		if parsedURL.RawQuery != "" {
			values := parsedURL.Query()
			encodedQuery := make([]string, 0)
			for key, vals := range values {
				for _, val := range vals {
					// 使用 PathEscape 而不是 QueryEscape，确保空格编码为 %20
					encodedQuery = append(encodedQuery, url.PathEscape(key)+"="+url.PathEscape(val))
				}
			}
			parsedURL.RawQuery = strings.Join(encodedQuery, "&")
		}

		// 编码 Fragment 部分（如果有的话）
		if parsedURL.Fragment != "" {
			parsedURL.Fragment = url.PathEscape(parsedURL.Fragment)
		}

		return parsedURL.String()
	}
	return urlStr
}

const evalFuncs = `
(function(){
    window.setTimeout = function(fn, delay) {
        fn();
    }
})()
`

// 使用chromedp跟踪URL重定向
func traceWithChromedp(initialURL string, timeout int, proxyConfig *ProxyConfig) ([]string, error) {
	log.Printf("使用Chromedp浏览器开始跟踪重定向: %s", initialURL)

	// 创建Chrome选项
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
		chromedp.UserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1"),
	)

	// 如果提供了代理配置，添加代理设置
	if proxyConfig != nil {
		proxyURL := fmt.Sprintf("%s:%s",
			proxyConfig.Host,
			proxyConfig.Port)

		log.Printf("使用代理: %s", proxyURL)

		opts = append(opts,
			chromedp.ProxyServer(proxyURL),
			chromedp.Flag("proxy-bypass-list", "<-loopback>"),
		)
	}

	// 创建分配器上下文
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	// 创建浏览器上下文
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// 设置超时
	ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// 为停止监听器创建事件上下文
	eventCtx, cancelEvent := context.WithCancel(ctx)
	defer cancelEvent()

	// 处理代理认证
	lctx, lcancel := context.WithCancel(ctx)
	defer lcancel()
	chromedp.ListenTarget(lctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *fetch.EventRequestPaused:
			go func() {
				_ = chromedp.Run(ctx, fetch.ContinueRequest(ev.RequestID))
			}()
		case *fetch.EventAuthRequired:
			if ev.AuthChallenge.Source == fetch.AuthChallengeSourceProxy {
				go func() {
					_ = chromedp.Run(ctx,
						fetch.ContinueWithAuth(ev.RequestID, &fetch.AuthChallengeResponse{
							Response: fetch.AuthChallengeResponseResponseProvideCredentials,
							Username: proxyConfig.Username,
							Password: proxyConfig.Password,
						}),
						fetch.Disable(),
					)
					lcancel()
				}()
			}
		}
	})

	// 存储重定向路径
	var redirects []string
	redirects = append(redirects, initialURL)
	var requestID network.RequestID
	var frameID cdp.FrameID

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			if containsURL(redirects, e.Response.URL) {
				fmt.Printf("%#v\n 状态码: %d\n", e.Response.URL, e.Response.Status)
			}
		// 	fmt.Printf("响应状态码: %d, URL: %s\n", e.Response.Status, e.Response.URL)
		case *page.EventFrameNavigated:
			// 检查URL是否在重定向列表中
			if e.Frame.ParentID == "" {
				if containsURL(redirects, e.Frame.URL) {
					// fmt.Printf("parentID: %s 主框架跳转到: %s\n  frameID: %s\n", e.Frame.ParentID, e.Frame.URL, e.Frame.ID)
					// fmt.Printf("%#v\n", e.Frame.URL, e.Response.Status)
					requestID = "" // 清空requestID
				}
			}
			// fmt.Printf("主框架跳转到: %s\n", e.Frame.URL)
			// fmt.Printf("%s 主框架跳转到: %#v\n", e.Frame.ID, e.Frame.URL)

		}
	})

	chromedp.ListenTarget(eventCtx, func(ev interface{}) {
		if ev, ok := ev.(*network.EventRequestWillBeSent); ok {

			if frameID == "" {
				frameID = ev.FrameID
			}

			if requestID == "" && ev.FrameID == frameID {
				// is it a reliable way to determine the initial request?
				if ev.Type == "Document" {
					requestID = ev.RequestID
					if containsURL(redirects, ev.Request.URL) == false {
						redirects = append(redirects, ev.Request.URL) // 添加到重定向列表
						fmt.Printf("requestID: %s 类型 %s 请求URL: %#v\n  frameID: %s\n", ev.RequestID, ev.Type, ev.Request.URL, ev.FrameID)
					} else {
						return
					}
				}
			}

			if ev.RequestID == requestID && ev.Type == "Document" && ev.FrameID == frameID {
				if containsURL(redirects, ev.Request.URL) == false {
					redirects = append(redirects, ev.Request.URL) // 添加到重定向列表
				} else {
					return
				}
				// fmt.Printf("%#v\n", ev.Request.URL)

				if ev.RedirectResponse != nil {
					fmt.Printf("重定向: %s → %s, 状态码: %d\n", ev.RedirectResponse.URL, ev.Request.URL, ev.RedirectResponse.Status)
				}
			}

			// if ev.Type == "Document" {
			// 	fmt.Printf("记录的requestID: %s\n", requestID)
			// 	fmt.Printf("%s %s 请求URL: %#v\n", ev.Type, ev.RequestID, ev.Request.URL)
			// }

		}
	})

	// 执行导航
	if err := chromedp.Run(ctx,
		fetch.Enable().WithHandleAuthRequests(true),
		network.Enable(),
		chromedp.ActionFunc(func(c context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(evalFuncs).Do(c)
			return err
		}),
		chromedp.Navigate(initialURL),
		chromedp.WaitReady("body"),
	); err != nil {
		log.Printf("导航失败: %v", err)
	}

	cancelEvent()

	// 打印最终的重定向路径
	log.Printf("重定向跟踪完成，共检测到 %d 个路径:", len(redirects))
	for i, url := range redirects {
		log.Printf("  [%d] %s", i, url)
	}

	return redirects, nil
}

// 检查URL是否已存在于重定向路径中
func containsURL(urls []string, url string) bool {
	for _, u := range urls {
		if u == url {
			return true
		}
	}
	return false
}

// 解析相对URL为绝对URL
func resolveURL(base, ref string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	refURL, err := url.Parse(ref)
	if err != nil {
		return "", err
	}

	resolvedURL := baseURL.ResolveReference(refURL)
	return resolvedURL.String(), nil
}
