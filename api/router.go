package api

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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
	EnableProxy bool        `json:"enable_proxy"` // 是否启用代理
	Proxy       ProxyConfig `json:"proxy"`
	Link        string      `json:"link" binding:"required"`
	Timeout     int         `json:"timeout"` // 超时时间（秒）
}

// 响应结构体
type RedirectCheckResponse struct {
	RedirectPath []string `json:"redirect_path"`
	TargetURL    string   `json:"target_url"`
}

// 检查Meta刷新重定向
func checkMetaRefresh(body string) string {
	patterns := []string{
		`<meta\s+http-equiv="refresh"\s+content="0;\s*url=(.*?)"`,
		`<meta\s+http-equiv="refresh"\s+content="0;url=(.*?)"`,
		`<meta\s+http-equiv=refresh\s+content="0;\s*url=(.*?)"`,
		`<meta\s+http-equiv=refresh\s+content="0;url=(.*?)"`,
	}

	bodyLower := strings.ToLower(body)
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(bodyLower)
		if len(matches) > 1 {
			return strings.Trim(matches[1], `"'`)
		}
	}
	return ""
}

// 获取域名的IP地址
func getHostIP(hostname string) string {
	ips, err := net.LookupHost(hostname)
	if err != nil {
		return "无法解析IP"
	}
	return strings.Join(ips, ", ")
}

func init() {
	// 创建一个默认的路由引擎
	router = gin.Default()

	// 根路由 - 测试连通性
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "服务器运行正常",
		})
	})

	// 重定向检查服务
	router.POST("/redirect-check", func(c *gin.Context) {
		startTime := time.Now()
		clientIP := c.ClientIP()
		log.Printf("开始处理请求: %v, 客户端IP: %s", startTime, clientIP)

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
			log.Printf("请求参数: URL=%s (IP: %s), EnableProxy=%v, Timeout=%d",
				req.Link, targetIP, req.EnableProxy, req.Timeout)
		} else {
			log.Printf("请求参数: URL=%s (URL解析失败), EnableProxy=%v, Timeout=%d",
				req.Link, req.EnableProxy, req.Timeout)
		}

		// 设置默认超时时间为30秒
		if req.Timeout <= 0 {
			req.Timeout = 30
			log.Printf("使用默认超时时间: %d秒", req.Timeout)
		}

		// 创建HTTP客户端
		transport := &http.Transport{
			TLSHandshakeTimeout:   time.Duration(req.Timeout) * time.Second,
			ResponseHeaderTimeout: time.Duration(req.Timeout) * time.Second,
			ExpectContinueTimeout: time.Duration(req.Timeout) * time.Second,
			DisableKeepAlives:     true, // 禁用连接重用
		}

		// 如果启用代理，设置代理配置
		if req.EnableProxy {
			// 设置代理URL
			proxyURL := fmt.Sprintf("http://%s:%s@%s:%s",
				req.Proxy.Username,
				req.Proxy.Password,
				req.Proxy.Host,
				req.Proxy.Port)

			// 解析代理服务器IP
			proxyIP := getHostIP(req.Proxy.Host)
			log.Printf("使用代理: %s (IP: %s)",
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
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   time.Duration(req.Timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		redirectPath := []string{req.Link}
		currentURL := req.Link

		// 检查重定向
		for i := 0; i < 10; i++ {
			parsedURL, _ := url.Parse(currentURL)
			currentIP := getHostIP(parsedURL.Hostname())
			log.Printf("开始第 %d 次请求: %s (IP: %s)", i+1, currentURL, currentIP)
			reqStartTime := time.Now()

			reqObj, err := http.NewRequest("GET", currentURL, nil)
			if err != nil {
				log.Printf("创建请求失败: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "创建请求失败"})
				return
			}

			// 设置默认请求头
			reqObj.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)")
			reqObj.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			reqObj.Header.Set("Accept-Language", "en-US,en;q=0.9")
			reqObj.Header.Set("Connection", "close")

			resp, err := client.Do(reqObj)
			reqDuration := time.Since(reqStartTime)
			log.Printf("请求耗时: %v", reqDuration)

			if err != nil {
				log.Printf("请求失败: %v (类型: %T)", err, err)
				if strings.Contains(err.Error(), "timeout") {
					c.JSON(http.StatusGatewayTimeout, gin.H{
						"error": fmt.Sprintf("请求超时 (耗时: %v): %v", reqDuration, err),
						"url":   currentURL,
					})
				} else if strings.Contains(err.Error(), "EOF") {
					c.JSON(http.StatusBadGateway, gin.H{
						"error": fmt.Sprintf("服务器连接中断 (EOF) (耗时: %v): %v", reqDuration, err),
						"url":   currentURL,
					})
				} else {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": fmt.Sprintf("请求失败 (耗时: %v): %v", reqDuration, err),
						"url":   currentURL,
					})
				}
				return
			}

			log.Printf("收到响应: 状态码=%d, URL=%s", resp.StatusCode, currentURL)

			// 检查HTTP重定向
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if location != "" {
					log.Printf("发现HTTP重定向: %s", location)
					nextURL, err := url.Parse(location)
					if err != nil {
						log.Printf("解析重定向URL失败: %v", err)
						break
					}

					if !nextURL.IsAbs() {
						currentURLParsed, err := url.Parse(currentURL)
						if err != nil {
							log.Printf("解析当前URL失败: %v", err)
							break
						}
						nextURL = currentURLParsed.ResolveReference(nextURL)
					}

					currentURL = nextURL.String()
					redirectPath = append(redirectPath, currentURL)
					resp.Body.Close()
					continue
				}
			}

			// 检查meta刷新重定向
			if resp.StatusCode == 200 {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Printf("读取响应体失败: %v", err)
					resp.Body.Close()
					break
				}
				resp.Body.Close()

				if metaLocation := checkMetaRefresh(string(body)); metaLocation != "" {
					log.Printf("发现Meta刷新重定向: %s", metaLocation)
					nextURL, err := url.Parse(metaLocation)
					if err != nil {
						log.Printf("解析Meta重定向URL失败: %v", err)
						break
					}

					if !nextURL.IsAbs() {
						currentURLParsed, err := url.Parse(currentURL)
						if err != nil {
							log.Printf("解析当前URL失败: %v", err)
							break
						}
						nextURL = currentURLParsed.ResolveReference(nextURL)
					}

					currentURL = nextURL.String()
					redirectPath = append(redirectPath, currentURL)
					continue
				}
			}

			resp.Body.Close()
			break
		}

		response := RedirectCheckResponse{
			RedirectPath: redirectPath,
			TargetURL:    redirectPath[len(redirectPath)-1],
		}

		totalDuration := time.Since(startTime)
		log.Printf("请求处理完成，总耗时: %v, 重定向路径: %v", totalDuration, redirectPath)

		c.JSON(http.StatusOK, response)
	})

	// 启动服务器
	// log.Printf("服务器启动在端口 3001")
	// r.Run(":3001")
	router.Run()
}

// func init() {
// 	router = gin.Default()
// 	router.Any("/*path", func(context *gin.Context) {
// 		uri := context.Param("path")
// 		if !strings.Contains(uri, "bot") {
// 			context.String(http.StatusNotFound, "404 Not found")
// 			return
// 		}
// 		url := apiUrl + uri
// 		req, err := http.NewRequestWithContext(context, context.Request.Method, url, context.Request.Body)
// 		if err != nil {
// 			fmt.Println(err)
// 			context.String(http.StatusBadRequest, err.Error())
// 			return
// 		}
// 		req.Header = context.Request.Header
// 		req.PostForm = context.Request.PostForm
// 		req.Form = context.Request.Form
// 		resp, err := http.DefaultClient.Do(req)
// 		if err != nil {
// 			fmt.Println(err)
// 			context.String(http.StatusBadRequest, err.Error())
// 			return
// 		}
// 		context.DataFromReader(resp.StatusCode, resp.ContentLength, "application/json", resp.Body, nil)
// 	})
// }

func Listen(w http.ResponseWriter, r *http.Request) {
	router.ServeHTTP(w, r)
}




