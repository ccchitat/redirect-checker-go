package api

import (
	"bytes"
	"encoding/json"
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
	EnableProxy *bool       `json:"enable_proxy"` // 是否启用代理，未传入时默认为true
	Proxy       ProxyConfig `json:"proxy"`
	Link        string      `json:"link" binding:"required"`
	Timeout     int         `json:"timeout"` // 超时时间（秒）
	Referer     string      `json:"referer"` // 请求来源
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
	Code   int    `json:"code"`
	Msg    string `json:"msg"`
	IPInfo struct {
		Type string `json:"type"`
		Text string `json:"text"`
		CNIP bool   `json:"cnip"`
	} `json:"ipinfo"`
	IPData struct {
		Info1 string `json:"info1"`
		Info2 string `json:"info2"`
		Info3 string `json:"info3"`
		ISP   string `json:"isp"`
	} `json:"ipdata"`
	ADCode struct {
		O string `json:"o"`
		P string `json:"p"`
		C string `json:"c"`
		N string `json:"n"`
	} `json:"adcode"`
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

// 获取IP信息
func getIPInfo(client *http.Client) (*IPInfo, error) {
	// 创建请求
	req, err := http.NewRequest("GET", "https://api.vore.top/api/IPdata", nil)
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
		})
	})

	// 重定向检查服务
	router.POST("/redirect-check", func(c *gin.Context) {
		startTime := time.Now()
		clientIP := getClientIP(c)
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

		// 设置默认启用代理
		if req.EnableProxy == nil {
			defaultValue := true
			req.EnableProxy = &defaultValue
			log.Printf("默认启用代理")
		}

		// 创建HTTP客户端
		transport := &http.Transport{
			TLSHandshakeTimeout:   time.Duration(req.Timeout) * time.Second,
			ResponseHeaderTimeout: time.Duration(req.Timeout) * time.Second,
			ExpectContinueTimeout: time.Duration(req.Timeout) * time.Second,
			DisableKeepAlives:     true, // 禁用连接重用
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

		// 获取IP信息
		ipInfo, err := getIPInfo(client)
		if err != nil {
			log.Printf("获取IP信息失败: %v", err)
			c.JSON(http.StatusOK, RedirectCheckResponse{
				Status: 0,
				Error:  "网络连接错误",
				IPInfo: IPInfoResponse{
					IP:      "未知",
					Country: "未知",
					Region:  "未知",
					City:    "未知",
				},
			})
			return
		}
		log.Printf("当前IP信息: IP=%s, 国家=%s, 地区=%s, ISP=%s",
			ipInfo.IPInfo.Text, ipInfo.IPData.Info1, ipInfo.IPData.Info2, ipInfo.IPData.ISP)

		redirectPath := []string{req.Link}
		currentURL := req.Link

		// 检查重定向
		for i := 0; i < 10; i++ {
			parsedURL, _ := url.Parse(currentURL)
			currentIP := getHostIP(parsedURL.Hostname())
			reqStartTime := time.Now()

			reqObj, err := http.NewRequest("GET", currentURL, nil)
			if err != nil {
				log.Printf("创建请求失败: %v", err)
				c.JSON(http.StatusOK, RedirectCheckResponse{
					Status: 0,
					Error:  "创建请求失败",
					IPInfo: IPInfoResponse{
						IP:      ipInfo.IPInfo.Text,
						Country: ipInfo.IPData.Info1,
						Region:  ipInfo.IPData.Info2,
						City:    ipInfo.IPData.Info3,
					},
				})
				return
			}

			// 设置默认请求头
			reqObj.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)")
			reqObj.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			reqObj.Header.Set("Accept-Language", "en-US,en;q=0.9")
			reqObj.Header.Set("Connection", "close")
			if req.Referer != "" {
				reqObj.Header.Set("Referer", req.Referer)
			}

			log.Printf("开始第 %d 次请求: %s (IP: %s) Referer: %s", i+1, currentURL, currentIP, req.Referer)

			resp, err := client.Do(reqObj)
			reqDuration := time.Since(reqStartTime)
			log.Printf("请求耗时: %v", reqDuration)

			if err != nil {
				log.Printf("请求失败: %v (类型: %T)", err, err)
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
						IP:      ipInfo.IPInfo.Text,
						Country: ipInfo.IPData.Info1,
						Region:  ipInfo.IPData.Info2,
						City:    ipInfo.IPData.Info3,
					},
					TargetURL: currentURL,
				})
				return
			}

			log.Printf("收到响应: 状态码=%d, URL=%s", resp.StatusCode, currentURL)

			// 检查HTTP重定向
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if location != "" {
					log.Printf("发现HTTP重定向: %s", location)

					// 对重定向URL进行编码处理
					location = encodeRedirectURL(location)
					log.Printf("编码后的重定向URL: %s", location)

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

					// 对Meta重定向URL进行编码处理
					metaLocation = encodeRedirectURL(metaLocation)
					log.Printf("编码后的Meta重定向URL: %s", metaLocation)

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

		// 成功响应
		response := RedirectCheckResponse{
			Status: 1,
			IPInfo: IPInfoResponse{
				IP:      ipInfo.IPInfo.Text,
				Country: ipInfo.IPData.Info1,
				Region:  ipInfo.IPData.Info2,
				City:    ipInfo.IPData.Info3,
			},
			RedirectPath:     redirectPath,
			TargetURL:        redirectPath[len(redirectPath)-1],
			TrackingTemplate: createTrackingTemplate(redirectPath[len(redirectPath)-1]),
		}

		totalDuration := time.Since(startTime)
		log.Printf("请求处理完成，总耗时: %v, 重定向路径: %v", totalDuration, redirectPath)

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
