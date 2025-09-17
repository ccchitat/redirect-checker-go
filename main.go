package main

import (
	"bufio"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"redirect-checker-go/api"
)

// enforceServerWhitelistFromFile checks whether the current server is allowed to run
// by reading a text file `whitelist.txt` in the working directory.
// File format: one entry per line; supports plain IP (IPv4/IPv6) or CIDR; lines starting with '#' or '//' and blank lines are ignored.
// If the file is missing or contains no valid entries, the program exits.
func enforceServerWhitelistFromFile(filePath string) {
	ips, cidrs, err := loadWhitelist(filePath)
	if err != nil {
		log.Fatalf("无法读取白名单文件: %s，错误: %v", filePath, err)
	}
	if len(ips) == 0 && len(cidrs) == 0 {
		log.Fatalf("白名单文件 %s 中未找到有效的 IP/CIDR 条目，拒绝运行", filePath)
	}

	// Only use detected public IPv4 for matching.
	pub := tryFetchPublicIPv4(2 * time.Second)
	if pub == "" {
		log.Fatalf("无法获取服务器公网IPv4，拒绝运行。请确保网络可用，或稍后重试。")
	}
	pubIP := net.ParseIP(pub)
	if pubIP == nil || pubIP.To4() == nil {
		log.Fatalf("解析公网IPv4失败(%q)，拒绝运行。", pub)
	}

	// Match public IP against whitelist
	matched := false
	for _, allow := range ips {
		if pubIP.Equal(allow) {
			matched = true
			break
		}
	}
	if !matched {
		for _, n := range cidrs {
			if n.Contains(pubIP) {
				matched = true
				break
			}
		}
	}

	if matched {
		log.Printf("服务器白名单检查通过（按公网IPv4）。公网IPv4=%s，白名单条目: %d (IP) / %d (CIDR)", pubIP.String(), len(ips), len(cidrs))
		return
	}

	log.Printf("服务器白名单检查未通过：公网IPv4=%s 不在白名单 (文件: %s)", pubIP.String(), filePath)
	log.Fatalf("拒绝运行（未在公网IP白名单中）")
}

func loadWhitelist(filePath string) ([]net.IP, []*net.IPNet, error) {
	f, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
		return nil, nil, err
	}
	defer f.Close()

	var ips []net.IP
	var cidrs []*net.IPNet
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if _, n, err := net.ParseCIDR(line); err == nil {
			cidrs = append(cidrs, n)
			continue
		}
		// Ignore invalid entries silently, but could log if needed
	}
	if err := s.Err(); err != nil {
		return nil, nil, err
	}
	return ips, cidrs, nil
}

func main() {
	// 启动时先打印本机 IP 信息（便于核对白名单与环境）
	logLocalIPs()
	logPublicIP()

	// 在启动HTTP服务前执行服务器白名单校验（基于文本文件）
	enforceServerWhitelistFromFile("whitelist.txt")
	// 设置路由处理函数
	http.HandleFunc("/", api.Listen)

	// 启动服务器
	log.Printf("服务器启动在默认端口")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}

// logLocalIPs prints current host IPv4/IPv6 addresses (excluding loopback)
func logLocalIPs() {
	var v4, v6 []string
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		// 仅处理已启用网卡
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			// 过滤链路本地 IPv6 (fe80::/10) 打印时不优先展示
			if ip.To16() != nil && ip.To4() == nil {
				if strings.HasPrefix(strings.ToLower(ip.String()), "fe80:") {
					continue
				}
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				v4 = append(v4, ipv4.String())
			} else if ip.To16() != nil {
				v6 = append(v6, ip.String())
			}
		}
	}
	// 计算首选出站本地 IPv4（不发包，仅通过路由栈选择本地地址）
	primary := primaryLocalIPv4()
	j4 := strings.Join(v4, ", ")
	j6 := strings.Join(v6, ", ")
	if primary != "" {
		log.Printf("本机IP地址: 首选IPv4=%s; IPv4=[%s]; IPv6=[%s]", primary, j4, j6)
	} else {
		log.Printf("本机IP地址: IPv4=[%s]; IPv6=[%s]", j4, j6)
	}
}

// primaryLocalIPv4 returns the local IPv4 chosen by routing for outbound connections.
func primaryLocalIPv4() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la.IP != nil {
		if ip4 := la.IP.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}

// logPublicIP tries to fetch and print the public IPv4 address (best-effort, non-fatal).
func logPublicIP() {
	pub := tryFetchPublicIPv4(1500 * time.Millisecond)
	if pub != "" {
		log.Printf("服务器公网IPv4: %s", pub)
	}
}

func tryFetchPublicIPv4(timeout time.Duration) string {
	endpoints := []string{
		"https://api.ipify.org",  // plain text IPv4/IPv6
		"https://ifconfig.me/ip", // plain text
		"https://ipinfo.io/ip",   // plain text
	}
	client := &http.Client{Timeout: timeout}
	for _, ep := range endpoints {
		req, _ := http.NewRequest("GET", ep, nil)
		req.Header.Set("Accept", "text/plain")
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		b := make([]byte, 64)
		n, _ := resp.Body.Read(b)
		resp.Body.Close()
		if n <= 0 {
			continue
		}
		s := strings.TrimSpace(string(b[:n]))
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

// package main

// import (
// 	"context"
// 	"fmt"
// 	"time"

// 	"github.com/chromedp/cdproto/cdp"
// 	"github.com/chromedp/cdproto/network"
// 	"github.com/chromedp/cdproto/page"
// 	"github.com/chromedp/chromedp"
// )

// const evalFuncs = `
// (function(){
//     window.setTimeout = function(fn, delay) {
//         fn();
//         //return _(fn, 0)
//     }
// })()
// `

// func main() {
// 	opts := append(chromedp.DefaultExecAllocatorOptions[:],
// 		chromedp.UserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3239.108 Safari/537.36"),
// 		chromedp.Flag("blink-settings", "imagesEnabled=false"),
// 		chromedp.Flag("disable-gpu", true),
// 		chromedp.Flag("headless", true),
// 	)
// 	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
// 	defer cancel()

// 	// use chromedp.WithDebugf to log the CDP messages
// 	// ctx, cancel = chromedp.NewContext(ctx, chromedp.WithDebugf(log.Printf))
// 	ctx, cancel = chromedp.NewContext(ctx)
// 	defer cancel()

// 	// Note: it's generally a bad idea to use a context timeout on the first Run call, as it will stop the entire browser
// 	// see https://github.com/chromedp/chromedp/blob/b88710e33da89f65c9ed750381125aea3922254c/chromedp.go#L258-L264
// 	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
// 	defer cancel()

// 	startTime := time.Now() // 记录开始时间

// 	// for stopping the listener from receiving any more events
// 	// see https://github.com/chromedp/chromedp/blob/b88710e33da89f65c9ed750381125aea3922254c/chromedp.go#L693-L701
// 	eventCtx, cancelEvent := context.WithCancel(ctx)
// 	defer cancelEvent()

// 	// to store the id of the initial request
// 	// it seems that all the following requests with the same request id are redirects of the initial request.
// 	// I'm not sure about this. Please have a thorough test.
// 	var requestID network.RequestID
// 	var frameID cdp.FrameID
// 	var redirectURLs []string // 存储重定向URL列表

// 	chromedp.ListenTarget(ctx, func(ev interface{}) {
// 		switch e := ev.(type) {
// 		case *network.EventResponseReceived:
// 			if containsURL(redirectURLs, e.Response.URL) {
// 				fmt.Printf("%#v\n 状态码: %d\n", e.Response.URL, e.Response.Status)
// 			}
// 		// 	fmt.Printf("响应状态码: %d, URL: %s\n", e.Response.Status, e.Response.URL)
// 		case *page.EventFrameNavigated:
// 			// 检查URL是否在重定向列表中
// 			if e.Frame.ParentID == "" {
// 				if containsURL(redirectURLs, e.Frame.URL) {
// 					// fmt.Printf("parentID: %s 主框架跳转到: %s\n  frameID: %s\n", e.Frame.ParentID, e.Frame.URL, e.Frame.ID)
// 					// fmt.Printf("%#v\n", e.Frame.URL, e.Response.Status)
// 					requestID = "" // 清空requestID
// 				}
// 			}
// 			// fmt.Printf("主框架跳转到: %s\n", e.Frame.URL)
// 			// fmt.Printf("%s 主框架跳转到: %#v\n", e.Frame.ID, e.Frame.URL)

// 		}
// 	})

// 	chromedp.ListenTarget(eventCtx, func(ev interface{}) {
// 		if ev, ok := ev.(*network.EventRequestWillBeSent); ok {

// 			if frameID == "" {
// 				frameID = ev.FrameID
// 			}

// 			if requestID == "" && ev.FrameID == frameID {
// 				// is it a reliable way to determine the initial request?
// 				if ev.Type == "Document" {
// 					requestID = ev.RequestID
// 					redirectURLs = append(redirectURLs, ev.Request.URL) // 添加到重定向列表
// 				} else {
// 					return
// 				}
// 			}

// 			if ev.RequestID == requestID && ev.Type == "Document" && ev.FrameID == frameID {
// 				redirectURLs = append(redirectURLs, ev.Request.URL) // 添加到重定向列表
// 				// fmt.Printf("requestID: %s 类型 %s 请求URL: %#v\n  frameID: %s\n", ev.RequestID, ev.Type, ev.Request.URL, ev.FrameID)
// 				// fmt.Printf("%#v\n", ev.Request.URL)

// 				if ev.RedirectResponse != nil {
// 					fmt.Printf("重定向: %s → %s, 状态码: %d\n", ev.RedirectResponse.URL, ev.Request.URL, ev.RedirectResponse.Status)
// 				}
// 			}

// 			// if ev.Type == "Document" {
// 			// 	fmt.Printf("记录的requestID: %s\n", requestID)
// 			// 	fmt.Printf("%s %s 请求URL: %#v\n", ev.Type, ev.RequestID, ev.Request.URL)
// 			// }

// 		}
// 	})

// 	if err := chromedp.Run(ctx,
// 		chromedp.ActionFunc(func(c context.Context) error {
// 			_, err := page.AddScriptToEvaluateOnNewDocument(evalFuncs).Do(c)
// 			return err
// 		}),
// 		// chromedp.Navigate("https://r.blueaff.com/5ZB8XW2/4KPF7Q4"),、
// 		chromedp.Navigate("https://app.partnermatic.com/track/2b66n4jaR5eZGpuiDalM_a3q94_awd8epApYvhzLB_aMG9l3OFb7i6XKSZFScpoJzFEHlbHCYtyEHRSk9Y_c"),
// 		chromedp.WaitReady("body"),
// 		// chromedp.ActionFunc(func(ctx context.Context) error {
// 		// 	var ok bool
// 		// 	return chromedp.Evaluate(`document.body !== null`, &ok).Do(ctx)
// 		// }),
// 	); err != nil {
// 		elapsed := time.Since(startTime)
// 		fmt.Printf("发生错误: %v\n运行时间: %v\n", err, elapsed)
// 	}

// 	cancelEvent()

// 	fmt.Printf("重定向URL列表: %v\n", redirectURLs)
// }

// // 检查URL是否已存在于重定向路径中
// func containsURL(urls []string, url string) bool {
// 	for _, u := range urls {
// 		if u == url {
// 			return true
// 		}
// 	}
// 	return false
// }
