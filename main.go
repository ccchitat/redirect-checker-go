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
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
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
