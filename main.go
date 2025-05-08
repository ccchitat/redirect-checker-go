// package main

// import (
// 	"log"
// 	"net/http"
// 	"redirect-checker-go/api"
// )

// func main() {
// 	// 设置路由处理函数
// 	http.HandleFunc("/", api.Listen)

// 	// 启动服务器
// 	log.Printf("服务器启动在默认端口")
// 	if err := http.ListenAndServe(":3000", nil); err != nil {
// 		log.Fatalf("服务器启动失败: %v", err)
// 	}
// }

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

const evalFuncs = `
(function(){
    window.setTimeout = function(fn, delay) {
        fn();
        //return _(fn, 0)
    }
})()
`

func main() {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3239.108 Safari/537.36"),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("headless", true),
	)
	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// use chromedp.WithDebugf to log the CDP messages
	// ctx, cancel = chromedp.NewContext(ctx, chromedp.WithDebugf(log.Printf))
	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	// Note: it's generally a bad idea to use a context timeout on the first Run call, as it will stop the entire browser
	// see https://github.com/chromedp/chromedp/blob/b88710e33da89f65c9ed750381125aea3922254c/chromedp.go#L258-L264
	ctx, cancel = context.WithTimeout(ctx, 50*time.Second)
	defer cancel()

	// for stopping the listener from receiving any more events
	// see https://github.com/chromedp/chromedp/blob/b88710e33da89f65c9ed750381125aea3922254c/chromedp.go#L693-L701
	eventCtx, cancelEvent := context.WithCancel(ctx)
	defer cancelEvent()

	// to store the id of the initial request
	// it seems that all the following requests with the same request id are redirects of the initial request.
	// I'm not sure about this. Please have a thorough test.
	var requestID network.RequestID
	chromedp.ListenTarget(eventCtx, func(ev interface{}) {
		if ev, ok := ev.(*network.EventRequestWillBeSent); ok {
			if requestID == "" {
				// is it a reliable way to determine the initial request?
				if ev.Type == "Document" {
					requestID = ev.RequestID
				} else {
					return
				}
			}

			if ev.RequestID == requestID {
				fmt.Printf("%#v\n", ev.Request.URL)
			}
		}
	})

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventFrameNavigated:
			if e.Frame.ParentID == "" { // 主框架跳转
				fmt.Printf("主框架跳转到: %s,    %s", e.Frame.URL, e.Frame.ParentID)
			}

		}
	})

	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(c context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(evalFuncs).Do(c)
			return err
		}),
		chromedp.Navigate("https://app.partnermatic.com/track/e80aXa07YmzIPNe1t6OKR7A80npKl2fYb1zHyaqeA33HMsqPad2oDcW8ylzsXHd9avNPHN0Qdn65udU5Kyk_a"),
	); err != nil {
		panic(err)
	}
	// stop the listener from receiving any more events
	// it's necessary when you have more tasks to run afterward
	cancelEvent()
}