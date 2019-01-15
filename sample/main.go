package main

import (
	"fmt"
	"net/url"
	"time"

	"github.com/raff/godet"
)

type CrawlResponse struct {
}

type Crawler interface {
	Crawl(url.URL) (*CrawlResponse, error)
}

func main() {
	// connect to Chrome instance
	remote, err := godet.Connect("localhost:9222", false)
	if err != nil {
		fmt.Println("cannot connect to Chrome instance:", err)
		return
	}

	// disconnect when done
	defer remote.Close()

	// get list of open tabs
	tabs, _ := remote.TabList("")
	fmt.Println("Tabs: ", tabs)

	// install some callbacks
	remote.CallbackEvent(godet.EventClosed, func(params godet.Params) {
		fmt.Println("RemoteDebugger connection terminated.")
	})

	remote.CallbackEvent("Network.requestWillBeSent", func(params godet.Params) {
	})

	remote.CallbackEvent("Network.responseReceived", func(params godet.Params) {
		fmt.Println("responseReceived",
			params["frameId"],
			params["type"],
			params["response"].(map[string]interface{})["url"])
	})
	// create new tab
	tab, _ := remote.NewTab("http://www.aau.dk")

	// navigate in existing tab
	_ = remote.ActivateTab(tab)

	remote.AllEvents(true)

	fmt.Println("SPECIFIC TAB: ", *tab)

	time.Sleep(2 * time.Second)

	// take a screenshot
	_ = remote.SaveScreenshot("screenshot.png", 0644, 0, true)

	remote.CloseTab(tab)
}
