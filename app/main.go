package main

import (
	"fmt"
	"log"
	"time"

	"github.com/aau-network-security/kraaler"

	ui "github.com/gizak/termui"
)

func main() {
	// domainFile := flag.String("f", "", "file with domains, line by line")
	// if *domainFile == "" {
	// 	fmt.Println("missing domains")
	// 	return
	// }

	// domainChan, err := kraaler.ReadDomainsFromFile(*domainFile)
	domainChan, err := kraaler.ReadDomainsFromFile("domainlist_sample.txt")
	if err != nil {
		fmt.Println(err)
		return
	}

	foundUrls := kraaler.ScanForServers(domainChan)
	list, urlChan := kraaler.URLWidget(foundUrls)
	sampler := kraaler.PairSampler(1000)
	us := kraaler.NewURLStore(sampler)
	go us.Push(urlChan)

	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	uiEvents := ui.PollEvents()
	ticker := time.NewTicker(time.Second).C
	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
				return
			}
		case <-ticker:
			ui.Render(list)
		}
	}

	// wc, err := kraaler.NewWorkerController(us)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// kraaler.RenderUrlStore(ui.Render, us)

}
