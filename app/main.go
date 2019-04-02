package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aau-network-security/kraaler"
	"github.com/aau-network-security/kraaler/store"
	ui "github.com/gizak/termui"
	"github.com/spf13/cobra"
)

var (
	ScreenDir  string
	BodyDir    string
	DBFile     string
	DomainFile string
)

var rootCmd = &cobra.Command{
	Use:   "krl",
	Short: "Kraaler is a contextual web crawler",
	Run: func(cmd *cobra.Command, args []string) {
		showErr := func(err error) {
			fmt.Printf("Error: %s\n", err)
		}

		if err := ensureDir(ScreenDir); err != nil {
			showErr(err)
			return
		}

		if err := ensureDir(BodyDir); err != nil {
			showErr(err)
			return
		}

		db, err := sql.Open("sqlite3", DBFile)
		if err != nil {
			showErr(err)
			return
		}

		us, err := store.NewURLStore(db, store.PairSampler(20), store.OnlyTLD("dk"))
		if err != nil {
			showErr(err)
			return
		}

		if DomainFile != "" {
			domainChan, err := kraaler.ReadDomainsFromFile(DomainFile)
			if err != nil {
				showErr(err)
				return
			}

			go func() {
				for dom := range kraaler.ScanForServers(
					us.FilterKnown(domainChan),
				) {
					us.Add(dom)
				}
			}()
		}

		ss, err := store.NewStore(db, BodyDir, ScreenDir)
		if err != nil {
			showErr(err)
			return
		}

		wc, err := kraaler.NewWorkerController(us, ss)
		if err != nil {
			showErr(err)
			return
		}

		wc.AddWorker()
		wc.AddWorker()
		wc.AddWorker()
		wc.AddWorker()
		wc.AddWorker()
		wc.AddWorker()
		wc.AddWorker()
		wc.AddWorker()
		wc.AddWorker()

		// renderUI(wc)
		time.Sleep(time.Minute * 60 * 24)
		fmt.Println("done!")
	},
}

func renderUI(wc *kraaler.WorkerController) {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	grid := ui.NewGrid()
	termWidth, termHeight := ui.TerminalDimensions()
	grid.SetRect(0, 0, termWidth, termHeight)
	grid.Set(
		ui.NewCol(1.0/2,
			wc.FactRecentSessions(),
		),

		ui.NewCol(1.0/2,
			ui.NewRow(.25, wc.FactWidget()),
			ui.NewRow(.75, nil),
		),
	)

	ui.Render(grid)

	uiEvents := ui.PollEvents()
	ticker := time.NewTicker(time.Second).C
	for {
		select {
		case e := <-uiEvents:
			switch e.ID {
			case "i":
				wc.AddWorker()
			case "q", "<C-c>":
				wc.Close()
				return
			case "<Resize>":
				payload := e.Payload.(ui.Resize)
				grid.SetRect(0, 0, payload.Width, payload.Height)
				ui.Clear()
				ui.Render(grid)
			}
		case <-ticker:
			ui.Render(grid)
		}
	}
}

func init() {
	rootCmd.Flags().StringVarP(&ScreenDir, "screen-dir", "s", "./screen", "Directory to store screenshots")
	rootCmd.Flags().StringVarP(&BodyDir, "body-dir", "b", "./bodies", "Directory for storing response bodies")
	rootCmd.Flags().StringVarP(&DBFile, "database-file", "d", "kraaler.db", "Name of database file")
	rootCmd.Flags().StringVarP(&DomainFile, "domain-file", "f", "", "File containing domains separated by newline")
}

func ensureDir(dir string) error {
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		return err
	}

	return os.MkdirAll(dir, os.ModePerm)
}

func main() {
	rootCmd.Execute()
	// if err := ui.Init(); err != nil {
	// 	log.Fatalf("failed to initialize termui: %v", err)
	// }
	// defer ui.Close()

	// wls := widgets.NewList()
	// wls.Rows = []string{
	// 	"[1] \"http://google.com\" (elapsed: 35s)",
	// }
	// wls.Title = "Workers"

	// sls := widgets.NewList()
	// sls.Rows = []string{
	// 	"Known URLs: 201239",
	// 	"Stored actions: 81239",
	// 	"Average save time: 240ms",
	// }
	// sls.Title = "Facts"
	// sls.BorderStyle = ui.NewStyle(ui.ColorGreen)

	// rfls := widgets.NewList()
	// rfls.Title = "Fetched (Recent)"
	// rfls.Rows = []string{
	// 	"  google.com[/some/path...] (time: 23s, size: 482 bytes)",
	// }

	// grid := ui.NewGrid()
	// termWidth, termHeight := ui.TerminalDimensions()
	// grid.SetRect(0, 0, termWidth, termHeight)
	// grid.Set(
	// 	ui.NewCol(1.0/2,
	// 		rfls,
	// 	),

	// 	ui.NewCol(1.0/2,
	// 		ui.NewRow(.25, sls),
	// 		ui.NewRow(.75, wls),
	// 	),
	// )

	// ui.Render(grid)

	// uiEvents := ui.PollEvents()
	// ticker := time.NewTicker(time.Second).C
	// for {
	// 	select {
	// 	case e := <-uiEvents:
	// 		switch e.ID {
	// 		case "q", "<C-c>":
	// 			return
	// 		case "<Resize>":
	// 			payload := e.Payload.(ui.Resize)
	// 			grid.SetRect(0, 0, payload.Width, payload.Height)
	// 			ui.Clear()
	// 			ui.Render(grid)
	// 		}
	// 	case <-ticker:
	// 		ui.Render(grid)
	// 	}
	// }

	// // domainFile := flag.String("f", "", "file with domains, line by line")
	// // if *domainFile == "" {
	// // 	fmt.Println("missing domains")
	// // 	return
	// // }

	// // domainChan, err := kraaler.ReadDomainsFromFile(*domainFile)

	// foundUrls := kraaler.ScanForServers(domainChan)
	// list, urlChan := kraaler.URLWidget(foundUrls)
	// sampler := kraaler.PairSampler(1000)
	// us := kraaler.NewURLStore(sampler)
	// go us.Push(urlChan)

	// if err := ui.Init(); err != nil {
	// 	log.Fatalf("failed to initialize termui: %v", err)
	// }
	// defer ui.Close()

	// uiEvents := ui.PollEvents()
	// ticker := time.NewTicker(time.Second).C
	// for {
	// 	select {
	// 	case e := <-uiEvents:
	// 		switch e.ID {
	// 		case "q", "<C-c>":
	// 			return
	// 		}
	// 	case <-ticker:
	// 		ui.Render(list)
	// 	}
	// }

	// // wc, err := kraaler.NewWorkerController(us)
	// // if err != nil {
	// // 	log.Fatal(err)
	// // }
	// // kraaler.RenderUrlStore(ui.Render, us)

}
