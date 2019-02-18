package kraaler

import (
	"fmt"
	"net/url"

	ui "github.com/gizak/termui"
	"github.com/gizak/termui/widgets"
)

func URLWidget(stream <-chan *url.URL) (ui.Drawable, chan *url.URL) {
	out := make(chan *url.URL)
	l := widgets.NewList()
	l.Rows = []string{
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
	}
	l.TextStyle = ui.NewStyle(ui.ColorYellow)
	l.WrapText = false
	l.SetRect(0, 0, 45, 8)

	go func() {
		defer close(out)
		var n int

		for u := range stream {
			l.Rows = append([]string{u.String()}, l.Rows[0:9]...)
			l.Title = fmt.Sprintf("URLs (total: %d)", n)
			out <- u
			n += 1
		}
	}()

	return l, out
}

// func RenderUrlStore(render func(bs ...ui.Bufferer), us *urlStore) {
// 	table := ui.NewTable()
// 	table.FgColor = ui.ColorYellow
// 	table.BgColor = ui.ColorDefault
// 	table.Y = 0
// 	table.X = 0
// 	table.Width = 62
// 	table.Height = 7

// 	go func() {
// 		for {
// 			time.Sleep(time.Second)
// 			rows := [][]string{
// 				[]string{"URL", "Since"},
// 			}

// 			for link, since := range us.Fetching() {
// 				rows = append(rows, []string{link, humanize.Time(since)})
// 			}

// 			table.Rows = rows

// 			render(table)
// 		}
// 	}()
// }
