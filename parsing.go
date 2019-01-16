package kraaler

import (
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func RetrieveLinks(src string) []*url.URL {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(src))
	if err != nil {
		return nil
	}

	urls := map[string]struct{}{}

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, ok := s.Attr("href")
		if !ok {
			return
		}

		urls[href] = struct{}{}
	})

	var res []*url.URL
	for u, _ := range urls {
		link, err := url.Parse(u)
		if err != nil {
			continue
		}

		res = append(res, link)
	}

	return res
}
