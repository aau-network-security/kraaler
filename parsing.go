package kraaler

import (
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func RetrieveLinks(src, body string) ([]*url.URL, error) {
	host, err := url.Parse(src)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return nil, err
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

		if link.Host == "" {
			link.Host = host.Host
		}

		if link.Scheme == "" {
			link.Scheme = host.Scheme
		}

		res = append(res, link)
	}

	return res, nil
}
