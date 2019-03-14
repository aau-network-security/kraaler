package kraaler

import (
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func mimeIsHTML(mime string) bool {
	return strings.HasPrefix(mime, "text/html")
}

func matcherByRegexp(s string, strs ...string) (func(string) bool, error) {
	rgx, err := regexp.Compile(s)
	if err != nil {
		return nil, err
	}

	rgxps := []*regexp.Regexp{rgx}
	for _, s := range strs {
		rgx, err := regexp.Compile(s)
		if err != nil {
			return nil, err
		}

		rgxps = append(rgxps, rgx)
	}

	return func(s string) bool {
		for _, rgx := range rgxps {
			if ok := rgx.MatchString(s); ok {
				return true
			}
		}

		return false
	}, nil
}

func RetrieveLinks(host *url.URL, body []byte) ([]*url.URL, error) {
	kind := http.DetectContentType(body)
	m, err := matcherByRegexp("^/[a-zA-Z]+", "^http://", "^https://")
	if err != nil {
		return nil, err
	}

	urls := map[string]struct{}{}
	switch {
	case mimeIsHTML(kind):
		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}

		doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
			href, ok := s.Attr("href")
			if !ok {
				return
			}

			if m(href) {
				urls[href] = struct{}{}
			}
		})
	}

	var res []*url.URL
	for u, _ := range urls {
		link, err := url.Parse(u)
		if err != nil {
			continue
		}

		if link.Host == "" {
			// cannot replace source with anything meaningful
			if host.Host == "" {
				continue
			}

			link.Host = host.Host
			link.Scheme = host.Scheme
		}

		res = append(res, link)
	}

	return res, nil
}
