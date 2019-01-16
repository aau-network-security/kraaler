package kraaler_test

import (
	"testing"

	"github.com/aau-network-security/kraaler"
)

func TestRetrieveLinks(t *testing.T) {
	domain := "https://test.com"
	tt := []struct {
		name string
		src  string
		urls []string
	}{
		{
			name: "simple valid",
			src:  `<html><a href="https://google.com">t</a></html>`,
			urls: []string{
				"https://google.com",
			},
		},
		{
			name: "relative valid",
			src:  `<html><a href="/search">t</a></html>`,
			urls: []string{
				domain + "/search",
			},
		},
		{
			name: "empty",
			src:  "<html></html>",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			found, err := kraaler.RetrieveLinks(domain, tc.src)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if n := len(found); n != len(tc.urls) {
				t.Fatalf("expected to find %d urls, but found %d", tc.urls, n)
			}

			expectedUrls := map[string]bool{}
			for _, link := range tc.urls {
				expectedUrls[link] = true
			}

			for _, foundUrl := range found {
				if ok := expectedUrls[foundUrl.String()]; !ok {
					t.Fatalf("unexpected url: %s", foundUrl)
				}
			}
		})
	}
}
