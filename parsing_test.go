package kraaler_test

import (
	"testing"

	"github.com/aau-network-security/kraaler"
)

func TestRetrieveLinks(t *testing.T) {
	tt := []struct {
		name string
		src  string
		urls int
	}{
		{name: "simple valid", src: "<html><a href=\"https://google.com\">t</a></html>", urls: 1},
		{name: "empty", src: "<html></html>", urls: 0},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if n := len(kraaler.RetrieveLinks(tc.src)); n != tc.urls {
				t.Fatalf("expected to find %d urls, but found %d", tc.urls, n)
			}
		})
	}
}
