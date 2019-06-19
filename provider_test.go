package kraaler_test

import (
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aau-network-security/kraaler"
)

func TestDomainFileProvider(t *testing.T) {
	tt := []struct {
		name           string
		startServer    bool
		domains        []string
		expectedAmount int
	}{
		{
			name:           "present server",
			startServer:    true,
			expectedAmount: 1,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			conf := kraaler.DomainFileProviderConfig{}
			if tc.startServer {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("hello world"))
				}))
				defer ts.Close()

				u, _ := url.Parse(ts.URL)
				_, port, err := net.SplitHostPort(u.Host)
				if err != nil {
					t.Fatalf("unable to split host and port: %s", err)
				}

				portInt, err := strconv.Atoi(port)
				if err != nil {
					t.Fatalf("unable to get port: %s", err)
				}

				tc.domains = append(tc.domains, "127.0.0.1")
				conf.Targets = map[int]func(string) string{
					portInt: func(s string) string { return fmt.Sprintf("http://%s", s) },
				}
			}

			tmpfile, err := ioutil.TempFile("", "kraaler-test-file-provider")
			if err != nil {
				t.Fatalf("unable to create temp file: %s", err)
			}
			defer os.Remove(tmpfile.Name())

			_, err = tmpfile.Write([]byte(strings.Join(tc.domains, "\n")))
			if err != nil {
				t.Fatalf("unable to write to temp file: %s", err)
			}

			dfp, err := kraaler.NewDomainFileProvider(tmpfile.Name(), &conf)
			if err != nil {
				t.Fatalf("unable to create file provider: %s", err)
			}
			defer dfp.Close()

			var urls []*url.URL
			for u := range dfp.UrlsC() {
				urls = append(urls, u)
			}

			if tc.expectedAmount != len(urls) {
				t.Fatalf("unexpected amount %d, expected: %d", len(urls), tc.expectedAmount)
			}
		})
	}

}

func TestPhishTankReader(t *testing.T) {
	tt := []struct {
		name           string
		servOut        string
		expectedAmount int
	}{
		{
			name:           "one url",
			servOut:        `[{"phish_id":"1","url":"http://test.com","submission_time":"2019-05-12T21:45:13+00:00","verified":"yes","verification_time":"2019-05-12T21:47:54+00:00","online":"yes"}]`,
			expectedAmount: 1,
		},
		{
			name:           "two urls",
			servOut:        `[{"phish_id":"2","url":"http://test2.com"},{"phish_id":"1","url":"http://test.com"}]`,
			expectedAmount: 2,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var HeadRequestsAmount int
			var GetRequestsAmount int
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodHead:
					w.Header().Add("Etag", fmt.Sprintf("%d", HeadRequestsAmount))
					HeadRequestsAmount += 1
				case http.MethodGet:
					writer := gzip.NewWriter(w)
					writer.Write([]byte(tc.servOut))
					writer.Flush()
					GetRequestsAmount += 1
				}
			}))
			defer ts.Close()

			ptr := kraaler.NewPhishTankProviderWithConfig(
				kraaler.PhishTankProviderConfig{
					Endpoint: ts.URL,
				},
			)
			defer ptr.Close()

			var urls []*url.URL
		loop:
			for {
				select {
				case u := <-ptr.UrlsC():
					urls = append(urls, u)
				case <-time.After(300 * time.Millisecond):
					break loop
				}

			}

			if tc.expectedAmount != len(urls) {
				t.Fatalf("unexpected amount %d, expected: %d", len(urls), tc.expectedAmount)
			}
		})
	}

}
