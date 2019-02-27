package kraaler_test

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aau-network-security/kraaler"
)

var (
	chromeBinaries = []string{
		"chromium",             // used by linux
		"google-chrome-stable", // used by travis
	}
	chromeBinary = ""
)

func init() {
	for _, b := range chromeBinaries {
		path, _ := exec.LookPath(b)
		if path != "" {
			chromeBinary = path
			break
		}
	}
}

func getAvailablePort() uint {
	l, _ := net.Listen("tcp", ":0")
	parts := strings.Split(l.Addr().String(), ":")
	l.Close()

	p, _ := strconv.Atoi(parts[len(parts)-1])

	return uint(p)
}

func responseFromServerWithHandler(handler http.Handler, port uint, useTLS bool, dur *time.Duration) (*kraaler.CrawlSession, error) {
	ts := httptest.NewUnstartedServer(handler)
	if handler != nil {
		if useTLS {
			ts.StartTLS()
		} else {
			ts.Start()
		}
	}

	defer ts.Close()

	q := make(chan kraaler.CrawlRequest, 1)
	resps := make(chan kraaler.CrawlSession, 1)

	second := time.Second
	w, err := kraaler.NewWorker(kraaler.WorkerConfig{
		Queue:       q,
		Responses:   resps,
		UseInstance: fmt.Sprintf("localhost:%d", port),
		LoadTimeout: &second,
	})
	if err != nil {
		return nil, err
	}
	defer w.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		return nil, err
	}

	var screenshots []time.Duration
	if dur != nil {
		screenshots = []time.Duration{*dur}
	}

	q <- kraaler.CrawlRequest{
		Url:         u,
		Screenshots: screenshots,
	}

	r := <-resps
	return &r, nil
}

type validator func(kraaler.CrawlSession) error

func codesAre(codes ...int) validator {
	return func(s kraaler.CrawlSession) error {
		if len(codes) != len(s.Actions) {
			return fmt.Errorf("expected %d codes, but received: %d", len(codes), len(s.Actions))
		}

		for i, c := range codes {
			if sc := s.Actions[i].Response.StatusCode; sc != c {
				return fmt.Errorf("expected action with index %d to be %d (status code), but it is: %d", i, c, sc)
			}
		}

		return nil
	}
}

func bodiesAre(bodies ...string) validator {
	return func(s kraaler.CrawlSession) error {
		if len(bodies) != len(s.Actions) {
			return fmt.Errorf("expected %d bodies, but received: %d", len(bodies), len(s.Actions))
		}

		for i, b := range bodies {
			if fetched := strings.TrimSpace(string(s.Actions[i].Response.Body)); fetched != b {
				return fmt.Errorf("unexpected body (%s), expected: %s", fetched, b)
			}
		}

		return nil
	}
}

func initiatorsAre(inits ...string) validator {
	return func(s kraaler.CrawlSession) error {
		if len(inits) != len(s.Actions) {
			return fmt.Errorf("expected %d initators, but received: %d", len(inits), len(s.Actions))
		}

		for i, expected := range inits {
			if init := strings.TrimSpace(string(s.Actions[i].Initiator.Kind)); init != expected {
				return fmt.Errorf("unexpected initiator (%s), expected: %s", init, expected)
			}
		}

		return nil
	}
}

func mimeIs(str string) validator {
	return func(s kraaler.CrawlSession) error {
		actions := s.Actions
		if b := strings.TrimSpace(string(actions[len(actions)-1].Response.MimeType)); b != str {
			return fmt.Errorf("unexpected body (%s), expected: %s", b, str)
		}
		return nil
	}
}

func hasActionCount(n int) validator {
	return func(s kraaler.CrawlSession) error {
		if len(s.Actions) != n {
			return fmt.Errorf("expected %d amount of actions, but got: %d", n, len(s.Actions))
		}
		return nil
	}
}

func join(v validator, vs ...validator) validator {
	return func(r kraaler.CrawlSession) error {
		if err := v(r); err != nil {
			return err
		}

		for _, v := range vs {
			if err := v(r); err != nil {
				return err
			}
		}

		return nil
	}
}

func consoleIs(c []string) validator {
	return func(s kraaler.CrawlSession) error {
		if n := len(s.Console); len(c) != n {
			return fmt.Errorf("unexpected length of console: %d", n)
		}

		for i, expected := range c {
			if s.Console[i] != expected {
				return fmt.Errorf("unexpected output (%s), expected: %s", s.Console[i], expected)
			}
		}

		return nil
	}
}

func postDataIs(str string) validator {
	return func(s kraaler.CrawlSession) error {
		postdata := s.Actions[len(s.Actions)-1].Request.PostData
		if postdata == nil {
			return fmt.Errorf("expected post data to be (%s), but it is nil", str)
		}

		if *postdata != str {
			return fmt.Errorf("expected post data to be (%s), but received: %s", str, *postdata)
		}

		return nil
	}
}

func securityDetailsPresent(s kraaler.CrawlSession) error {
	for i, a := range s.Actions {
		if a.SecurityDetails == nil {
			return fmt.Errorf("expected security details to be non-nil (request n: %d)", i+1)
		}
	}

	return nil
}

func TestCrawl(t *testing.T) {
	if chromeBinary == "" {
		t.Fatal("unable to locate chrome binary")
	}

	txtHandler := func(s string, sc int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(sc); fmt.Fprintln(w, s) })
	}

	closerHandler := http.NewServeMux()
	closerHandler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "can't hijack rw", http.StatusInternalServerError)
			return
		}

		conn, _, _ := hj.Hijack()
		conn.Close()
	})

	redirectHandler := http.NewServeMux()
	redirectHandler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/other", 301) })
	redirectHandler.HandleFunc("/other", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/last", 301) })
	redirectHandler.HandleFunc("/last", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "hello world") })

	multiHandler := http.NewServeMux()
	multiHandlerRootBody := `<html><body><img src="/img"/></body></html>`
	multiHandler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, multiHandlerRootBody)
	})
	multiHandler.HandleFunc("/img", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, "not found")
	})

	tt := []struct {
		name      string
		handler   http.Handler
		tls       bool
		wait      time.Duration
		validator validator
	}{
		{
			name:    "basic",
			handler: txtHandler("hello world", http.StatusOK),
			validator: join(
				hasActionCount(1),
				initiatorsAre("user"),
				bodiesAre("hello world"),
				codesAre(http.StatusOK),
				mimeIs("text/plain"),
			),
		},
		{
			name:    "basic tls",
			handler: txtHandler("hello world", http.StatusOK),
			tls:     true,
			validator: join(
				hasActionCount(1),
				initiatorsAre("user"),
				bodiesAre("hello world"),
				codesAre(http.StatusOK),
				mimeIs("text/plain"),
				securityDetailsPresent,
			),
		},
		{
			name:    "no server",
			handler: nil,
			validator: join(
				hasActionCount(0),
			),
		},
		{
			name:    "not found status",
			handler: txtHandler("not found", http.StatusNotFound),
			validator: join(
				hasActionCount(1),
				initiatorsAre("user"),
				bodiesAre("not found"),
				codesAre(http.StatusNotFound),
				mimeIs("text/plain"),
			),
		},
		{
			name:    "console",
			handler: txtHandler("<script>console.log('a a');console.log('b')</script>", http.StatusOK),
			validator: join(
				hasActionCount(1),
				initiatorsAre("user"),
				consoleIs([]string{"a a", "b"}),
				codesAre(http.StatusOK),
				mimeIs("text/html"),
			),
		},
		{
			name:    "redirect",
			handler: redirectHandler,
			validator: join(
				hasActionCount(3),
				initiatorsAre("user", "redirect", "redirect"),
				codesAre(http.StatusMovedPermanently, http.StatusMovedPermanently, http.StatusOK),
				bodiesAre("", "", "hello world"),
				mimeIs("text/plain"),
			),
		},
		{
			name:    "html parsing",
			handler: multiHandler,
			validator: join(
				hasActionCount(2),
				initiatorsAre("user", "parser"),
				bodiesAre(multiHandlerRootBody, "not found"),
				codesAre(http.StatusOK, http.StatusNotFound),
				mimeIs("text/plain"),
			),
		},
		{
			name:    "post data",
			handler: txtHandler("<script>function hest() { var xhr = new XMLHttpRequest(); xhr.open('POST', '/poster'); xhr.send('some_data'); }; hest()</script>", http.StatusOK),
			wait:    500 * time.Millisecond,
			validator: join(
				hasActionCount(2),
				initiatorsAre("user", "script"),
				codesAre(http.StatusOK, http.StatusOK),
				mimeIs("text/html"),
				postDataIs("some_data"),
			),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			port := getAvailablePort()
			cmd := exec.Command(chromeBinary,
				"--headless",
				"--ignore-certificate-errors",
				"--disable-gpu",
				fmt.Sprintf("--remote-debugging-port=%d", port),
				"http://localhost")

			if err := cmd.Start(); err != nil {
				t.Fatalf("unable to start chrome: %s", err)
			}
			defer func() {
				if err := cmd.Process.Kill(); err != nil {
					log.Fatal("failed to kill process: ", err)
				}
			}()

			var wait *time.Duration
			var ti time.Duration
			if tc.wait != ti {
				wait = &tc.wait
			}

			resp, err := responseFromServerWithHandler(tc.handler, port, tc.tls, wait)
			if err != nil {
				t.Fatal(err)
			}

			if err := tc.validator(*resp); err != nil {
				t.Fatal(err)
			}
		})
	}

}
