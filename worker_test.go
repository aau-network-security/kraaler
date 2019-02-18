package kraaler_test

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aau-network-security/kraaler"
	docker "github.com/fsouza/go-dockerclient"
)

var travis bool

func init() {
	flag.BoolVar(&travis, "travis", false, "is the tester travis")
	flag.Parse()
}

func dockerInterfaceIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, i := range ifaces {
		if i.Name != "docker0" {
			continue
		}

		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			return fmt.Sprintf("%s", ip), nil
		}

	}

	return "", nil
}

func responseFromServerWithHandler(handler http.Handler) (*kraaler.CrawlSession, error) {
	dip, err := dockerInterfaceIP()
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s:%d", dip, kraaler.GetAvailablePort())
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	ts := httptest.NewUnstartedServer(handler)
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()
	defer ts.Close()

	q := make(chan kraaler.CrawlRequest, 1)
	resps := make(chan kraaler.CrawlSession, 1)
	dclient, err := docker.NewClient("unix:///var/run/docker.sock")
	if err != nil {
		return nil, err
	}

	var instance string
	if travis {
		instance = "localhost:9222"
	}

	w, err := kraaler.NewWorker(kraaler.WorkerConfig{
		Queue:        q,
		Responses:    resps,
		DockerClient: dclient,
		UseInstance:  instance,
	})
	if err != nil {
		return nil, err
	}
	defer w.Close()

	endpoint := fmt.Sprintf("http://%s", addr)
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	q <- kraaler.CrawlRequest{
		Url: u,
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
				return fmt.Errorf("expected action with index %d to be %d (status code), but it is:%d", i, c, sc)
			}
		}

		return nil
	}
}

func bodyIs(str string) validator {
	return func(s kraaler.CrawlSession) error {
		actions := s.Actions
		if b := strings.TrimSpace(string(actions[len(actions)-1].Response.Body)); b != str {
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

func TestCrawl(t *testing.T) {
	txtHandler := func(s string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, s) })
	}

	redirectHandler := http.NewServeMux()
	redirectHandler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/other", 301) })
	redirectHandler.HandleFunc("/other", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/last", 301) })
	redirectHandler.HandleFunc("/last", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "hello world") })

	tt := []struct {
		name      string
		handler   http.Handler
		validator validator
	}{
		{
			name:    "basic",
			handler: txtHandler("hello world"),
			validator: join(
				hasActionCount(1),
				bodyIs("hello world"),
				codesAre(http.StatusOK),
			),
		},

		{
			name:    "console",
			handler: txtHandler("<script>console.log('a a');console.log('b')</script>"),
			validator: join(
				hasActionCount(1),
				consoleIs([]string{"a a", "b"}),
				codesAre(http.StatusOK),
			),
		},
		{
			name:    "redirect",
			handler: redirectHandler,
			validator: join(
				hasActionCount(3),
				codesAre(http.StatusMovedPermanently, http.StatusMovedPermanently, http.StatusOK),
				bodyIs("hello world"),
			),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := responseFromServerWithHandler(tc.handler)
			if err != nil {
				t.Fatal(err)
			}

			if err := tc.validator(*resp); err != nil {
				t.Fatal(err)
			}
		})
	}

}
