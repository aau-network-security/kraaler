package kraaler

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type URLProvider interface {
	UrlsC() <-chan *url.URL
}

type DomainFileProvider struct {
	path string
	c    DomainFileProviderConfig
	urls chan *url.URL
	stop chan struct{}
	once sync.Once
}

type DomainFileProviderConfig struct {
	Logger  *zap.Logger
	Timeout time.Duration
	Targets map[int]func(string) string
}

func NewDomainFileProvider(path string, conf *DomainFileProviderConfig) (*DomainFileProvider, error) {
	var c DomainFileProviderConfig
	if conf != nil {
		c = *conf
	}

	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	if c.Logger == nil {
		c.Logger = zap.L()
	}

	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}

	if c.Targets == nil {
		c.Targets = map[int]func(string) string{
			80:  func(s string) string { return fmt.Sprintf("http://%s", s) },
			443: func(s string) string { return fmt.Sprintf("https://%s", s) },
		}
	}

	return &DomainFileProvider{
		path: path,
		c:    c,
		urls: make(chan *url.URL),
		stop: make(chan struct{}),
	}, nil
}

func (dfp *DomainFileProvider) UrlsC() <-chan *url.URL {
	dfp.once.Do(func() {
		openport := func(addr string, p int) bool {
			endpoint := fmt.Sprintf("%s:%d", addr, p)
			conn, err := net.DialTimeout("tcp", endpoint, dfp.c.Timeout)
			if err != nil {
				return false
			}
			conn.Close()

			return true
		}

		go func() {
			formatTxt := func(s string) string {
				return strings.ToLower(strings.TrimSpace(s))
			}

			file, err := os.Open(dfp.path)
			if err != nil {
				return
			}

			defer file.Close()
			defer close(dfp.urls)

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				addr := formatTxt(scanner.Text())
				for port, fmter := range dfp.c.Targets {
					if openport(addr, port) {
						foundUrl := fmter(addr)
						u, _ := url.Parse(foundUrl)

						dfp.c.Logger.Info("found_web_server",
							zap.String("url", foundUrl),
						)

						select {
						case dfp.urls <- u:
						case <-dfp.stop:
							return
						}
					}
				}
			}

			if err := scanner.Err(); err != nil {
				return
			}
		}()
	})

	return dfp.urls
}

func (dfp *DomainFileProvider) Close() {
	close(dfp.stop)
}

type phishTankEntry struct {
	ID               int
	RawID            string    `json:"phish_id"`
	Url              string    `json:"url"`
	SubmissionTime   time.Time `json:"submission_time"`
	VerificationTime time.Time `json:"verification_time"`
	Online           string    `json:"online"`
	Target           string    `json:"target"`
}

type phishTankEntryList []phishTankEntry

func (el phishTankEntryList) Len() int           { return len(el) }
func (el phishTankEntryList) Swap(i, j int)      { el[i], el[j] = el[j], el[i] }
func (el phishTankEntryList) Less(i, j int) bool { return el[i].ID < el[j].ID }

type PhishTankProvider struct {
	conf PhishTankProviderConfig
	once sync.Once
	etag string
	stop chan struct{}
	urls chan *url.URL
}

type PhishTankProviderConfig struct {
	Endpoint     string
	APIKey       string
	TickDuration time.Duration
}

func NewPhishTankProviderWithConfig(conf PhishTankProviderConfig) *PhishTankProvider {
	if conf.Endpoint == "" {
		conf.Endpoint = "http://data.phishtank.com/data/online-valid.json.gz"
	}

	if conf.APIKey != "" {
		conf.Endpoint = fmt.Sprintf("http://data.phishtank.com/data/%s/online-valid.json.gz", conf.APIKey)
	}

	if conf.TickDuration == 0 {
		conf.TickDuration = 20 * time.Minute
	}

	return &PhishTankProvider{
		conf: conf,
		stop: make(chan struct{}),
		urls: make(chan *url.URL),
	}
}

func NewPhishTankProvider() *PhishTankProvider {
	return NewPhishTankProviderWithConfig(PhishTankProviderConfig{})
}

func (ptr *PhishTankProvider) getEntries() ([]phishTankEntry, error) {
	resp, err := http.Head(ptr.conf.Endpoint)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	etag := resp.Header.Get("Etag")
	if etag == ptr.etag {
		return nil, nil
	}

	ptr.etag = etag
	resp, err = http.Get(ptr.conf.Endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	uncompressed, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer uncompressed.Close()

	var entries phishTankEntryList
	err = json.NewDecoder(uncompressed).Decode(&entries)
	if err != nil {
		return nil, err
	}

	for i, _ := range entries {
		e := entries[i]
		e.ID, _ = strconv.Atoi(e.RawID)
		entries[i] = e
	}

	sort.Sort(entries)

	return entries, nil
}

func (ptr *PhishTankProvider) UrlsC() <-chan *url.URL {
	ptr.once.Do(func() {
		go func() {
			ticker := time.NewTicker(ptr.conf.TickDuration)
			defer ticker.Stop()
			defer close(ptr.urls)

			var newestId int
			for {
				entries, err := ptr.getEntries()
				if err != nil {
					fmt.Println(err)
				}

				for _, e := range entries {
					if e.ID <= newestId {
						continue
					}

					u, err := url.Parse(e.Url)
					if err != nil {
						continue
					}

					select {
					case ptr.urls <- u:
						newestId = e.ID
					case <-ptr.stop:
						return
					}
				}

				select {
				case <-ticker.C:
				case <-ptr.stop:
					return
				}
			}
		}()
	})

	return ptr.urls
}

func (ptr *PhishTankProvider) Close() {
	close(ptr.stop)
}
