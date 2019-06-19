package kraaler

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mafredri/cdp/protocol/network"
	"go.uber.org/zap"
)

type CTXLOGGER struct{}

type Domain string

func (d Domain) HTTP() string {
	return fmt.Sprintf("http://%s/", d)
}

func (d Domain) HTTPS() string {
	return fmt.Sprintf("https://%s/", d)
}

func ReadDomainsFromFile(path string) (<-chan Domain, error) {
	out := make(chan Domain)

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	go func() {
		formatTxt := func(s string) string {
			return strings.ToLower(strings.TrimSpace(s))
		}

		defer file.Close()
		defer close(out)

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			txt := formatTxt(scanner.Text())
			out <- Domain(txt)
		}

		if err := scanner.Err(); err != nil {
			return
		}
	}()

	return out, nil
}

type Resolution struct {
	Width  int
	Height int
}

func (r Resolution) String() string {
	return fmt.Sprintf("%dx%d", r.Width, r.Height)
}

func ScanForServers(ctx context.Context, domains <-chan Domain) <-chan *url.URL {
	out := make(chan *url.URL)
	timeout := 5 * time.Second
	log := func(string) {}

	logger, ok := ctx.Value(CTXLOGGER{}).(*zap.SugaredLogger)
	if ok {
		log = func(addr string) {
			logger.Info("found_web_server",
				"addr", addr,
			)
		}
	}

	openport := func(d Domain, p int) bool {
		endpoint := fmt.Sprintf("%s:%d", d, p)
		conn, err := net.DialTimeout("tcp", endpoint, timeout)
		if err != nil {
			return false
		}
		conn.Close()

		return true
	}

	go func() {
		defer close(out)
		for d := range domains {
			if openport(d, 443) {
				addr := d.HTTPS()
				u, _ := url.Parse(addr)

				select {
				case <-ctx.Done():
					return
				case out <- u:
					log(addr)
				}

				continue
			}

			if openport(d, 80) {
				addr := d.HTTP()
				u, _ := url.Parse(addr)

				select {
				case <-ctx.Done():
					return
				case out <- u:
					log(addr)
				}
			}
		}
	}()

	return out
}

type CrawlRequest struct {
	Url         *url.URL
	Screenshots []time.Duration
}

type CrawlResponse struct {
	Primary     *CrawlAction
	Secondaries []CrawlAction
	Error       error
}

type BrowserScreenshot struct {
	Screenshot []byte
	Resolution Resolution
	Kind       string
	Taken      time.Time
}

type CallFrame struct {
	Column     int
	LineNumber int
	Url        string
	Function   *string
}

type Initiator struct {
	Kind  string
	Stack *CallFrame
}

type Page struct {
	InitialURL   *url.URL
	Actions      []*CrawlAction
	Resolution   string
	Console      []*JavaScriptConsole
	Screenshots  []*BrowserScreenshot
	Error        error
	DocumentURLs []*url.URL

	InitiatedTime  time.Time
	NavigateTime   time.Time
	LoadedTime     time.Time
	TerminatedTime time.Time
}

type Host struct {
	Domain      Domain
	IPAddr      string
	NameServers []string
}

type CrawlAction struct {
	Parent    *CrawlAction
	Initiator Initiator

	Host     Host
	Request  network.Request
	Response *network.Response
	Error    *string
	Body     *ResponseBody

	Timings BrowserTimes
}

func (ca *CrawlAction) Finished() bool {
	return ca.Response != nil
}

// func NewCrawlActionFromParams(params map[string]interface{}) (*CrawlAction, error) {
// 	var err error
// 	var ca CrawlAction

// 	ca.Timings.StartTime, err = ReadFloatFromParams("timestamp", params)
// 	if err != nil {
// 		return nil, err
// 	}

// 	initz, err := GetParamsFromParams("initiator", params)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ca.Initiator, err = NewInitiator(initz)
// 	if err != nil {
// 		return nil, err
// 	}

// 	reqz, err := GetParamsFromParams("request", params)
// 	if err != nil {
// 		return nil, err
// 	}

// 	ca.Request.URL, err = ReadStringFromParams("url", reqz)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if fragment, err := ReadStringFromParams("urlFragment", reqz); err == nil {
// 		ca.Request.URL += fragment
// 	}

// 	ca.Request.Method, err = ReadStringFromParams("method", reqz)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if data, err := ReadStringFromParams("postData", reqz); err == nil {
// 		ca.Request.PostData = &data
// 	}

// 	headerz, err := GetParamsFromParams("headers", reqz)
// 	if err != nil {
// 		return nil, err
// 	}
// 	ca.Request.Headers = map[string]string{}
// 	for k, v := range headerz {
// 		vStr, _ := v.(string)
// 		ca.Request.Headers[k] = vStr
// 	}

// 	return &ca, nil
// }

// func (ca *CrawlAction) ReadResponse(br *network.Response, timestamp float64) error {
// 	ca.Timings.EndTime = timestamp

// 	if ca.Response == nil {
// 		var resp BrowserResponse
// 		ca.Response = &resp
// 	}

// 	if err := ca.Response.Read(br); err != nil {
// 		return err
// 	}

// 	ca.SecurityDetails = sec

// 	respz, err := GetParamsFromParams(key, params)
// 	if err != nil {
// 		return err
// 	}

// 	if ip, err := ReadStringFromParams("remoteIPAddress", respz); err == nil && ip != "" {
// 		ca.HostIP = &ip
// 	} else {
// 		u, err := url.Parse(ca.Request.URL)
// 		if err != nil {
// 			return err
// 		}

// 		ips, err := net.LookupHost(u.Host)
// 		if err == nil && len(ips) > 0 {
// 			ip := ips[0]
// 			ca.HostIP = &ip
// 		}
// 	}

// 	protocol, err := ReadStringFromParams("protocol", respz)
// 	if err != nil {
// 		return err
// 	}
// 	ca.Protocol = &protocol

// 	if timing, err := GetParamsFromParams("timing", respz); err == nil {
// 		connStart, err := ReadFloatFromParams("connectStart", timing)
// 		if err != nil {
// 			return err
// 		}
// 		ca.Timings.ConnectStartTime = &connStart

// 		connEnd, err := ReadFloatFromParams("connectEnd", timing)
// 		if err != nil {
// 			return err
// 		}
// 		ca.Timings.ConnectEndTime = &connEnd

// 		sendStart, err := ReadFloatFromParams("sendStart", timing)
// 		if err != nil {
// 			return err
// 		}
// 		ca.Timings.SendStartTime = &sendStart

// 		sendEnd, err := ReadFloatFromParams("sendEnd", timing)
// 		if err != nil {
// 			return err
// 		}
// 		ca.Timings.SendEndTime = &sendEnd
// 	}

// 	return nil
// }

// func (ca *CrawlAction) ReadError(params godet.Params) error {
// 	var err error
// 	ca.Timings.EndTime, err = ReadFloatFromParams("timestamp", params)
// 	if err != nil {
// 		return err
// 	}

// 	errMsg, err := ReadStringFromParams("errorText", params)
// 	if err != nil {
// 		return err
// 	}

// 	ca.ResponseError = &errMsg

// 	return nil
// }

type BrowserRequest struct {
	URL      string
	Method   string
	Headers  map[string]string
	PostData *string
}

type BrowserResponse struct {
	StatusCode         int
	Headers            map[string]string
	MimeType           string
	Body               []byte
	BodyChecksumSha256 string
}

func (br *BrowserResponse) Read(resp *network.Response) error {
	br.MimeType = resp.MimeType
	br.StatusCode = resp.Status
	header, err := resp.Headers.Map()
	if err != nil {
		return err
	}

	br.Headers = map[string]string{}
	for k, v := range header {
		br.Headers[k] = v
	}

	return nil
}

type BrowserTimes struct {
	StartTime        float64
	EndTime          float64
	ConnectStartTime *float64
	ConnectEndTime   *float64
	SendStartTime    *float64
	SendEndTime      *float64
}

func (bt *BrowserTimes) Align() {
	bt.StartTime -= bt.StartTime
	bt.EndTime -= bt.StartTime

	for _, f := range []*float64{
		bt.ConnectStartTime,
		bt.ConnectEndTime,
		bt.SendStartTime,
		bt.SendEndTime,
	} {
		if f != nil {
			newTime := *f - bt.StartTime
			f = &newTime
		}
	}
}
