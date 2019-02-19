package kraaler

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/raff/godet"
)

type Domain string

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

func ScanForServers(domains <-chan Domain) <-chan *url.URL {
	out := make(chan *url.URL)

	go func() {
		defer close(out)

		for d := range domains {
			timeout := 5 * time.Second
			openport := func(p int) bool {
				endpoint := fmt.Sprintf("%s:%d", d, p)
				conn, err := net.DialTimeout("tcp", endpoint, timeout)
				if err != nil {
					return false
				}
				conn.Close()

				return true
			}

			if openport(80) {
				u, _ := url.Parse(fmt.Sprintf("http://%s/", d))
				out <- u
			}

			if openport(443) {
				u, _ := url.Parse(fmt.Sprintf("https://%s/", d))
				out <- u
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

// type DomainInfo struct {
// 	fetchCount int
// 	urlPool    map[*url.URL]struct{}
// }

// type urlStore struct {
// 	m sync.RWMutex

// 	domains  map[string]*DomainInfo
// 	known    map[string]bool
// 	fetching map[*url.URL]time.Time
// 	sampler  Sampler
// }

// func NewUrlStore(sampler Sampler) *urlStore {
// 	return &urlStore{
// 		domains:  map[string]*DomainInfo{},
// 		known:    map[string]bool{},
// 		fetching: map[*url.URL]time.Time{},
// 		sampler:  sampler,
// 	}
// }

// func (us *urlStore) Sample() *url.URL {
// 	us.m.Lock()
// 	defer us.m.Unlock()

// 	url := us.sampler(us.domains, us.known)
// 	us.fetching[url] = time.Now()

// 	return url
// }

// func (us *urlStore) Push(u *url.URL) error {
// 	link := u.String()
// 	if _, ok := us.known[link]; ok {
// 		return nil
// 	}

// 	if u.Host == "" {
// 		return fmt.Errorf("host of url is empty: %s", u)
// 	}

// 	if u.Scheme == "" {
// 		return fmt.Errorf("scheme of url is empty: %s", u)
// 	}

// 	domain, err := publicsuffix.EffectiveTLDPlusOne(u.Host)
// 	if err != nil {
// 		return err
// 	}

// 	us.m.Lock()
// 	defer us.m.Unlock()
// 	info := us.domains[domain]
// 	if info == nil {
// 		info = &DomainInfo{
// 			urlPool: map[*url.URL]struct{}{},
// 		}
// 		us.domains[domain] = info
// 	}

// 	info.urlPool[u] = struct{}{}

// 	return nil
// }

// func (us *urlStore) Completed(u *url.URL) {
// 	us.m.Lock()
// 	defer us.m.Unlock()
// 	if _, ok := us.fetching[u]; ok {
// 		delete(us.fetching, u)
// 		return
// 	}
// }

// func (us *urlStore) Fetching() map[string]time.Time {
// 	us.m.RLock()
// 	defer us.m.RUnlock()

// 	copy := map[string]time.Time{}
// 	for k, v := range us.fetching {
// 		copy[k.String()] = v
// 	}

// 	return copy
// }

type Sampler func(queued map[*url.URL]struct{}) *url.URL

func PairSampler(pw int) Sampler {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	domainCount := map[string]int{}

	return func(queued map[*url.URL]struct{}) *url.URL {
		weights := map[*url.URL]int{}
		for u, _ := range queued {
			weight := 1

			if count := domainCount[u.Host]; count == 1 {
				// almost a pair
				weight *= pw
			}

			weights[u] = weight
		}

		u := randomPickWeighted(r, weights)
		domainCount[u.Host] = domainCount[u.Host] + 1

		return u
	}
}

func randomPickWeighted(rd *rand.Rand, m map[*url.URL]int) *url.URL {
	var totalWeight int
	for _, w := range m {
		totalWeight += w
	}

	r := rd.Intn(totalWeight)

	for k, w := range m {
		r -= w
		if r <= 0 {
			return k
		}
	}

	return nil
}

type BrowserScreenshot struct {
	Screenshot []byte
	Resolution Resolution
	Kind       string
	Taken      time.Time
}

type CrawlSession struct {
	ID             string
	Actions        []*CrawlAction
	Resolution     string
	Console        []string
	Screenshots    []*BrowserScreenshot
	Error          error
	StartTime      time.Time
	LoadedTime     time.Time
	TerminatedTime time.Time
}

type CrawlAction struct {
	Parent          *CrawlAction
	Initiator       string
	Protocol        *string
	HostIP          *string
	SecurityDetails *BrowserSecurityDetails

	Request       BrowserRequest
	Response      *BrowserResponse
	ResponseError *string

	Timings BrowserTimes
}

func (ca *CrawlAction) Finished() bool {
	return ca.Response != nil
}

func NewCrawlActionFromParams(params map[string]interface{}) (*CrawlAction, error) {
	var err error
	var ca CrawlAction

	ca.Timings.StartTime, err = ReadFloatFromParams("timestamp", params)
	if err != nil {
		return nil, err
	}

	initz, err := GetParamsFromParams("initiator", params)
	if err != nil {
		return nil, err
	}

	ca.Initiator, err = ReadStringFromParams("type", initz)
	if err != nil {
		return nil, err
	}

	reqz, err := GetParamsFromParams("request", params)
	if err != nil {
		return nil, err
	}

	ca.Request.URL, err = ReadStringFromParams("url", reqz)
	if err != nil {
		return nil, err
	}

	if fragment, err := ReadStringFromParams("urlFragment", reqz); err == nil {
		ca.Request.URL += fragment
	}

	ca.Request.Method, err = ReadStringFromParams("method", reqz)
	if err != nil {
		return nil, err
	}

	if data, err := ReadStringFromParams("postData", reqz); err == nil {
		ca.Request.PostData = &data
	}

	headerz, err := GetParamsFromParams("headers", reqz)
	if err != nil {
		return nil, err
	}
	ca.Request.Headers = map[string]string{}
	for k, v := range headerz {
		vStr, _ := v.(string)
		ca.Request.Headers[k] = vStr
	}

	return &ca, nil
}

func (ca *CrawlAction) ReadResponse(params map[string]interface{}, key string) error {
	var err error
	ca.Timings.EndTime, err = ReadFloatFromParams("timestamp", params)
	if err != nil {
		return err
	}

	var resp BrowserResponse
	if err := resp.Read(params, key); err != nil {
		return err
	}

	ca.Response = &resp

	respz, err := GetParamsFromParams(key, params)
	if err != nil {
		return err
	}

	if ip, err := ReadStringFromParams("remoteIPAddress", respz); err == nil {
		ca.HostIP = &ip
	}

	protocol, err := ReadStringFromParams("protocol", respz)
	if err != nil {
		return err
	}
	ca.Protocol = &protocol

	if timing, err := GetParamsFromParams("timing", respz); err == nil {
		connStart, err := ReadFloatFromParams("connectStart", timing)
		if err != nil {
			return err
		}
		ca.Timings.ConnectStartTime = &connStart

		connEnd, err := ReadFloatFromParams("connectEnd", timing)
		if err != nil {
			return err
		}
		ca.Timings.ConnectEndTime = &connEnd

		sendStart, err := ReadFloatFromParams("sendStart", timing)
		if err != nil {
			return err
		}
		ca.Timings.SendStartTime = &sendStart

		sendEnd, err := ReadFloatFromParams("sendEnd", timing)
		if err != nil {
			return err
		}
		ca.Timings.SendEndTime = &sendEnd
	}

	return nil
}

func (ca *CrawlAction) ReadError(params godet.Params) error {
	var err error
	ca.Timings.EndTime, err = ReadFloatFromParams("timestamp", params)
	if err != nil {
		return err
	}

	errMsg, err := ReadStringFromParams("errorText", params)
	if err != nil {
		return err
	}

	ca.ResponseError = &errMsg

	return nil
}

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

func (br *BrowserResponse) Read(params map[string]interface{}, key string) error {
	rawResp, ok := params[key].(map[string]interface{})
	if !ok {
		return &NoParamErr{"response"}
	}

	br.MimeType, ok = rawResp["mimeType"].(string)
	if !ok {
		return &NoParamErr{"mimeType"}
	}

	rawStatus, ok := rawResp["status"].(float64)
	if !ok {
		return &NoParamErr{"status"}
	}
	br.StatusCode = int(rawStatus)

	rawHeaders, ok := rawResp["headers"].(map[string]interface{})
	if !ok {
		return &NoParamErr{"headers"}
	}

	br.Headers = map[string]string{}
	for k, v := range rawHeaders {
		vStr, _ := v.(string)

		br.Headers[k] = vStr
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

type BrowserSecurityDetails struct {
	Protocol    string
	KeyExchange string
	Cipher      string
	SubjectName string
	SanList     []string
	Issuer      string
	ValidFrom   time.Time
	ValidTo     time.Time
}
