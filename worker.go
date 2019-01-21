package kraaler

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/google/uuid"
	"github.com/raff/godet"
)

var DefaultClient *docker.Client

func init() {
	var err error
	DefaultClient, err = docker.NewClient("unix:///var/run/docker.sock")
	if err != nil {
		log.Fatal(err)
	}
}

type NoParamErr struct{ param string }

func (npe *NoParamErr) Error() string { return fmt.Sprintf("unable to get param: %s", npe.param) }

type NotOfTypeErr struct{ kind string }

func (note *NotOfTypeErr) Error() string { return fmt.Sprintf("value is not of type: %s", note.kind) }

type Worker struct {
	ID   string
	Port uint

	container *docker.Container
	rdb       *godet.RemoteDebugger

	kill chan struct{}
}

func NewWorker(queue <-chan *FetchRequest, results chan<- FetchResponse) (*Worker, error) {
	id := uuid.New().String()[0:8]
	w := &Worker{
		ID: id,
	}

	c, err := w.createContainer()
	if err != nil {
		return nil, err
	}
	w.container = c

	WaitForPort(w.Port)

	rdb, err := godet.Connect(fmt.Sprintf("localhost:%d", w.Port), false)
	if err != nil {
		return nil, err
	}
	w.rdb = rdb

	go w.listen(queue, results)

	return w, nil
}

func (w *Worker) listen(queue <-chan *FetchRequest, results chan<- FetchResponse) {
	w.kill = make(chan struct{})

	for {
		select {
		case <-w.kill:
			return

		case req := <-queue:
			results <- w.fetch(req)
		}
	}
}

func (w *Worker) createContainer() (*docker.Container, error) {
	if w.Port == 0 {
		port := GetAvailablePort()
		w.Port = port
	}

	opts := docker.CreateContainerOptions{
		Name: fmt.Sprintf("kraaler-worker-%s", w.ID),
		Config: &docker.Config{
			Image: "justinribeiro/chrome-headless",
		},
		HostConfig: &docker.HostConfig{
			MemorySwap:       0,
			MemorySwappiness: 0,
			Memory:           756 * 1024 * 1024,
			CapAdd:           []string{"SYS_ADMIN"},
			PortBindings: map[docker.Port][]docker.PortBinding{
				docker.Port("9222/tcp"): {{
					HostIP:   "127.0.0.1",
					HostPort: fmt.Sprintf("%d", w.Port),
				}},
			},
		},
	}

	c, err := DefaultClient.CreateContainer(opts)
	if err != nil {
		return nil, err
	}

	if err := DefaultClient.StartContainer(c.ID, nil); err != nil {
		DefaultClient.RemoveContainer(docker.RemoveContainerOptions{ID: c.ID})
		return nil, err
	}

	return c, nil
}

func (w *Worker) Close() {
	w.kill <- struct{}{}

	if w.rdb != nil {
		w.rdb.Close()
	}

	if w.container != nil {
		DefaultClient.RemoveContainer(docker.RemoveContainerOptions{
			ID:    w.container.ID,
			Force: true,
		})
	}
}

func ReadStringFromParams(key string, params map[string]interface{}) (string, error) {
	v, ok := params[key]
	if !ok {
		return "", &NoParamErr{key}
	}

	vStr, ok := v.(string)
	if !ok {
		return "", &NotOfTypeErr{"string"}
	}

	return vStr, nil
}

func ReadFloatFromParams(key string, params map[string]interface{}) (float64, error) {
	v, ok := params[key]
	if !ok {
		return 0, &NoParamErr{key}
	}

	vFloat, ok := v.(float64)
	if !ok {
		return 0, &NotOfTypeErr{"float64"}
	}

	return vFloat, nil
}

func GetParamsFromParams(key string, params map[string]interface{}) (map[string]interface{}, error) {
	v, ok := params[key]
	if !ok {
		return nil, &NoParamErr{key}
	}

	vMap, ok := v.(map[string]interface{})
	if !ok {
		return nil, &NotOfTypeErr{"map[string]interface{}"}
	}

	return vMap, nil
}

type BrowserAction struct {
	ID         string
	Parent     string
	Initiator  string
	Protocol   *string
	CPUProfile []float64

	Request       BrowserRequest
	Response      *BrowserResponse
	HostIP        *string
	ResponseError *string

	Console []string
	Timings BrowserTimes
}

func (ba *BrowserAction) Read(event string, params godet.Params) error {
	switch event {
	case "Network.requestWillBeSent":
		return ba.ReadRequest(params)

	case "Network.responseReceived":
		return ba.ReadResponse(params)

	case "Network.loadingFailed":
		return ba.ReadError(params)
	}

	return fmt.Errorf("unknown event")
}

func (ba *BrowserAction) ReadRequest(gparams godet.Params) error {
	params := map[string]interface{}(gparams)
	var err error

	ba.ID, err = ReadStringFromParams("requestId", params)
	if err != nil {
		return err
	}

	ba.Parent, err = ReadStringFromParams("loaderId", params)
	if err != nil {
		return err
	}

	ba.Timings.StartTime, err = ReadFloatFromParams("timestamp", params)
	if err != nil {
		return err
	}

	initz, err := GetParamsFromParams("initiator", params)
	if err != nil {
		return err
	}

	ba.Initiator, err = ReadStringFromParams("type", initz)
	if err != nil {
		return err
	}

	reqz, err := GetParamsFromParams("request", params)
	if err != nil {
		return err
	}

	ba.Request.URL, err = ReadStringFromParams("url", reqz)
	if err != nil {
		return err
	}

	if fragment, err := ReadStringFromParams("urlFragment", reqz); err == nil {
		ba.Request.URL += fragment
	}

	ba.Request.Method, err = ReadStringFromParams("method", reqz)
	if err != nil {
		return err
	}

	if data, err := ReadStringFromParams("postData", reqz); err == nil {
		ba.Request.PostData = &data
	}

	headerz, err := GetParamsFromParams("headers", reqz)
	if err != nil {
		return err
	}
	ba.Request.Headers = map[string]string{}
	for k, v := range headerz {
		vStr, _ := v.(string)
		ba.Request.Headers[k] = vStr
	}

	return nil
}

func (ba *BrowserAction) ReadResponse(params map[string]interface{}) error {
	var err error
	ba.Timings.EndTime, err = ReadFloatFromParams("timestamp", params)
	if err != nil {
		return err
	}

	var resp BrowserResponse
	if err := resp.Read(params); err != nil {
		return err
	}

	ba.Response = &resp

	respz, err := GetParamsFromParams("response", params)
	if err != nil {
		return err
	}

	if ip, err := ReadStringFromParams("remoteIPAddress", respz); err == nil {
		ba.HostIP = &ip
	}

	protocol, err := ReadStringFromParams("protocol", respz)
	if err != nil {
		return err
	}
	ba.Protocol = &protocol

	if timing, err := GetParamsFromParams("timing", respz); err == nil {
		connStart, err := ReadFloatFromParams("connectStart", timing)
		if err != nil {
			return err
		}
		ba.Timings.ConnectStartTime = &connStart

		connEnd, err := ReadFloatFromParams("connectEnd", timing)
		if err != nil {
			return err
		}
		ba.Timings.ConnectEndTime = &connEnd

		sendStart, err := ReadFloatFromParams("sendStart", timing)
		if err != nil {
			return err
		}
		ba.Timings.SendStartTime = &sendStart

		sendEnd, err := ReadFloatFromParams("sendEnd", timing)
		if err != nil {
			return err
		}
		ba.Timings.SendEndTime = &sendEnd

		pushStart, err := ReadFloatFromParams("pushStart", timing)
		if err != nil {
			return err
		}
		ba.Timings.PushStartTime = &pushStart

		pushEnd, err := ReadFloatFromParams("pushEnd", timing)
		if err != nil {
			return err
		}
		ba.Timings.PushEndTime = &pushEnd
	}

	return nil
}

func (ba *BrowserAction) ReadError(params godet.Params) error {
	var err error
	ba.Timings.EndTime, err = ReadFloatFromParams("timestamp", params)
	if err != nil {
		return err
	}

	errMsg, err := ReadStringFromParams("errorText", params)
	if err != nil {
		return err
	}

	ba.ResponseError = &errMsg

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

func (br *BrowserResponse) Read(params map[string]interface{}) error {
	rawResp, ok := params["response"].(map[string]interface{})
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
	PushStartTime    *float64
	PushEndTime      *float64
}

func (w *Worker) fetch(req *FetchRequest) FetchResponse {
	stop := make(chan time.Time)

	w.rdb.CallbackEvent("Page.frameStoppedLoading", func(params godet.Params) {
		stop <- time.Now()
	})

	var logs []string
	w.rdb.CallbackEvent("Runtime.consoleAPICalled",
		godet.ConsoleAPICallback(func(items []interface{}) {
			fmt.Println(items)
			if len(items) < 2 {
				return
			}

			kind, ok := items[0].(string)
			if !ok {
				return
			}

			if kind != "console.log" {
				return
			}

			var logMsg string
			for i := 1; i < len(items); i++ {
				logMsg += fmt.Sprintf(" %v", items[i])
			}

			logs = append(logs, logMsg[1:])
		}))

	requests := map[string]BrowserAction{}
	for _, e := range []string{
		"Network.requestWillBeSent",
		"Network.responseReceived",
	} {
		func(e string) {
			w.rdb.CallbackEvent(e, func(params godet.Params) {
				id, ok := params["requestId"].(string)
				if !ok {
					return
				}

				ba := requests[id]
				if err := ba.Read(e, params); err != nil {
					log.Println("reading error:", err)
				}
				requests[id] = ba
			})
		}(e)
	}

	tab, err := w.rdb.NewTab("about:blank")
	if err != nil {
		return FetchResponse{Error: err}
	}

	w.rdb.NetworkEvents(true)
	w.rdb.RuntimeEvents(true)
	w.rdb.PageEvents(true)

	clear := func() {
		w.rdb.CloseTab(tab)
		w.rdb.ClearBrowserCache()
		w.rdb.ClearBrowserCookies()
	}
	defer clear()

	if err := w.rdb.ActivateTab(tab); err != nil {
		return FetchResponse{Error: err}
	}

	time.Sleep(time.Second)

	start := time.Now()
	if _, err := w.rdb.Navigate(req.Url.String()); err != nil {
		return FetchResponse{Error: err}
	}

	t := <-stop

	time.Sleep(time.Second)

	fmt.Println(logs)
	fmt.Println(t.Sub(start))

	for _, r := range requests {
		if r.ResponseError != nil {
			continue
		}

		body, err := w.rdb.GetResponseBody(r.ID)
		if err != nil {
			fmt.Println("body error: ", err)
			continue
		}

		fmt.Println(r)

		r.Response.Body = body
		r.Response.BodyChecksumSha256 = fmt.Sprintf("%x", sha256.Sum256(body))

		requests[r.ID] = r
	}

	// w.rdb.SaveScreenshot("screenshot.png", 0644, 0, true)

	return FetchResponse{}
}

func GetAvailablePort() uint {
	l, _ := net.Listen("tcp", ":0")
	parts := strings.Split(l.Addr().String(), ":")
	l.Close()

	p, _ := strconv.Atoi(parts[len(parts)-1])

	return uint(p)
}

func WaitForPort(port uint) {
	for {
		conn, _ := godet.Connect(fmt.Sprintf("localhost:%d", port), false)
		if conn != nil {
			conn.Close()
			break
		}

		time.Sleep(time.Second)
	}
}
