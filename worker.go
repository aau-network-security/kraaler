package kraaler

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/google/uuid"
	"github.com/raff/godet"
)

const (
	CHROME_REQ_WILL_BE_SENT = "Network.requestWillBeSent"
	CHROME_RESP_RECEIVED    = "Network.responseReceived"
	CHROME_LOADING_FAILED   = "Network.loadingFailed"
	CUSTOM_GOT_BODY         = "Custom.body"
)

var (
	FuncTimeoutErr = errors.New("timeout")
)

var DefaultResolution = &Resolution{
	Width:  1366,
	Height: 768,
}

type NoParamErr struct{ param string }

func (npe *NoParamErr) Error() string { return fmt.Sprintf("unable to get param: %s", npe.param) }

type NotOfTypeErr struct{ value, kind string }

func (note *NotOfTypeErr) Error() string {
	return fmt.Sprintf("value (\"%s\") is not of type: %s", note.value, note.kind)
}

type Worker struct {
	id        string
	port      uint
	container *docker.Container
	rdb       *godet.RemoteDebugger
	kill      chan struct{}

	conf WorkerConfig
}

type WorkerConfig struct {
	Queue        <-chan CrawlRequest
	Responses    chan<- CrawlSession
	DockerClient *docker.Client
	UseInstance  string
	Resolution   *Resolution
	LoadTimeout  *time.Duration
}

func NewWorker(conf WorkerConfig) (*Worker, error) {
	werr := func(err error) (*Worker, error) { return nil, err }

	if conf.Queue == nil {
		return werr(fmt.Errorf("queue chan is nil"))
	}

	if conf.Responses == nil {
		return werr(fmt.Errorf("response chan is nil"))
	}

	if conf.DockerClient == nil && conf.UseInstance == "" {
		return werr(fmt.Errorf("docker client and existing instance cannot be nil at the same time"))
	}

	if conf.Resolution == nil {
		conf.Resolution = DefaultResolution
	}

	if conf.LoadTimeout == nil {
		timeout := 15 * time.Second
		conf.LoadTimeout = &timeout
	}

	id := uuid.New().String()[0:8]
	w := &Worker{
		id:   id,
		conf: conf,
	}

	endpoint := conf.UseInstance
	if conf.UseInstance == "" {
		c, err := w.createContainer()
		if err != nil {
			return nil, err
		}
		w.container = c

		endpoint = fmt.Sprintf("localhost:%d", w.port)
	}

	WaitForInstance(endpoint, 2*time.Minute)

	rdb, err := godet.Connect(endpoint, false)
	if err != nil {
		return nil, err
	}
	if err := rdb.SetCacheDisabled(true); err != nil {
		return nil, err
	}
	w.rdb = rdb

	go w.listen(conf.Queue, conf.Responses)

	return w, nil
}

func (w *Worker) listen(queue <-chan CrawlRequest, results chan<- CrawlSession) {
	w.kill = make(chan struct{})

	for {
		select {
		case <-w.kill:
			return

		case req := <-queue:
			resp := w.fetch(req)
			results <- resp
		}
	}
}

func (w *Worker) createContainer() (*docker.Container, error) {
	if w.port == 0 {
		port := GetAvailablePort()
		w.port = port
	}

	img := "chromedp/headless-shell"
	opts := docker.CreateContainerOptions{
		Name: fmt.Sprintf("kraaler-worker-%s", w.id),
		Config: &docker.Config{
			Image: img,
			Cmd:   []string{fmt.Sprintf("--window-size=%s", w.conf.Resolution), "--no-sandbox", "--disable-gpu"},
		},
		HostConfig: &docker.HostConfig{
			MemorySwap:       0,
			MemorySwappiness: 0,
			Memory:           756 * 1024 * 1024,
			PortBindings: map[docker.Port][]docker.PortBinding{
				docker.Port("9222/tcp"): {{
					HostIP:   "127.0.0.1",
					HostPort: fmt.Sprintf("%d", w.port),
				}},
			},
		},
	}

	c, err := w.conf.DockerClient.CreateContainer(opts)
	if err != nil {
		if err.Error() != "no such image" {
			return nil, err
		}

		if err := PullImage(w.conf.DockerClient, img); err != nil {
			return nil, err
		}

		c, err = w.conf.DockerClient.CreateContainer(opts)
		if err != nil {
			return nil, err
		}
	}

	if err := w.conf.DockerClient.StartContainer(c.ID, nil); err != nil {
		w.conf.DockerClient.RemoveContainer(docker.RemoveContainerOptions{ID: c.ID})
		return nil, err
	}

	return c, nil
}

type ChromeEventParam struct {
	event  string
	params map[string]interface{}
}

func (w *Worker) fetch(req CrawlRequest) CrawlSession {
	stop := make(chan time.Time)

	w.rdb.CallbackEvent("Page.frameStoppedLoading", func(params godet.Params) {
		stop <- time.Now()
	})

	var console []string
	w.rdb.CallbackEvent("Runtime.consoleAPICalled",
		godet.ConsoleAPICallback(func(items []interface{}) {
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

			console = append(console, logMsg[1:])
		}))

	raw := map[string][]ChromeEventParam{}
	var m sync.Mutex

	for _, e := range []string{
		CHROME_REQ_WILL_BE_SENT,
		CHROME_RESP_RECEIVED,
		CHROME_LOADING_FAILED,
	} {
		func(e string) {
			w.rdb.CallbackEvent(e, func(params godet.Params) {
				id, ok := params["requestId"].(string)
				if !ok {
					return
				}

				m.Lock()
				eps := raw[id]
				raw[id] = append(eps, ChromeEventParam{e, params})
				m.Unlock()
			})
		}(e)
	}

	tab, err := w.rdb.NewTab("about:blank")
	if err != nil {
		return CrawlSession{Error: err}
	}

	w.rdb.NetworkEvents(true)
	w.rdb.RuntimeEvents(true)
	w.rdb.PageEvents(true)

	clear := func() {
		w.rdb.ClearBrowserCookies()
		w.rdb.CloseTab(tab)
	}
	defer clear()

	if err := w.rdb.ActivateTab(tab); err != nil {
		return CrawlSession{Error: err}
	}

	time.Sleep(200 * time.Millisecond)

	starttime := time.Now()
	if _, err := w.rdb.Navigate(req.Url.String()); err != nil {
		return CrawlSession{Error: err}
	}
	var loadedTime time.Time
	select {
	case t := <-stop:
		loadedTime = t
	case <-time.After(*w.conf.LoadTimeout):
		return CrawlSession{Error: fmt.Errorf("Frame load timeout")}
	}

	screen := make(chan *BrowserScreenshot, 1)

	var wg sync.WaitGroup
	capture := func(d time.Duration) {
		time.Sleep(d)
		ss, err := w.CaptureScreenshot()
		if err != nil {
			log.Printf("unable to capture screenshot: %s", err)
		}

		screen <- ss
		wg.Done()
	}

	for _, timing := range req.Screenshots {
		wg.Add(1)
		capture(timing)
	}

	m.Lock()
	for id, eps := range raw {
		body, err := w.rdb.GetResponseBody(id)
		if err != nil {
			fmt.Println("body error: ", err)
			continue
		}

		params := map[string]interface{}{
			"requestId": id,
			"body":      body,
			"sha256":    fmt.Sprintf("%x", sha256.Sum256(body)),
		}

		raw[id] = append(eps, ChromeEventParam{
			event:  CUSTOM_GOT_BODY,
			params: params,
		})
	}
	m.Unlock()

	wg.Wait()
	var capturedScreenshots []*BrowserScreenshot
	for i := 0; i < len(req.Screenshots); i++ {
		capturedScreenshots = append(capturedScreenshots, <-screen)
	}

	terminateTime := time.Now()

	return CrawlSession{
		InitialURL:     req.Url.String(),
		Resolution:     w.conf.Resolution.String(),
		Actions:        ActionsFromEvents(raw),
		Console:        console,
		Screenshots:    capturedScreenshots,
		StartTime:      starttime,
		LoadedTime:     loadedTime,
		TerminatedTime: terminateTime,
	}
}

func (w *Worker) CaptureScreenshot() (*BrowserScreenshot, error) {
	taken := time.Now()
	bytes, err := w.rdb.CaptureScreenshot("png", 0, true)
	if err != nil {
		return nil, err
	}

	return &BrowserScreenshot{
		Screenshot: bytes,
		Taken:      taken,
	}, nil
}

func (w *Worker) Close() {
	w.kill <- struct{}{}

	if w.rdb != nil {
		w.rdb.Close()
	}

	if w.container != nil {
		w.conf.DockerClient.RemoveContainer(docker.RemoveContainerOptions{
			ID:    w.container.ID,
			Force: true,
		})
	}
}

func ActionsFromEvents(logs map[string][]ChromeEventParam) []*CrawlAction {
	requests := map[string]*CrawlAction{}
	requestIsSent := func(params map[string]interface{}, last *CrawlAction) (*CrawlAction, error) {
		_, performedRedirect := params["redirectResponse"].(map[string]interface{})
		if performedRedirect && last != nil {
			if err := last.ReadResponse(params, "redirectResponse"); err != nil {
				return nil, err
			}
		}

		_, ok := params["request"].(map[string]interface{})
		if !ok {
			return nil, nil
		}

		a, err := NewCrawlActionFromParams(params)
		if err != nil {
			return nil, err
		}

		rid, ok := params["requestId"].(string)
		if ok {
			requests[rid] = a
		}

		if id, ok := params["loaderId"].(string); ok {
			if parent, ok := requests[id]; ok && rid != id {
				a.Parent = parent
			}
		}

		if performedRedirect {
			a.Initiator.Kind = "redirect"
		}

		return a, nil
	}

	var sessionActions []*CrawlAction
	for _, eps := range logs {
		var actions []*CrawlAction
		var last *CrawlAction
		for _, ep := range eps {
			switch ep.event {
			case CHROME_REQ_WILL_BE_SENT:
				a, err := requestIsSent(ep.params, last)
				if err != nil {
					log.Printf("error handling \"%s\": %s\n", CHROME_REQ_WILL_BE_SENT, err)
				}

				if a != nil {
					if last != nil {
						a.Parent = last
					}

					actions = append(actions, a)
					last = a
				}

			case CHROME_RESP_RECEIVED:
				id, ok := ep.params["requestId"].(string)
				if !ok {
					continue
				}

				a, ok := requests[id]
				if !ok {
					continue
				}

				err := a.ReadResponse(ep.params, "response")
				if err != nil {
					log.Printf("error handling \"%s\": %s\n", CHROME_RESP_RECEIVED, err)
				}

			case CHROME_LOADING_FAILED:
				err := last.ReadError(ep.params)
				if err != nil {
					log.Printf("error handling \"%s\": %s\n", CHROME_LOADING_FAILED, err)
				}

			case CUSTOM_GOT_BODY:
				id, ok := ep.params["requestId"].(string)
				if !ok {
					continue
				}

				a, ok := requests[id]
				if !ok {
					continue
				}

				if a.Response == nil {
					var resp BrowserResponse
					a.Response = &resp
				}

				a.Response.Body, _ = ep.params["body"].([]byte)
				a.Response.BodyChecksumSha256, _ = ep.params["sha256"].(string)
			}
		}

		sessionActions = append(sessionActions, actions...)
	}

	sort.Slice(sessionActions,
		func(i, j int) bool {
			return sessionActions[i].Timings.StartTime < sessionActions[j].Timings.StartTime
		})

	if len(sessionActions) > 0 {
		sessionActions[0].Initiator.Kind = "user"
	}

	for _, a := range sessionActions {
		j, _ := json.MarshalIndent(a, "", "  ")
		fmt.Println(string(j))
	}

	return sessionActions
}

func ReadStringFromParams(key string, params map[string]interface{}) (string, error) {
	v, ok := params[key]
	if !ok {
		return "", &NoParamErr{key}
	}

	vStr, ok := v.(string)
	if !ok {
		return "", &NotOfTypeErr{key, "string"}
	}

	return vStr, nil
}

func ReadStringSliceFromParams(key string, params map[string]interface{}) ([]string, error) {
	v, ok := params[key]
	if !ok {
		return nil, &NoParamErr{key}
	}

	notArray := func() ([]string, error) {
		return nil, &NotOfTypeErr{key, "[]string"}
	}

	inters, ok := v.([]interface{})
	if !ok {
		return notArray()
	}

	var result []string
	for _, i := range inters {
		str, ok := i.(string)
		if !ok {
			return notArray()
		}

		result = append(result, str)
	}

	return result, nil
}

func ReadFloatFromParams(key string, params map[string]interface{}) (float64, error) {
	v, ok := params[key]
	if !ok {
		return 0, &NoParamErr{key}
	}

	vFloat, ok := v.(float64)
	if !ok {
		return 0, &NotOfTypeErr{key, "float64"}
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
		return nil, &NotOfTypeErr{key, "map[string]interface{}"}
	}

	return vMap, nil
}

func GetAvailablePort() uint {
	l, _ := net.Listen("tcp", ":0")
	parts := strings.Split(l.Addr().String(), ":")
	l.Close()

	p, _ := strconv.Atoi(parts[len(parts)-1])

	return uint(p)
}

func PullImage(c *docker.Client, img string) error {
	return c.PullImage(docker.PullImageOptions{
		Repository: img,
		Tag:        "latest",
	}, docker.AuthConfiguration{})
}

func WaitForInstance(endpoint string, max time.Duration) {
	t := time.NewTicker(max)
	defer t.Stop()

	for {
		conn, _ := godet.Connect(endpoint, false)
		select {
		case <-t.C:
			return
		default:
			if conn != nil {
				conn.Close()
				return
			}

			time.Sleep(time.Second)
		}

	}
}

type workerController struct {
	m         sync.Mutex
	workers   []*Worker
	dclient   *docker.Client
	us        URLStore
	tasks     chan CrawlRequest
	responses chan CrawlSession
	stop      chan bool
}

func NewWorkerController(us URLStore) (*workerController, error) {
	dclient, err := docker.NewClient("unix:///var/run/docker.sock")
	if err != nil {
		return nil, err
	}

	tasks := make(chan CrawlRequest)
	responses := make(chan CrawlSession)
	stop := make(chan bool)

	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}

			u, err := us.Sample()
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}

			select {
			case <-stop:
				return
			case tasks <- CrawlRequest{Url: u}:
			}
		}
	}()

	return &workerController{
		tasks:     tasks,
		responses: responses,
		us:        us,
		dclient:   dclient,
		stop:      stop,
	}, nil
}

func (wc *workerController) AddWorker() error {
	wc.m.Lock()
	defer wc.m.Unlock()

	w, err := NewWorker(WorkerConfig{
		Queue:        wc.tasks,
		Responses:    wc.responses,
		DockerClient: wc.dclient,
	})
	if err != nil {
		return err
	}
	wc.workers = append(wc.workers, w)

	return nil
}

func (wc *workerController) Close() {
	wc.m.Lock()
	defer wc.m.Unlock()

	wc.stop <- true

	for _, w := range wc.workers {
		w.Close()
	}
}

func timeoutAction(f func() error, d time.Duration) error {
	errc := make(chan error, 1)

	go func() {
		errc <- f()
	}()

	select {
	case err := <-errc:
		return err
	case <-time.After(d):
		return FuncTimeoutErr
	}
}
