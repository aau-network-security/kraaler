package kraaler

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net"
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

var DefaultResolution = &Resolution{
	Width:  1366,
	Height: 768,
}

type NoParamErr struct{ param string }

func (npe *NoParamErr) Error() string { return fmt.Sprintf("unable to get param: %s", npe.param) }

type NotOfTypeErr struct{ kind string }

func (note *NotOfTypeErr) Error() string { return fmt.Sprintf("value is not of type: %s", note.kind) }

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
	Resolution   *Resolution
}

func NewWorker(conf WorkerConfig) (*Worker, error) {
	werr := func(err error) (*Worker, error) { return nil, err }

	if conf.Queue == nil {
		return werr(fmt.Errorf("queue chan is nil"))
	}

	if conf.Responses == nil {
		return werr(fmt.Errorf("response chan is nil"))
	}

	if conf.DockerClient == nil {
		return werr(fmt.Errorf("docker client cannot be nil"))
	}

	if conf.Resolution == nil {
		conf.Resolution = DefaultResolution
	}

	id := uuid.New().String()[0:8]
	w := &Worker{
		id:   id,
		conf: conf,
	}

	c, err := w.createContainer()
	if err != nil {
		return nil, err
	}
	w.container = c

	WaitForPort(w.port)

	rdb, err := godet.Connect(fmt.Sprintf("localhost:%d", w.port), false)
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
			Cmd:   []string{fmt.Sprintf("--window-size=%s", w.conf.Resolution)},
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
	loadedtime := <-stop

	screen := make(chan *BrowserScreenshot, 1)

	var wg sync.WaitGroup
	capture := func(d time.Duration) {
		time.Sleep(3 * time.Second)
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

	for id, eps := range raw {
		body, err := w.rdb.GetResponseBody(id)
		if err != nil {
			fmt.Println("body error: ", err)
			continue
		}

		params := map[string]interface{}{
			"body":   body,
			"sha256": fmt.Sprintf("%x", sha256.Sum256(body)),
		}

		raw[id] = append(eps, ChromeEventParam{
			event:  CUSTOM_GOT_BODY,
			params: params,
		})
	}

	wg.Wait()
	var capturedScreenshots []*BrowserScreenshot
	for i := 0; i < len(req.Screenshots); i++ {
		capturedScreenshots = append(capturedScreenshots, <-screen)
	}

	terminateTime := time.Now()

	return CrawlSession{
		Resolution:     w.conf.Resolution.String(),
		Actions:        ActionsFromEvents(raw),
		Console:        console,
		Screenshots:    capturedScreenshots,
		StartTime:      starttime,
		LoadedTime:     loadedtime,
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

		switch {
		case last == nil:
			a.Initiator = "user"
		case performedRedirect:
			a.Initiator = "redirect"
		default:
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
				if last == nil {
					continue
				}

				err := last.ReadResponse(ep.params, "response")
				if err != nil {
					log.Printf("error handling \"%s\": %s\n", CHROME_RESP_RECEIVED, err)
				}

			case CHROME_LOADING_FAILED:
				err := last.ReadError(ep.params)
				if err != nil {
					log.Printf("error handling \"%s\": %s\n", CHROME_LOADING_FAILED, err)
				}

			case CUSTOM_GOT_BODY:
				if last == nil {
					continue
				}

				last.Response.Body, _ = ep.params["body"].([]byte)
				last.Response.BodyChecksumSha256, _ = ep.params["sha256"].(string)
			}
		}

		sessionActions = append(sessionActions, actions...)
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

func WaitForPort(port uint) {

	endpoint := fmt.Sprintf("localhost:%d", port)
	for {
		conn, err := godet.Connect(endpoint, false)
		if conn != nil {
			conn.Close()
			break
		}

		time.Sleep(time.Second)
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
