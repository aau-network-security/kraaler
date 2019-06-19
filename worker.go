package kraaler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	ui "github.com/gizak/termui"
	"github.com/gizak/termui/widgets"
	"github.com/google/uuid"
	"github.com/mafredri/cdp"
	"github.com/mafredri/cdp/devtool"
	"github.com/mafredri/cdp/protocol/network"
	"github.com/mafredri/cdp/protocol/page"
	"github.com/mafredri/cdp/protocol/target"
	"github.com/mafredri/cdp/rpcc"
	"github.com/mafredri/cdp/session"
	"github.com/patrickmn/go-cache"
	"github.com/raff/godet"
	"go.uber.org/zap"
)

const (
	CHROME_REQ_WILL_BE_SENT = "Network.requestWillBeSent"
	CHROME_RESP_RECEIVED    = "Network.responseReceived"
	CHROME_LOADING_FAILED   = "Network.loadingFailed"
	CHROME_LOADING_FINISHED = "Network.loadingFinished"
	CUSTOM_GOT_BODY         = "Custom.body"
)

var (
	ErrFuncTimeout = errors.New("timeout")
	ErrNameServer  = errors.New("unable to get name servers")
	ErrDockerConn  = errors.New("docker connection not responding")
	ErrTimeoutDOM  = errors.New("timeout loading document object model")
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
	container *docker.Container
	endpoint  string
	killC     chan struct{}
	hostInfo  *cache.Cache
	logger    *zap.SugaredLogger

	rpccConn       *rpcc.Conn
	cdpClient      *cdp.Client
	sessionManager *session.Manager

	conf WorkerConfig
}

type WorkerConfig struct {
	Queue        <-chan CrawlRequest
	Responses    chan<- Page
	DockerClient *docker.Client
	UseInstance  string
	Resolution   *Resolution
	LoadTimeout  *time.Duration
	Logger       *zap.SugaredLogger
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

	var logger *zap.SugaredLogger
	if conf.Logger != nil {
		logger = conf.Logger.With(zap.String("worker_id", id))
	}

	w := &Worker{
		id:       id,
		logger:   logger,
		killC:    make(chan struct{}),
		conf:     conf,
		endpoint: conf.UseInstance,
		hostInfo: cache.New(2*time.Minute, 30*time.Second),
	}

	if w.endpoint == "" {
		c, err := w.createContainer()
		if err != nil {
			return nil, err
		}
		w.container = c
	}

	return w, nil
}

func (w *Worker) Run() {
	queue, results := w.conf.Queue, w.conf.Responses
	errCheck := func(errs ...error) func(error) bool {
		return func(err error) bool {
			for _, e := range errs {
				if err == e {
					return true
				}
			}
			return false
		}
	}

	fetch := func(req CrawlRequest) Page {
		errForReset := errCheck(context.DeadlineExceeded, ErrDockerConn)

		for {
			ctx := context.Background()
			if w.conf.Logger != nil {
				ctx = context.WithValue(ctx, CTXLOGGER{}, w.conf.Logger)
			}
			ctx, cancel := context.WithTimeout(ctx, 20*time.Second)

			resp := w.fetch(ctx, req)
			cancel()

			if err := resp.Error; errForReset(err) {
				w.removeContainer(w.container)
				var err error

				w.container, err = w.createContainer()
				for err != nil {
					w.container, err = w.createContainer()
				}

				continue
			}

			return resp
		}
	}

	w.logger.Infow("worker_running")

	for {
		select {
		case <-w.killC:
			return

		case req := <-queue:
			resp := fetch(req)
			results <- resp

		}
	}
}

func (w *Worker) getHostInfo(domain string) Host {
	if h, ok := w.hostInfo.Get(domain); ok {
		if host, ok := h.(Host); ok {
			return host
		}
	}

	host, _ := GetHostInfo(Domain(domain))
	w.hostInfo.Set(domain, host, cache.DefaultExpiration)
	return host
}

func (w *Worker) createContainer() (*docker.Container, error) {
	port := GetAvailablePort()
	w.endpoint = fmt.Sprintf("http://127.0.0.1:%d", port)

	img := "chromedp/headless-shell"
	var swap int64 = 0
	opts := docker.CreateContainerOptions{
		Name: fmt.Sprintf("kraaler-worker-%s", w.id),
		Config: &docker.Config{
			Image: img,
			Cmd:   []string{fmt.Sprintf("--window-size=%s", w.conf.Resolution), "--no-sandbox", "--disable-gpu"},
		},
		HostConfig: &docker.HostConfig{
			MemorySwap:       0,
			MemorySwappiness: swap,
			Memory:           768 * 1024 * 1024,
			CPUPeriod:        100000,
			CPUQuota:         100000, // one core
			DNS:              []string{"1.1.1.1"},
			PortBindings: map[docker.Port][]docker.PortBinding{
				docker.Port("9222/tcp"): {{
					HostIP:   "127.0.0.1",
					HostPort: fmt.Sprintf("%d", port),
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

	stop := func(err error) (*docker.Container, error) {
		w.removeContainer(c)
		return nil, err
	}

	if err := w.conf.DockerClient.StartContainer(c.ID, nil); err != nil {
		return stop(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := WaitForEndpoint(ctx, w.endpoint); err != nil {
		return stop(err)
	}

	return c, nil
}

func (w *Worker) removeContainer(c *docker.Container) error {
	if c == nil {
		return nil
	}

	w.conf.DockerClient.StopContainer(
		c.ID,
		1,
	)

	return w.conf.DockerClient.RemoveContainer(
		docker.RemoveContainerOptions{
			ID: c.ID,
		},
	)
}

type ChromeEventParam struct {
	event  string
	params map[string]interface{}
}

type Causer interface {
	Cause() error
}

func (w *Worker) Client(ctx context.Context) (*cdp.Client, func() error, error) {
	handleErr := func(err error) (*cdp.Client, func() error, error) {
		if strings.HasSuffix(err.Error(), "rpcc: the connection is closing") {
			w.rpccConn.Close()
			w.rpccConn = nil

			w.cdpClient = nil

			w.sessionManager.Close()
			w.sessionManager = nil

			return nil, nil, rpcc.ErrConnClosing
		}

		return nil, nil, err
	}

	if w.rpccConn == nil {
		bver, err := devtool.New(w.endpoint).Version(ctx)
		if err != nil {
			return handleErr(err)
		}
		bconn, err := rpcc.DialContext(ctx, bver.WebSocketDebuggerURL)
		if err != nil {
			return handleErr(err)
		}

		w.rpccConn = bconn
	}

	if w.cdpClient == nil {
		w.cdpClient = cdp.NewClient(w.rpccConn)
	}

	if w.sessionManager == nil {
		sess, err := session.NewManager(w.cdpClient)
		if err != nil {
			return handleErr(err)
		}

		w.sessionManager = sess
	}

	createCtx, err := w.cdpClient.Target.CreateBrowserContext(ctx)
	if err != nil {
		return handleErr(err)
	}

	createTargetArgs := target.NewCreateTargetArgs("about:blank").
		SetBrowserContextID(createCtx.BrowserContextID)
	createTarget, err := w.cdpClient.Target.CreateTarget(ctx, createTargetArgs)
	if err != nil {
		return handleErr(err)
	}

	conn, err := w.sessionManager.Dial(ctx, createTarget.TargetID)
	if err != nil {
		return handleErr(err)
	}

	c := cdp.NewClient(conn)
	closer := func() error {
		if err := conn.Close(); err != nil {
			return err
		}

		closeReply, err := w.cdpClient.Target.CloseTarget(ctx, target.NewCloseTargetArgs(createTarget.TargetID))
		if err != nil {
			return err
		}
		if !closeReply.Success {
			return errors.New("could not close target: " + string(createTarget.TargetID))
		}

		err = w.cdpClient.Target.DisposeBrowserContext(ctx, target.NewDisposeBrowserContextArgs(createCtx.BrowserContextID))
		if err != nil {
			return err
		}

		return nil
	}

	return c, closer, nil
}

func retrieveConsole(conn *godet.RemoteDebugger) ([]string, func()) {
	var console []string
	var m sync.Mutex
	conn.CallbackEvent("Runtime.consoleAPICalled",
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

			m.Lock()
			console = append(console, logMsg[1:])
			m.Unlock()
		}))

	conn.RuntimeEvents(true)

	return console, func() {
		conn.RuntimeEvents(false)
		conn.CallbackEvent("Runtime.consoleAPICalled", nil)
		m.Lock()
	}
}

func retrieveEvents(conn *godet.RemoteDebugger) (<-chan time.Time, map[string][]ChromeEventParam, func()) {
	raw := map[string][]ChromeEventParam{}
	var m sync.Mutex

	for _, e := range []string{
		CHROME_REQ_WILL_BE_SENT,
		CHROME_RESP_RECEIVED,
		CHROME_LOADING_FAILED,
	} {
		func(e string) {
			conn.CallbackEvent(e, func(params godet.Params) {
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

	conn.CallbackEvent(CHROME_LOADING_FINISHED, func(params godet.Params) {
		id, ok := params["requestId"].(string)
		if !ok {
			return
		}

		body, err := conn.GetResponseBody(id)
		if err != nil {
			return
		}

		params = map[string]interface{}{
			"requestId": id,
			"body":      body,
			"sha256":    fmt.Sprintf("%x", sha256.Sum256(body)),
		}

		m.Lock()
		eps := raw[id]
		raw[id] = append(eps, ChromeEventParam{
			event:  CUSTOM_GOT_BODY,
			params: params,
		})
		m.Unlock()
	})

	frameLoad := make(chan time.Time)
	conn.CallbackEvent("Page.frameStoppedLoading", func(params godet.Params) {
		select {
		case frameLoad <- time.Now():
		default:
		}
	})

	conn.NetworkEvents(true)
	conn.PageEvents(true)

	return frameLoad, raw, func() {
		conn.NetworkEvents(false)
		conn.PageEvents(false)
		for _, e := range []string{
			"Page.frameStoppedLoading",
			CHROME_REQ_WILL_BE_SENT,
			CHROME_RESP_RECEIVED,
			CHROME_LOADING_FAILED,
			CHROME_LOADING_FINISHED,
		} {
			conn.CallbackEvent(e, nil)
		}
		close(frameLoad)
		m.Lock()
	}
}

func (w *Worker) fetch(ctx context.Context, req CrawlRequest) Page {
	urlstr := req.Url.String()
	w.logger.Infow("worker_fetch_start", "url", urlstr)
	defer func() {
		w.logger.Infow("worker_fetch_stop", "url", urlstr)
	}()

	result := Page{
		InitialURL:    req.Url,
		Resolution:    w.conf.Resolution.String(),
		InitiatedTime: time.Now(),
	}

	replyErr := func(err error) Page {
		if cdp.ErrorCause(err) == context.DeadlineExceeded {
			if strings.HasPrefix(err.Error(), "cdp.Page:") {
				result.Error = ErrTimeoutDOM
				return result
			}

			result.Error = context.DeadlineExceeded
		}

		if strings.HasPrefix(err.Error(), "could not resolve") {
			result.Error = ErrDockerConn
		}

		if result.Error == nil {
			result.Error = err
		}

		w.logger.Infow("worker_fetch_error", "error", result.Error.Error())
		return result
	}

	c, clientClose, err := w.Client(ctx)
	if err != nil {
		if err == rpcc.ErrConnClosing {
			c, clientClose, err = w.Client(ctx)
			if err != nil {
				return replyErr(err)
			}
		} else {
			return replyErr(err)
		}
	}
	defer func() {
		if err := clientClose(); err != nil {
			w.removeContainer(w.container)
			c, err := w.createContainer()
			if err != nil {
				return
			}
			w.container = c
		}
	}()

	_, err = c.Page.Navigate(ctx, page.NewNavigateArgs("about:blank"))
	if err != nil {
		return replyErr(err)
	}

	dom, err := c.Page.DOMContentEventFired(ctx)
	if err != nil {
		return replyErr(err)
	}
	defer dom.Close()

	readRequests := requestsReader(ctx, c.Network)
	readResponses := responsesReader(ctx, c.Network)
	readRequestErrors := requestErrorsReader(ctx, c.Network)
	readBodies := responseBodyReader(ctx, c.Network)
	readConsole := consoleReader(ctx, c.Runtime)

	if err = c.Page.Enable(ctx); err != nil {
		return replyErr(err)
	}

	if err = c.Network.Enable(ctx, nil); err != nil {
		return replyErr(err)
	}

	if err = c.Runtime.Enable(ctx); err != nil {
		return replyErr(err)
	}

	result.NavigateTime = time.Now()
	_, err = c.Page.Navigate(ctx, page.NewNavigateArgs(req.Url.String()))
	if err != nil {
		return replyErr(err)
	}

	if _, err := dom.Recv(); err != nil {
		return replyErr(err)
	}
	result.LoadedTime = time.Now()
	screenshotC := w.captureScreenshots(ctx, c.Page, req.Screenshots...)

loop:
	for {
		select {
		case <-ctx.Done():
			return replyErr(ctx.Err())
		case screens := <-screenshotC:
			result.Screenshots = screens
			result.TerminatedTime = time.Now()
			break loop
		}
	}

	requests, err := readRequests()
	if err != nil {
		return replyErr(err)
	}

	responses, err := readResponses()
	if err != nil {
		return replyErr(err)
	}

	rerrs, err := readRequestErrors()
	if err != nil {
		return replyErr(err)
	}

	bodies, err := readBodies()
	if err != nil {
		return replyErr(err)
	}

	result.Actions = ActionsFromEvents(&BrowserEvents{
		requests:  requests,
		responses: responses,
		errors:    rerrs,
		bodies:    bodies,
	})

	for _, a := range result.Actions {
		u, err := url.Parse(a.Request.URL)
		if err != nil {
			continue
		}

		a.Host = w.getHostInfo(u.Host)
	}
	if len(result.Actions) > 0 {
		if err := result.Actions[0].Error; err != nil {
			result.Error = fmt.Errorf(*err)
		}

		if body := result.Actions[0].Body; body != nil {
			result.DocumentURLs = LinksFromBodies(req.Url, body)
		}
	}

	console, err := readConsole()
	if err != nil {
		return replyErr(err)
	}
	result.Console = console

	return result
}

func requestsReader(ctx context.Context, net cdp.Network) func() ([]*network.RequestWillBeSentReply, error) {
	stop := make(chan struct{})
	var requests []*network.RequestWillBeSentReply
	var replyErr error

	go func() {
		reqs, err := net.RequestWillBeSent(ctx)
		if err != nil {
			replyErr = err
			return
		}
		defer reqs.Close()

		for {
			req, err := reqs.Recv()
			if err != nil {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			default:
				requests = append(requests, req)
			}
		}
	}()

	return func() ([]*network.RequestWillBeSentReply, error) {
		close(stop)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if replyErr != nil {
			return nil, replyErr
		}

		return requests, nil
	}
}

func responsesReader(ctx context.Context, net cdp.Network) func() ([]*network.ResponseReceivedReply, error) {
	stop := make(chan struct{})
	var responses []*network.ResponseReceivedReply
	var replyErr error

	go func() {
		resps, err := net.ResponseReceived(ctx)
		if err != nil {
			replyErr = err
			return
		}
		defer resps.Close()

		for {
			resp, err := resps.Recv()
			if err != nil {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			default:
				responses = append(responses, resp)
			}
		}
	}()

	return func() ([]*network.ResponseReceivedReply, error) {
		close(stop)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if replyErr != nil {
			return nil, replyErr
		}

		return responses, nil
	}
}

func requestErrorsReader(ctx context.Context, net cdp.Network) func() ([]*network.LoadingFailedReply, error) {
	stop := make(chan struct{})
	var errors []*network.LoadingFailedReply
	var replyErr error

	go func() {
		respErrs, err := net.LoadingFailed(ctx)
		if err != nil {
			replyErr = err
			return
		}
		defer respErrs.Close()

		for {
			respErr, err := respErrs.Recv()
			if err != nil {
				return
			}

			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			default:
				errors = append(errors, respErr)
			}
		}
	}()

	return func() ([]*network.LoadingFailedReply, error) {
		close(stop)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if replyErr != nil {
			return nil, replyErr
		}

		return errors, nil
	}
}

type ResponseBody struct {
	RequestID      network.RequestID
	Body           []byte
	Links          []*url.URL
	ChecksumSha256 string
}

func responseBodyReader(ctx context.Context, net cdp.Network) func() ([]*ResponseBody, error) {
	stop := make(chan struct{})
	var bodies []*ResponseBody
	var replyErr error

	go func() {
		loadings, err := net.LoadingFinished(ctx)
		if err != nil {
			replyErr = err
			return
		}
		defer loadings.Close()

		for {
			req, err := loadings.Recv()
			if err != nil {
				return
			}

			bodyReply, err := net.GetResponseBody(ctx, &network.GetResponseBodyArgs{req.RequestID})
			if err != nil {
				return
			}

			var body []byte
			if bodyReply.Base64Encoded {
				body, err = base64.StdEncoding.DecodeString(bodyReply.Body)
				if err != nil {
					body = []byte(bodyReply.Body)
				}
			} else {
				body = []byte(bodyReply.Body)
			}

			checksum := fmt.Sprintf("%x", sha256.Sum256(body))

			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			default:
				bodies = append(bodies, &ResponseBody{
					RequestID:      req.RequestID,
					Body:           body,
					ChecksumSha256: checksum,
				})
			}
		}
	}()

	return func() ([]*ResponseBody, error) {
		close(stop)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if replyErr != nil {
			return nil, replyErr
		}

		return bodies, nil
	}
}

type JavaScriptConsole struct {
	Msg      string
	Line     int
	Column   int
	Function string
	URL      string
}

func consoleReader(ctx context.Context, runt cdp.Runtime) func() ([]*JavaScriptConsole, error) {
	stop := make(chan struct{})
	var console []*JavaScriptConsole
	var replyErr error

	go func() {
		messages, err := runt.ConsoleAPICalled(ctx)
		if err != nil {
			return
		}
		defer messages.Close()

		for {
			msg, err := messages.Recv()
			if err != nil {
				return
			}

			if msg.Type != "log" {
				continue
			}

			var txt string
			for _, o := range msg.Args {
				txt += fmt.Sprintf("%s ", o.Value)
			}
			txt = txt[0 : len(txt)-1]

			cmsg := &JavaScriptConsole{
				Msg: txt,
			}

			if st := msg.StackTrace; st != nil && len(st.CallFrames) > 0 {
				cf := st.CallFrames[0]
				cmsg.Line = cf.LineNumber
				cmsg.Column = cf.ColumnNumber
				cmsg.Function = cf.FunctionName
				cmsg.URL = cf.URL
			}

			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			default:
				console = append(console, cmsg)
			}
		}
	}()

	return func() ([]*JavaScriptConsole, error) {
		close(stop)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if replyErr != nil {
			return nil, replyErr
		}

		return console, nil
	}
}

func (w *Worker) captureScreenshots(ctx context.Context, pg cdp.Page, durations ...time.Duration) <-chan []*BrowserScreenshot {
	out := make(chan []*BrowserScreenshot)

	go func() {
		defer close(out)

		var wg sync.WaitGroup
		var m sync.Mutex
		var screenshots []*BrowserScreenshot
		for _, dur := range durations {
			wg.Add(1)

			go func(dur time.Duration) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					return
				case <-time.After(dur):
				}

				taken := time.Now()
				encoded, err := pg.CaptureScreenshot(ctx, page.NewCaptureScreenshotArgs().SetFormat("png"))
				if err != nil {
					return
				}

				var screenshot []byte
				if _, err := base64.StdEncoding.Decode(screenshot, encoded.Data); err != nil {
					screenshot = encoded.Data
				}

				m.Lock()
				screenshots = append(screenshots, &BrowserScreenshot{
					Screenshot: screenshot,
					Taken:      taken,
					Resolution: *w.conf.Resolution,
					Kind:       "png",
				})
				m.Unlock()

			}(dur)
		}

		wg.Wait()

		out <- screenshots
	}()

	return out
}

func (w *Worker) Close() {
	close(w.killC)

	if w.rpccConn != nil {
		w.rpccConn.Close()
	}

	if w.sessionManager != nil {
		w.sessionManager.Close()
	}

	if w.container != nil {
		w.removeContainer(w.container)
	}
}

type BrowserEvents struct {
	requests  []*network.RequestWillBeSentReply
	responses []*network.ResponseReceivedReply
	errors    []*network.LoadingFailedReply
	bodies    []*ResponseBody
}

func ActionsFromEvents(events *BrowserEvents) []*CrawlAction {
	requests := map[network.RequestID]*CrawlAction{}

	var actions []*CrawlAction
	for _, sent := range events.requests {
		u, err := url.Parse(sent.Request.URL)
		if err != nil {
			continue
		}

		if u.Scheme == "data" {
			continue
		}

		ca := CrawlAction{
			Initiator: Initiator{
				Kind: sent.Initiator.Type,
			},
			Request: sent.Request,
		}

		if parent, ok := requests[network.RequestID(sent.LoaderID)]; ok {
			parent.Response = sent.RedirectResponse
			ca.Parent = parent
		}

		requests[sent.RequestID] = &ca
		actions = append(actions, &ca)
	}

	for _, recv := range events.responses {
		req, ok := requests[recv.RequestID]
		if !ok {
			continue
		}

		req.Response = &recv.Response
	}

	for _, err := range events.errors {
		req, ok := requests[err.RequestID]
		if !ok {
			continue
		}

		if req.Error == nil {
			req.Error = &err.ErrorText
		}
	}

	for _, body := range events.bodies {
		req, ok := requests[body.RequestID]
		if !ok {
			continue
		}

		req.Body = body
	}

	for _, a := range actions {
		if a.Parent != nil && a.Parent.Response != nil {
			sc := a.Parent.Response.Status
			if sc >= 300 && sc < 400 {
				a.Initiator.Kind = "redirect"
			}
			continue
		}

		a.Initiator.Kind = "user"
	}

	return actions
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

func LinksFromBodies(host *url.URL, bodies ...*ResponseBody) []*url.URL {
	var links []*url.URL
	// for _, b := range bodies {
	// 	l, _ := RetrieveLinks(host, b.Body)
	// 	links = append(links, l...)
	// }

	return links
}

func WaitForEndpoint(ctx context.Context, endpoint string) error {
	connect := func() error {
		devt := devtool.New(endpoint)
		pt, err := devt.Get(ctx, devtool.Page)
		if err != nil {
			pt, err = devt.Create(ctx)
			if err != nil {
				return err
			}
		}

		conn, err := rpcc.DialContext(ctx, pt.WebSocketDebuggerURL)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}

loop:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
			if err := connect(); err != nil {
				for _, s := range []string{"connection reset", "connection refused"} {
					if strings.Contains(err.Error(), s) {
						continue loop
					}
				}

				fmt.Println("wait err", err)

				return err
			}
		}

		return nil

	}
}

type URLStore interface {
	Sample() (*url.URL, error)
	Add(urls ...*url.URL) (int, error)
	Visit(u *url.URL, t time.Time) error
	Size() int
}

type PageStore interface {
	SaveSession(Page) error
}

type SavedSession struct {
	Error         error
	Session       *Page
	CrawlDuration time.Duration
	StoreDuration time.Duration
}

func (ss *SavedSession) String() string {
	state := "✔"
	if ss.Session.Error != nil {
		state = "✘ "
	}

	err := ""
	if ss.Session.Error != nil {
		err = fmt.Sprintf("(error: %s)", ss.Session.Error)
	}

	str := fmt.Sprintf("%s %-8s%s%s (duration: %v) %s",
		state,
		"["+ss.Session.InitialURL.Scheme+"]",
		ss.Session.InitialURL.Host,
		ss.Session.InitialURL.Path,
		ss.CrawlDuration,
		err,
	)

	return str
}

type PageHandleFunc func(Page)
type PageMiddleware func(PageHandleFunc) PageHandleFunc

type URLHandleFunc func(*url.URL)
type URLMiddleware func(URLHandleFunc) URLHandleFunc

func SkipURLsMiddleware(URLHandleFunc) URLHandleFunc {
	return func(*url.URL) {
		return
	}
}

type WorkerControllerConfig struct {
	DockerClient   *docker.Client
	URLStore       URLStore
	PageStore      PageStore
	Logger         *zap.SugaredLogger
	PageMiddleware []PageMiddleware
	URLMiddleware  []URLMiddleware
}

type WorkerController struct {
	m              sync.Mutex
	ctx            context.Context
	conf           WorkerControllerConfig
	workers        []*Worker
	recentSessions []*SavedSession
	ready          chan bool
	tasks          chan CrawlRequest
	responses      chan Page
	cancel         func()
}

func NewWorkerController(ctx context.Context, conf WorkerControllerConfig) (*WorkerController, error) {
	if conf.DockerClient == nil {
		dclient, err := docker.NewClient("unix:///var/run/docker.sock")
		if err != nil {
			return nil, err
		}
		conf.DockerClient = dclient
	}

	_, cancel := context.WithCancel(ctx)

	tasks := make(chan CrawlRequest)
	responses := make(chan Page)
	ready := make(chan bool, 1)

	wc := &WorkerController{
		ctx:       ctx,
		conf:      conf,
		tasks:     tasks,
		responses: responses,
		cancel:    cancel,
		ready:     ready,
	}

	go wc.startQueue()
	go func() {
		wc.recentSessions = make([]*SavedSession, 50)
		for {
			select {
			case sess := <-responses:
				t := time.Now()
				err := conf.PageStore.SaveSession(sess)
				conf.URLStore.Visit(sess.InitialURL, time.Now())
				conf.URLStore.Add(sess.DocumentURLs...)
				wc.recentSessions = append(wc.recentSessions[1:len(wc.recentSessions)],
					&SavedSession{
						Session:       &sess,
						Error:         err,
						StoreDuration: time.Since(t),
						CrawlDuration: time.Since(sess.InitiatedTime),
					})
				ready <- true
			case <-ctx.Done():
				return
			}
		}

	}()

	return wc, nil
}

func (wc *WorkerController) startQueue() {
	for {
		var u *url.URL
		var err error

		select {
		case <-wc.ctx.Done():
			return
		case <-wc.ready:
			u, err = wc.conf.URLStore.Sample()
			if err != nil {
				select {
				case <-time.After(500 * time.Millisecond):
					continue
				case <-wc.ctx.Done():
					return
				}
			}
		}

		select {
		case <-wc.ctx.Done():
			return
		case wc.tasks <- CrawlRequest{Url: u, Screenshots: []time.Duration{time.Second}}:
		}
	}
}

func (wc *WorkerController) AddWorker() error {
	wc.m.Lock()
	defer wc.m.Unlock()

	w, err := NewWorker(WorkerConfig{
		Queue:        wc.tasks,
		Responses:    wc.responses,
		DockerClient: wc.conf.DockerClient,
		Logger:       wc.conf.Logger,
	})
	if err != nil {
		return err
	}

	go w.Run()

	wc.workers = append(wc.workers, w)
	wc.ready <- true

	return nil
}

func (wc *WorkerController) FactWidget() ui.Drawable {
	fw := widgets.NewList()
	update := func() {
		fw.Rows = []string{
			fmt.Sprintf("Known URLs: %d", wc.conf.URLStore.Size()),
		}
	}

	go func() {
		update()

		ticker := time.NewTicker(2 * time.Second)
		for range ticker.C {
			update()
		}
	}()

	fw.Title = "Facts"
	fw.BorderStyle = ui.NewStyle(ui.ColorGreen)

	return fw
}

func (wc *WorkerController) FactRecentSessions() ui.Drawable {
	rs := widgets.NewList()
	update := func() {
		var rows []string

		for i := len(wc.recentSessions) - 1; i >= 0; i-- {
			s := wc.recentSessions[i]
			if s != nil {
				rows = append(rows, s.String())
			}
		}

		rs.Rows = rows
	}

	go func() {
		update()

		ticker := time.NewTicker(2 * time.Second)
		for {
			select {
			case <-wc.ctx.Done():
				return
			case <-ticker.C:
				update()
			}
		}
	}()

	rs.Title = "Fetched (Recent)"
	rs.BorderStyle = ui.NewStyle(ui.ColorBlue)

	return rs
}

func (wc *WorkerController) Close() {
	wc.cancel()
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
		return ErrFuncTimeout
	}
}

func errorFuncWithContext(ctx context.Context, f func() error) <-chan error {
	errc := make(chan error)

	go func() {
		defer close(errc)
		errc <- f()
	}()

	return errc
}

func GetHostInfo(domain Domain) (Host, error) {
	h := Host{
		Domain: domain,
	}
	replyErr := func(err error) (Host, error) {
		return h, err
	}

	nss, _ := net.LookupNS(string(domain))
	for _, ns := range nss {
		h.NameServers = append(h.NameServers, ns.Host)
	}

	ips, err := net.LookupIP(string(domain))
	if err != nil {
		return replyErr(err)
	}

	if len(ips) == 0 {
		return replyErr(nil)
	}

	h.IPAddr = ips[0].String()

	return h, nil
}
