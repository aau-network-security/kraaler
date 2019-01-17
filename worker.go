package kraaler

import (
	"fmt"
	"log"
	"net"
	"sort"
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

type BrowserRequest struct {
	ID          string
	LoaderId    string
	DocumentUrl string
	Initiator   string
	Redirect    map[string]interface{}
	StartTime   float64
	EndTime     float64
}

func (br BrowserRequest) String() string {
	return fmt.Sprintf(`ID: %s
  Loader: %s
  DocumentURL: %s
  Initiator: %s
  Redirect: %v
  %f
  %f
`, br.ID, br.LoaderId, br.DocumentUrl, br.Initiator, br.Redirect, br.StartTime, br.EndTime)
}

type BrowserRequests []BrowserRequest

func (s BrowserRequests) Len() int           { return len(s) }
func (s BrowserRequests) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s BrowserRequests) Less(i, j int) bool { return s[i].StartTime < s[j].StartTime }

func (w *Worker) fetch(req *FetchRequest) FetchResponse {
	stop := make(chan time.Time)
	w.rdb.CallbackEvent("Page.frameStoppedLoading", func(params godet.Params) {
		stop <- time.Now()
	})

	requests := map[string]BrowserRequest{}
	w.rdb.CallbackEvent("Network.requestWillBeSent", func(params godet.Params) {
		var br BrowserRequest

		br.ID, _ = params["requestId"].(string)
		br.StartTime, _ = params["timestamp"].(float64)
		br.DocumentUrl, _ = params["documentURL"].(string)
		br.LoaderId, _ = params["loaderId"].(string)
		br.Redirect, _ = params["redirectResponse"].(map[string]interface{})

		initz, _ := params["initiator"].(map[string]interface{})
		br.Initiator = initz["type"].(string)

		// req, _ := params["request"].(map[string]interface{})
		// rawUrl, _ := req["url"].(string)
		// rawFragment, _ := req["urlFragment"].(string)
		// Url, _ := url.Parse(rawUrl + rawFragment)

		requests[br.ID] = br
	})

	w.rdb.CallbackEvent("Network.responseReceived", func(params godet.Params) {
		requestId, _ := params["requestId"].(string)
		ended, _ := params["timestamp"].(float64)

		r := requests[requestId]
		r.EndTime = ended

		requests[requestId] = r
	})

	start := time.Now()
	tab, err := w.rdb.NewTab("about:blank")
	if err != nil {
		return FetchResponse{Error: err}
	}
	w.rdb.PageEvents(true)
	w.rdb.NetworkEvents(true)

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

	if _, err := w.rdb.Navigate(req.Url.String()); err != nil {
		return FetchResponse{Error: err}
	}

	t := <-stop
	close(stop)

	var requestz BrowserRequests
	for _, r := range requests {
		requestz = append(requestz, r)
	}

	sort.Sort(requestz)
	for _, r := range requestz {
		fmt.Println(r)
	}

	fmt.Println(t.Sub(start))

	w.rdb.SaveScreenshot("screenshot.png", 0644, 0, true)

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
