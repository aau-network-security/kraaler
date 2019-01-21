package kraaler_test

import (
	"net/url"
	"testing"

	"github.com/aau-network-security/kraaler"
)

func TestNewWorker(t *testing.T) {
	queue := make(chan *kraaler.FetchRequest)
	resps := make(chan kraaler.FetchResponse, 10)

	w, err := kraaler.NewWorker(queue, resps)
	if err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse("http://forsikringsguiden.dk")
	queue <- &kraaler.FetchRequest{
		Url: u,
	}

	w.Close()
}