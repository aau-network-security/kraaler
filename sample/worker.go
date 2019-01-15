package main

import (
	"net/url"

	"github.com/raff/godet"
)

type Worker struct {
	remote *godet.RemoteDebugger
}

func NewWorker(queue <-chan *url.URL) *Worker {
	return &Worker{}
}

func (w *Worker) Halt() error {
	return w.remote.Close()
}
