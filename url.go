package kraaler

import (
	"errors"
	"net/url"
	"sync"
)

var (
	StoreIsEmptyErr = errors.New("store is empty")
)

type URLStore interface {
	Sample() (*url.URL, error)
	Push(<-chan *url.URL)
}

type urlStore struct {
	m       sync.RWMutex
	sampler Sampler
	strings map[string]bool
	urls    map[*url.URL]struct{}
}

func NewURLStore(sampler Sampler) *urlStore {
	return &urlStore{
		sampler: sampler,
		strings: map[string]bool{},
		urls:    map[*url.URL]struct{}{},
	}
}

func (us *urlStore) Sample() (*url.URL, error) {
	us.m.RLock()
	defer us.m.RUnlock()
	if len(us.urls) == 0 {
		return nil, StoreIsEmptyErr
	}

	return us.sampler(us.urls), nil
}

func (us *urlStore) Push(stream <-chan *url.URL) {
	for u := range stream {
		us.m.RLock()
		if us.strings[u.String()] {
			us.m.RUnlock()
			continue
		}
		us.m.RUnlock()

		us.m.Lock()
		us.strings[u.String()] = true
		us.urls[u] = struct{}{}
		us.m.Unlock()
	}
}
