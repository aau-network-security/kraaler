package store

import (
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"sync"
	"time"

	"github.com/aau-network-security/kraaler"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/publicsuffix"
)

var (
	StoreIsEmptyErr = errors.New("store is empty")
)

type URLFilter func(*url.URL) bool

type urlStore struct {
	m          sync.RWMutex
	db         *sql.DB
	sampler    Sampler
	resampling bool
	filters    []URLFilter

	strings map[string]*url.URL
	urls    map[*url.URL]*time.Time
	ids     map[*url.URL]int64
}

func OnlyTLD(ending string) func(*url.URL) bool {
	return func(u *url.URL) bool {
		tld, ok := publicsuffix.PublicSuffix(u.Host)
		if !ok {
			return false
		}

		return ending == tld
	}
}

type URLStoreOpt func(*urlStore)

func WithURLFilters(f ...URLFilter) URLStoreOpt {
	return func(u *urlStore) {
		u.filters = append(u.filters, f...)
	}
}

func WithSampler(s Sampler) URLStoreOpt {
	return func(u *urlStore) {
		u.sampler = s
	}
}

func WithNoResampling() URLStoreOpt {
	return func(u *urlStore) {
		u.resampling = false
	}
}

func NewURLStore(db *sql.DB, opts ...URLStoreOpt) (*urlStore, error) {
	if _, err := db.Exec(urlStoreSchema); err != nil {
		return nil, err
	}

	rows, err := db.Query("select id, url, last_visit from url_visits")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	us := &urlStore{
		db:         db,
		sampler:    UniformSampler(),
		resampling: true,
		urls:       map[*url.URL]*time.Time{},
		ids:        map[*url.URL]int64{},
		strings:    map[string]*url.URL{},
	}

	for _, opt := range opts {
		opt(us)
	}

	for rows.Next() {
		var id int64
		var urlStr string
		var unixTime sql.NullInt64

		err = rows.Scan(&id, &urlStr, &unixTime)
		if err != nil {
			return nil, err
		}

		u, err := url.Parse(urlStr)
		if err != nil {
			return nil, err
		}

		us.strings[urlStr] = u
		us.ids[u] = id
		us.urls[u] = nil

		if unixTime.Valid && us.resampling {
			t := time.Unix(0, unixTime.Int64)
			us.urls[u] = &t
		}
	}

	return us, nil
}

func (us *urlStore) Size() int {
	us.m.RLock()
	n := len(us.urls)
	us.m.RUnlock()
	return n
}

func (us *urlStore) Sample() (*url.URL, error) {
	us.m.RLock()
	if len(us.urls) == 0 {
		us.m.RUnlock()
		return nil, StoreIsEmptyErr
	}

	u := us.sampler(us.urls)
	us.m.RUnlock()
	if u == nil {
		return nil, fmt.Errorf("sample is nil")
	}

	if !us.resampling {
		us.m.Lock()
		delete(us.urls, u)
		us.m.Unlock()
	}

	return u, nil
}

func (us *urlStore) Consume(p kraaler.URLProvider) {
	go func() {
		for u := range p.UrlsC() {
			us.Add(u)
		}
	}()
}

func (us *urlStore) Add(urls ...*url.URL) (int, error) {
	var urlsToAdd []*url.URL
	us.m.Lock()
	defer us.m.Unlock()

loop:
	for _, u := range urls {
		for _, f := range us.filters {
			if ok := f(u); !ok {
				continue loop
			}
		}

		if _, ok := us.strings[u.String()]; ok {
			continue
		}

		urlsToAdd = append(urlsToAdd, u)
	}

	if len(urlsToAdd) == 0 {
		return 0, nil
	}

	tx, err := us.db.Begin()
	if err != nil {
		return 0, err
	}

	stmt, err := tx.Prepare("INSERT INTO url_visits(url) values(?)")
	if err != nil {
		return 0, err
	}

	var count int
	var dbErr error

	for _, u := range urlsToAdd {
		res, err := stmt.Exec(u.String())
		if err != nil {
			if dbErr != nil {
				dbErr = err
			}

			continue

		}

		id, err := res.LastInsertId()
		if err != nil {
			if dbErr != nil {
				dbErr = err
			}

			continue
		}

		us.strings[u.String()] = u
		us.urls[u] = nil
		us.ids[u] = id
		count += 1
	}
	tx.Commit()

	return count, dbErr
}

func (us *urlStore) Visit(u *url.URL, t time.Time) error {
	us.m.Lock()
	if _, ok := us.urls[u]; ok {
		stmt, err := us.db.Prepare("update url_visits set last_visit=? where id=?")
		if err != nil {
			us.m.Unlock()
			return err
		}

		_, err = stmt.Exec(t.Unix(), us.ids[u])
		if err != nil {
			us.m.Unlock()
			return err
		}

		if !us.resampling {
			delete(us.urls, u)
			us.m.Unlock()
			return nil
		}

		us.urls[u] = &t

	}
	us.m.Unlock()

	return nil
}

func (us *urlStore) FilterKnown(doms <-chan kraaler.Domain) <-chan kraaler.Domain {
	out := make(chan kraaler.Domain)

	go func() {
		for dom := range doms {
			us.m.RLock()
			if _, ok := us.strings[dom.HTTPS()]; !ok {
				us.m.RUnlock()
				out <- dom
				continue
			}

			if _, ok := us.strings[dom.HTTP()]; !ok {
				us.m.RUnlock()
				out <- dom
				continue
			}

			us.m.RUnlock()
		}

		close(out)
	}()

	return out
}

type Sampler func(map[*url.URL]*time.Time) *url.URL

func UniformSampler() Sampler {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	return func(urls map[*url.URL]*time.Time) *url.URL {
		i := r.Intn(len(urls))
		for u := range urls {
			if i == 0 {
				return u
			}

			i--
		}

		return nil
	}
}

func PairSampler(pw int) Sampler {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	pwF := float64(pw)

	return func(queued map[*url.URL]*time.Time) *url.URL {
		domainCount := map[string]int{}
		for u, visit := range queued {
			if u.Host == "" {
				continue
			}

			if visit != nil {
				domainCount[u.Host] = domainCount[u.Host] + 1
				continue
			}

			if _, ok := domainCount[u.Host]; !ok {
				domainCount[u.Host] = 0
			}
		}

		weights := map[*url.URL]float64{}
		for u, t := range queued {
			if t == nil {
				baseWeight := 1.0
				if domainCount[u.Host] == 1 {
					baseWeight = pwF
				}
				weights[u] = baseWeight / float64(domainCount[u.Host]+1)
			}
		}

		u := randomPickWeighted(r, weights)

		return u
	}
}

func randomPickWeighted(rd *rand.Rand, m map[*url.URL]float64) *url.URL {
	var totalWeight float64
	for _, w := range m {
		totalWeight += w
	}

	if totalWeight == 0 {
		return nil
	}

	r := rd.Float64() * totalWeight
	for k, w := range m {
		r -= w
		if r <= 0 {
			return k
		}
	}

	return nil
}
