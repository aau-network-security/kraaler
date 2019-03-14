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
	m       sync.RWMutex
	db      *sql.DB
	sampler Sampler
	filters []URLFilter

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

func NewURLStore(db *sql.DB, sampler Sampler, filters ...URLFilter) (*urlStore, error) {
	if _, err := db.Exec(urlStoreSchema); err != nil {
		return nil, err
	}

	rows, err := db.Query("select id, url, last_visit from url_visits")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	strings := map[string]*url.URL{}
	ids := map[*url.URL]int64{}
	urls := map[*url.URL]*time.Time{}

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

		strings[urlStr] = u
		ids[u] = id
		urls[u] = nil

		if unixTime.Valid {
			t := time.Unix(unixTime.Int64, 0)
			urls[u] = &t
		}
	}

	return &urlStore{
		db:      db,
		sampler: sampler,
		urls:    urls,
		ids:     ids,
		strings: strings,
		filters: filters,
	}, nil
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

	return u, nil
}

func (us *urlStore) Add(urls ...*url.URL) (int, error) {
	var urlsToAdd []*url.URL
	us.m.RLock()
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
	us.m.RUnlock()

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

	us.m.Lock()
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
	us.m.Unlock()

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
			if _, ok := us.strings[dom.HTTP()]; !ok {
				us.m.RUnlock()
				out <- dom
				continue
			}

			if _, ok := us.strings[dom.HTTPS()]; !ok {
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

type Sampler func(queued map[*url.URL]*time.Time) *url.URL

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
