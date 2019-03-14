package store

import (
	"database/sql"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestURLStore(t *testing.T) {
	tt := []struct {
		name    string
		actions func(*testing.T, *urlStore)
	}{
		{name: "basic", actions: func(t *testing.T, us *urlStore) {
			u, _ := url.Parse("https://google.com")
			if _, err := us.Add(u); err != nil {
				t.Fatalf("unable to add url: %s", err)
			}
		}},
		{name: "with-visit", actions: func(t *testing.T, us *urlStore) {
			u, _ := url.Parse("https://google.com")
			if _, err := us.Add(u); err != nil {
				t.Fatalf("unable to add url: %s", err)
			}

			us.Visit(u, time.Now())
		}},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			db, fn, err := getDB("kraaler-url-store")
			if err != nil {
				t.Fatalf("unable to create db: %s", err)
			}
			defer os.RemoveAll(fn)

			us, err := NewURLStore(db, nil)
			if err != nil {
				t.Fatalf("unable to create url store: %s", err)
			}

			tc.actions(t, us)
			db.Close()

			db2, err := sql.Open("sqlite3", fn)
			if err != nil {
				t.Fatalf("unable to open db again: %s", err)
			}

			us2, err := NewURLStore(db2, nil)
			if err != nil {
				t.Fatalf("unable to create url store: %s", err)
			}

			times := map[string]*time.Time{}
			ids := map[string]int64{}
			for u, t := range us2.urls {
				ids[u.String()] = us2.ids[u]
				times[u.String()] = t
			}

			if len(us.urls) != len(us2.urls) {
				t.Fatalf("expected the two url stores to be of same length")
			}

			for u, ti := range us.urls {
				otherTime, ok := times[u.String()]
				if !ok {
					t.Fatalf("unable to find url time: %s", u)
				}

				var unixTi, unixOtherTi int64
				if ti != nil {
					unixTi = ti.Unix()
				}

				if otherTime != nil {
					unixOtherTi = otherTime.Unix()
				}

				if unixTi != unixOtherTi {
					t.Fatalf("expected times to be equal")
				}

				id, ok := ids[u.String()]
				if !ok {
					t.Fatalf("did not find url: %s", u)
				}

				otherId, ok := us.ids[u]
				if !ok {
					t.Fatalf("expected id to be non-empty: %s", u)
				}

				if id != otherId {
					t.Fatalf("expected ids to match (%d != %d)", id, otherId)
				}
			}

		})
	}
}
