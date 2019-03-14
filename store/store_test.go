package store

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aau-network-security/kraaler"
	"github.com/mafredri/cdp/protocol/network"
	_ "github.com/mattn/go-sqlite3"
	cache "github.com/patrickmn/go-cache"
)

func TestIDStore(t *testing.T) {
	type person struct {
		name   string
		age    int
		height int
	}

	tt := []struct {
		name   string
		cache  *cache.Cache
		person person
	}{
		{name: "no cache", cache: nil, person: person{
			name:   "Martin",
			age:    18,
			height: 182,
		}},
		{name: "with cache", cache: cache.New(time.Minute, time.Minute), person: person{
			name:   "Martin",
			age:    18,
			height: 182,
		}},
	}

	fname := func(t *testing.T) string {
		tmpfile, err := ioutil.TempFile("", "id-store-test")
		if err != nil {
			t.Fatalf("unable to create temp file: %s", err)
		}
		f := tmpfile.Name()
		os.Remove(f)

		return f
	}

	initSql := `
create table whatever_test (
id INTEGER PRIMARY KEY,
name TEXT NOT NULL,
age INTEGER NOT NULL,
height INTEGER NOT NULL
)`

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			fn := fname(t)
			db, err := sql.Open("sqlite3", fn)
			if err != nil {
				t.Fatalf("unable to create database: %s", err)
			}
			defer db.Close()
			defer os.Remove(fn)

			if _, err := db.Exec(initSql); err != nil {
				t.Fatalf("unable to initialize database: %s", err)
			}

			s := NewIDStore("whatever_test", tc.cache, "name", "age", "height")
			tx, err := db.Begin()
			if err != nil {
				t.Fatalf("unable to begin transaction: %s", err)
			}
			defer tx.Rollback()

			id, err := s.Get(tx, tc.person.name, tc.person.age, tc.person.height)
			if err != nil {
				t.Fatalf("unable to get id: %s", err)
			}

			if id == 0 {
				t.Fatalf("expected id to be non-zero")
			}

			otherID, err := s.Get(tx, tc.person.name, tc.person.age, tc.person.height)
			if err != nil {
				t.Fatalf("unable to get id (again): %s", err)
			}

			if id != otherID {
				t.Fatalf("expected id to be reused")
			}
		})
	}
}

func integerFieldsNonZero(tx *sql.Tx, table string, fields ...string) error {
	query := fmt.Sprintf("select %s from %s", strings.Join(fields, ","), table)

	ints := make([]interface{}, len(fields))
	for i, _ := range ints {
		var ii int
		ints[i] = &ii
	}

	if err := tx.QueryRow(query).Scan(ints...); err != nil {
		return err
	}

	for i, n := range ints {
		p := n.(*int)
		if *p == 0 {
			return fmt.Errorf("field \"%s\" is 0 (zero)", fields[i])
		}
	}

	return nil
}

func tableMustBeOfSize(tx *sql.Tx, table string, n int) error {
	query := fmt.Sprintf("select count(*) from %s", table)

	var count int
	if err := tx.QueryRow(query).Scan(&count); err != nil {
		return fmt.Errorf("unable to get count for %s: %s", table, err)
	}

	if count != n {
		return fmt.Errorf("expected %s to be of size %d, but was %d", table, n, count)
	}

	return nil
}

func getDB(name string) (*sql.DB, string, error) {
	tmpfile, err := ioutil.TempFile("", name)
	if err != nil {
		return nil, "", err
	}
	f := tmpfile.Name()
	os.Remove(f)

	db, err := sql.Open("sqlite3", f)
	return db, f, err
}

func TestSessionStore(t *testing.T) {

	aauURL, _ := url.Parse("http://aau.dk")
	tt := []struct {
		name string
		sess kraaler.CrawlSession
	}{
		{name: "basic", sess: kraaler.CrawlSession{
			InitialURL:     aauURL,
			Resolution:     "800x600",
			NavigateTime:   time.Now(),
			LoadedTime:     time.Now(),
			TerminatedTime: time.Now(),
		}},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			db, path, err := getDB("session-store-test")
			if err != nil {
				t.Fatalf("unable to create database: %s", err)
			}
			defer os.Remove(path)

			ss, err := NewSessionStore(db)
			if err != nil {
				t.Fatalf("unable to create session store: %s", err)
			}

			tx, err := db.Begin()
			if err != nil {
				t.Fatalf("unable to create transaction: %s", err)
			}
			defer tx.Rollback()

			if _, err := ss.Save(tx, &tc.sess); err != nil {
				t.Fatalf("unable to save session: %s", err)
			}

			if err := tableMustBeOfSize(tx, "fact_sessions", 1); err != nil {
				t.Fatal(err)
			}

			if err := tableMustBeOfSize(tx, "dim_resolutions", 1); err != nil {
				t.Fatal(err)
			}

			if err := integerFieldsNonZero(tx, "fact_sessions",
				"id",
				"resolution_id",
				"navigated_time",
				"loaded_time",
				"terminated_time",
			); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConsoleStore(t *testing.T) {
	tt := []struct {
		name    string
		console []*kraaler.JavaScriptConsole
	}{
		{name: "basic", console: []*kraaler.JavaScriptConsole{
			&kraaler.JavaScriptConsole{Msg: "hello"},
			&kraaler.JavaScriptConsole{Msg: "hello2"},
		}},
	}

	table := "fact_console_output"
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			db, path, err := getDB("console-store-test")
			if err != nil {
				t.Fatalf("unable to create database: %s", err)
			}
			defer os.Remove(path)

			cs, err := NewConsoleStore(db)
			if err != nil {
				t.Fatalf("unable to create console store: %s", err)
			}

			tx, err := db.Begin()
			if err != nil {
				t.Fatalf("unable to create transaction: %s", err)
			}
			defer tx.Rollback()

			if err := cs.Save(tx, 1, tc.console); err != nil {
				t.Fatalf("unable to save console: %s", err)
			}

			if err := tableMustBeOfSize(tx, table, len(tc.console)); err != nil {
				t.Fatal(err)
			}

			if err := integerFieldsNonZero(tx, table,
				"session_id",
				"seq",
			); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestScreenStore(t *testing.T) {
	tt := []struct {
		name       string
		url        string
		screenshot kraaler.BrowserScreenshot
	}{
		{name: "basic", url: "http://aau.dk", screenshot: kraaler.BrowserScreenshot{
			Screenshot: []byte("a"),
			Kind:       "png",
			Taken:      time.Now(),
		}},
	}

	table := "fact_screenshots"
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			db, path, err := getDB("screen-store-test")
			if err != nil {
				t.Fatalf("unable to create database: %s", err)
			}
			defer os.Remove(path)

			dir, err := ioutil.TempDir("", fmt.Sprintf("screen-store-screenshotstore-test-%s", tc.name))
			if err != nil {
				t.Fatalf("error when creating temp dir: %s", err)
			}
			defer os.RemoveAll(dir)

			ss, err := NewScreenStore(db, NewScreenshotStore(dir))
			if err != nil {
				t.Fatalf("unable to create screen store: %s", err)
			}

			tx, err := db.Begin()
			if err != nil {
				t.Fatalf("unable to create transaction: %s", err)
			}
			defer tx.Rollback()

			if err := ss.Save(tx, 1, tc.url, []*kraaler.BrowserScreenshot{&tc.screenshot}); err != nil {
				t.Fatalf("unable to save: %s", err)
			}

			if err := tableMustBeOfSize(tx, table, 1); err != nil {
				t.Fatal(err)
			}

			if err := integerFieldsNonZero(tx, table,
				"session_id",
				"time_taken",
			); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestActionStore(t *testing.T) {
	tt := []struct {
		name      string
		action    kraaler.CrawlAction
		tableDiff map[string]int
	}{
		{
			name: "basic",
			action: kraaler.CrawlAction{
				Initiator: kraaler.Initiator{
					Kind: "script",
					Stack: &kraaler.CallFrame{
						Column:     2,
						LineNumber: 25,
						Function:   func(s string) *string { return &s }("some_func"),
					},
				},
				Host: kraaler.Host{
					Domain: "aau.dk",
					IPAddr: "8.8.8.8",
				},
				Request: network.Request{
					URL:    "http://aau.dk",
					Method: "GET",
					Headers: network.Headers([]byte(
						`{ "User-Agent": "Chrome", "Date": "Today"}`,
					)),
					PostData: func(s string) *string { return &s }("some_post"),
				},
				Response: &network.Response{
					Status:   http.StatusOK,
					Protocol: func(s string) *string { return &s }("http"),
					Headers: network.Headers([]byte(
						`{ "Server": "nginx" }`,
					)),
					MimeType: "text/plain",
					SecurityDetails: &network.SecurityDetails{
						Protocol: "Test",
						Issuer:   "Test",
					},
				},
				Body: &kraaler.ResponseBody{
					Body: []byte("hello world"),
				},
			},
			tableDiff: map[string]int{
				"dim_methods":    1,
				"dim_hosts":      1,
				"dim_protocols":  2,
				"dim_initiators": 1,
				"fact_actions":   1,

				"dim_header_keyvalues":  3,
				"fact_response_headers": 1,
				"fact_request_headers":  2,

				"dim_url_schemes":     1,
				"dim_url_users":       0,
				"dim_url_hosts":       1,
				"dim_url_paths":       1,
				"dim_url_fragments":   0,
				"dim_url_raw_queries": 0,
				"fact_urls":           1,

				"dim_mime_types": 2,
				"fact_bodies":    1,

				"fact_post_data":       1,
				"fact_initiator_stack": 1,

				"dim_issuers":           1,
				"dim_key_exchanges":     1,
				"dim_ciphers":           1,
				"dim_san_lists":         1,
				"fact_security_details": 1,
			},
		},
	}

	table := "fact_actions"
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			db, path, err := getDB("action-store-test")
			if err != nil {
				t.Fatalf("unable to create database: %s", err)
			}
			defer os.Remove(path)

			dir, err := ioutil.TempDir("", fmt.Sprintf("action-store-test-%s", tc.name))
			if err != nil {
				t.Fatalf("error when creating temp dir: %s", err)
			}
			defer os.RemoveAll(dir)

			fs, err := NewFileStore(dir, WithCompression(GzipCompression))
			if err != nil {
				t.Fatalf("unable to create file store: %s", err)
			}

			as, err := NewActionStore(db, fs)
			if err != nil {
				t.Fatalf("unable to create action store: %s", err)
			}

			tx, err := db.Begin()
			if err != nil {
				t.Fatalf("unable to create transaction: %s", err)
			}
			defer tx.Rollback()

			if err := as.Save(tx, 1, []*kraaler.CrawlAction{&tc.action}); err != nil {
				t.Fatalf("unable to save: %s", err)
			}

			if err := tableMustBeOfSize(tx, table, 1); err != nil {
				t.Fatal(err)
			}

			for table, diff := range tc.tableDiff {
				if err := tableMustBeOfSize(tx, table, diff); err != nil {
					t.Fatal(err)
				}
			}

			if err := integerFieldsNonZero(tx, table,
				"session_id",
				"method_id",
				"protocol_id",
				"host_id",
				"initiator_id",
				"status_code",
			); err != nil {
				t.Fatal(err)
			}
		})
	}
}
