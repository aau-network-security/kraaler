package store

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestFileStore(t *testing.T) {
	lessThanOrg := func(sf StoredFile) error {
		if sf.OrgSize <= sf.CompSize {
			return fmt.Errorf("comp size (%d) is equal or larger than org size (%d)", sf.CompSize, sf.OrgSize)
		}
		return nil
	}

	type checker func(StoredFile) error

	tt := []struct {
		name   string
		files  []string
		opts   []FileStoreOpt
		checks []checker
		amount int
	}{
		{name: "basic", files: []string{"meow"}, amount: 1},
		{name: "deduplication", files: []string{"meow", "meow"}, amount: 1},
		{name: "distinct", files: []string{"meow", "meow2"}, amount: 2},
		{name: "compression",
			opts:   []FileStoreOpt{WithCompression(GzipCompression)},
			files:  []string{"meow meow meow"},
			amount: 1,
			checks: []checker{lessThanOrg},
		},
		{name: "conditional mime",
			opts:   []FileStoreOpt{WithMimeTypes(func(s string) bool { return strings.HasPrefix(s, "text/html") })},
			files:  []string{"meow", "<html></html>"},
			amount: 1,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir("", fmt.Sprintf("kraaler-filestore-test-%s", tc.name))
			if err != nil {
				t.Fatalf("error when creating temp dir: %s", err)
			}
			defer os.RemoveAll(dir)

			fs, err := NewFileStore(dir, tc.opts...)
			if err != nil {
				t.Fatalf("error when creating filestore: %s", err)
			}

			for _, txt := range tc.files {
				sf, err := fs.Store([]byte(txt))
				if err != nil {
					if err == NotAllowedMimeErr {
						continue
					}

					t.Fatalf("error when storing file (%s): %s", txt, err)
				}

				for _, c := range tc.checks {
					if err := c(sf); err != nil {
						t.Fatal(err)
					}
				}
			}

			files, err := ioutil.ReadDir(dir)
			if err != nil {
				t.Fatalf("unable to read temp dir: %s", err)
			}

			if len(files) != tc.amount {
				t.Fatalf("unexpected amount of files in store (expected: %d): %d", tc.amount, len(files))
			}

		})
	}
}

// func TestGetHostID(t *testing.T) {
// 	type row struct {
// 		domain string
// 		tld    string
// 		ip     string
// 	}

// 	tt := []struct {
// 		name string
// 		ip   string
// 		url  string
// 		row  row
// 	}{
// 		{name: "basic", ip: "8.8.8.8", url: "https://google.com/", row: row{"google.com", "com", "8.8.8.8"}},
// 		{name: "subdomains", ip: "8.8.8.8", url: "https://mail.google.com/", row: row{"mail.google.com", "com", "8.8.8.8"}},
// 	}

// 	s, err := NewStore("get_host_id.db", "dummy-store")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer os.Remove("get_host_id.db")

// 	for _, tc := range tt {
// 		t.Run(tc.name, func(t *testing.T) {
// 			getId := func() int64 {
// 				tx, err := s.db.Begin()
// 				if err != nil {
// 					t.Fatalf("unexpected error when creating transaction: %s", err)
// 				}

// 				id, err := txStore{tx: tx}.getHostId(kraaler.BrowserAction{
// 					HostIP: &tc.ip,
// 					Request: kraaler.BrowserRequest{
// 						URL: tc.url,
// 					},
// 				})

// 				tx.Commit()

// 				if err != nil {
// 					t.Fatalf("unexpected error when retrieving host id: %s", err)
// 				}

// 				if id == 0 {
// 					t.Fatalf("expected id to be greater than zero")
// 				}

// 				return id
// 			}

// 			id := getId()

// 			var fetched row
// 			err = s.db.QueryRow("select domain, tld, ipv4 from dim_hosts where domain = ? and tld = ? and ipv4 = ?",
// 				tc.row.domain,
// 				tc.row.tld,
// 				tc.row.ip,
// 			).Scan(
// 				&fetched.domain,
// 				&fetched.tld,
// 				&fetched.ip,
// 			)
// 			if err != nil {
// 				t.Fatalf("unable to fetch row from database: %s", err)
// 			}

// 			fv := fmt.Sprintf("%v", fetched)
// 			ev := fmt.Sprintf("%v", tc.row)
// 			if fv != ev {
// 				t.Fatalf("unexpected row values:\n  expected -> %v\n  actual: -> %v\n",
// 					ev,
// 					fv,
// 				)
// 			}

// 			if id != getId() {
// 				t.Fatalf("expected id to be reused")
// 			}

// 		})
// 	}

// }

// func TestGetSchemeId(t *testing.T) {
// 	type row struct {
// 		kind     string
// 		protocol string
// 	}

// 	tt := []struct {
// 		name     string
// 		url      string
// 		protocol string
// 		row      row
// 	}{
// 		{name: "basic", protocol: "HTTP 2", url: "https://google.com/", row: row{"https", "HTTP 2"}},
// 	}

// 	s, err := NewStore("get_scheme_id.db", "dummy-store")
// 	if err != nil {
// 		t.Fatalf("unable to open database: %s", err)
// 	}
// 	defer os.Remove("get_scheme_id.db")

// 	for _, tc := range tt {
// 		t.Run(tc.name, func(t *testing.T) {
// 			getId := func() int64 {
// 				tx, err := s.db.Begin()
// 				if err != nil {
// 					t.Fatalf("unexpected error when creating transaction: %s", err)
// 				}

// 				id, err := txStore{tx: tx}.getSchemeId(kraaler.BrowserAction{
// 					Protocol: &tc.protocol,
// 					Request: kraaler.BrowserRequest{
// 						URL: tc.url,
// 					},
// 				})

// 				tx.Commit()

// 				if err != nil {
// 					t.Fatalf("unexpected error when retrieving host id: %s", err)
// 				}

// 				if id == 0 {
// 					t.Fatalf("expected id to be greater than zero")
// 				}

// 				return id
// 			}

// 			id := getId()

// 			var dummyId int64
// 			err = s.db.QueryRow("select id from dim_schemes where scheme = ?",
// 				tc.row.kind,
// 			).Scan(&dummyId)
// 			if err != nil && err != sql.ErrNoRows {
// 				t.Fatalf("error fetching: %s", err)
// 			}

// 			if id != getId() {
// 				t.Fatalf("expected id to be reused")
// 			}

// 		})
// 	}

// }

// func TestGetInitiatorId(t *testing.T) {
// 	type row struct {
// 		name string
// 	}

// 	tt := []struct {
// 		name      string
// 		initiator string
// 		row       row
// 	}{
// 		{name: "basic", initiator: "parser", row: row{"parser"}},
// 	}

// 	s, err := NewStore("get_initiator_id.db", "dummy-store")
// 	if err != nil {
// 		t.Fatalf("unable to open database: %s", err)
// 	}
// 	defer os.Remove("get_initiator_id.db")

// 	for _, tc := range tt {
// 		t.Run(tc.name, func(t *testing.T) {
// 			getId := func() int64 {
// 				tx, err := s.db.Begin()
// 				if err != nil {
// 					t.Fatalf("unexpected error when creating transaction: %s", err)
// 				}

// 				id, err := txStore{tx: tx}.getInitiatorId(kraaler.BrowserAction{
// 					Initiator: tc.initiator,
// 				})

// 				tx.Commit()

// 				if err != nil {
// 					t.Fatalf("unexpected error when retrieving initiator id: %s", err)
// 				}

// 				if id == 0 {
// 					t.Fatalf("expected id to be greater than zero")
// 				}

// 				return id
// 			}

// 			id := getId()

// 			var dummyId int64
// 			err = s.db.QueryRow("select id from dim_initiators where name = ?",
// 				tc.row.name,
// 			).Scan(&dummyId)
// 			if err != nil && err != sql.ErrNoRows {
// 				t.Fatalf("error fetching: %s", err)
// 			}

// 			if id != getId() {
// 				t.Fatalf("expected id to be reused")
// 			}

// 		})
// 	}

// }

// func TestGetErrorId(t *testing.T) {
// 	type row struct {
// 		error string
// 	}

// 	tt := []struct {
// 		name  string
// 		error string
// 		row   row
// 	}{
// 		{name: "basic", error: "error is bad", row: row{"error is bad"}},
// 	}

// 	s, err := NewStore("get_error_id.db", "dummy-store")
// 	if err != nil {
// 		t.Fatalf("unable to open database: %s", err)
// 	}
// 	defer os.Remove("get_error_id.db")

// 	for _, tc := range tt {
// 		t.Run(tc.name, func(t *testing.T) {
// 			getId := func() int64 {
// 				tx, err := s.db.Begin()
// 				if err != nil {
// 					t.Fatalf("unexpected error when creating transaction: %s", err)
// 				}

// 				id, err := txStore{tx: tx}.getErrorId(kraaler.BrowserAction{
// 					ResponseError: &tc.error,
// 				})

// 				tx.Commit()

// 				if err != nil {
// 					t.Fatalf("unexpected error when retrieving host id: %s", err)
// 				}

// 				if id == 0 {
// 					t.Fatalf("expected id to be greater than zero")
// 				}

// 				return id
// 			}

// 			id := getId()

// 			var dummyId int64
// 			err = s.db.QueryRow("select id from dim_errors where error = ?",
// 				tc.row.error,
// 			).Scan(&dummyId)
// 			if err != nil && err != sql.ErrNoRows {
// 				t.Fatalf("error fetching: %s", err)
// 			}

// 			if id != getId() {
// 				t.Fatalf("expected id to be reused")
// 			}

// 		})
// 	}

// }

// func TestGetKeyValueId(t *testing.T) {
// 	s, err := NewStore("get_keyv_id.db", "dummy-store")
// 	if err != nil {
// 		t.Fatalf("unable to open database: %s", err)
// 	}
// 	defer os.Remove("get_keyv_id.db")

// 	getId := func() int64 {
// 		tx, err := s.db.Begin()
// 		if err != nil {
// 			t.Fatalf("unexpected error when creating transaction: %s", err)
// 		}

// 		id, err := txStore{tx: tx}.getKeyvalueId("keytest", "valuetest")

// 		tx.Commit()

// 		if err != nil {
// 			t.Fatalf("unexpected error when retrieving keyvalue id: %s", err)
// 		}

// 		if id == 0 {
// 			t.Fatalf("expected id to be greater than zero")
// 		}

// 		return id
// 	}

// 	id := getId()

// 	var count int64
// 	err = s.db.QueryRow("select count(*) from dim_header_keyvalues").Scan(&count)
// 	if err != nil && err != sql.ErrNoRows {
// 		t.Fatalf("error fetching: %s", err)
// 	}

// 	if count <= 0 {
// 		t.Fatalf("expected atleast one column in dim_header_keyvalues")
// 	}

// 	err = s.db.QueryRow("select count(*) from dim_header_keys").Scan(&count)
// 	if err != nil && err != sql.ErrNoRows {
// 		t.Fatalf("error fetching: %s", err)
// 	}

// 	if count <= 0 {
// 		t.Fatalf("expected atleast one column dim_header_keys")
// 	}

// 	if id != getId() {
// 		t.Fatalf("expected id to be reused")
// 	}

// }

// func TestStoreSave(t *testing.T) {
// 	s, err := NewStore("save_test.db", "dummy-store")
// 	if err != nil {
// 		t.Fatalf("unable to open database: %s", err)
// 	}

// 	tx, err := s.db.Begin()
// 	if err != nil {
// 		t.Fatalf("unexpected error when creating transaction: %s", err)
// 	}

// 	proto := "HTTP 1.1"
// 	hostip := "1.1.1.1"
// 	action := kraaler.BrowserAction{
// 		Initiator: "parser",
// 		Protocol:  &proto,
// 		Request: kraaler.BrowserRequest{
// 			URL:    "https://google.com/",
// 			Method: "GET",
// 			Headers: map[string]string{
// 				"Dummy-Header": "Testing",
// 			},
// 		},
// 		Response: &kraaler.BrowserResponse{
// 			StatusCode: http.StatusOK,
// 			Headers: map[string]string{
// 				"Dummy-Reply": "Testing2",
// 			},
// 			MimeType:           "text/html",
// 			Body:               []byte("meow"),
// 			BodyChecksumSha256: "asbcsast",
// 		},
// 		HostIP: &hostip,
// 		SecurityDetails: &kraaler.BrowserSecurityDetails{
// 			Protocol:    "TLS 1.2",
// 			KeyExchange: "RSA",
// 			Cipher:      "No idea",
// 			SubjectName: "google.com",
// 			SanList:     []string{"aaa", "bbb", "ccc"},
// 			Issuer:      "Google",
// 			ValidFrom:   time.Now(),
// 			ValidTo:     time.Now().Add(24 * time.Hour),
// 		},
// 		Console: []string{"test1", "test2"},
// 	}

// 	err = s.Save(action)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	tx.Commit()
// }
