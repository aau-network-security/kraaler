package store

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/aau-network-security/kraaler"
)

func TestGetHostID(t *testing.T) {
	type row struct {
		domain string
		tld    string
		ip     string
	}

	tt := []struct {
		name string
		ip   string
		url  string
		row  row
	}{
		{name: "basic", ip: "8.8.8.8", url: "https://google.com/", row: row{"google.com", "com", "8.8.8.8"}},
		{name: "subdomains", ip: "8.8.8.8", url: "https://mail.google.com/", row: row{"mail.google.com", "com", "8.8.8.8"}},
	}

	s, err := NewStore("get_host_id.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("get_host_id.db")

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			getId := func() int64 {
				tx, err := s.db.Begin()
				if err != nil {
					t.Fatalf("unexpected error when creating transaction: %s", err)
				}

				id, err := txStore{tx}.getHostID(kraaler.BrowserAction{
					HostIP: &tc.ip,
					Request: kraaler.BrowserRequest{
						URL: tc.url,
					},
				})

				tx.Commit()

				if err != nil {
					t.Fatalf("unexpected error when retrieving host id: %s", err)
				}

				if id == 0 {
					t.Fatalf("expected id to be greater than zero")
				}

				return id
			}

			id := getId()

			var fetched row
			err = s.db.QueryRow("select domain, tld, ipv4 from dim_hosts where domain = ? and tld = ? and ipv4 = ?",
				tc.row.domain,
				tc.row.tld,
				tc.row.ip,
			).Scan(
				&fetched.domain,
				&fetched.tld,
				&fetched.ip,
			)
			if err != nil {
				t.Fatalf("unable to fetch row from database: %s", err)
			}

			fv := fmt.Sprintf("%v", fetched)
			ev := fmt.Sprintf("%v", tc.row)
			if fv != ev {
				t.Fatalf("unexpected row values:\n  expected -> %v\n  actual: -> %v\n",
					ev,
					fv,
				)
			}

			if id != getId() {
				t.Fatalf("expected id to be reused")
			}

		})
	}

}

func TestGetSchemeId(t *testing.T) {
	type row struct {
		kind     string
		protocol string
	}

	tt := []struct {
		name     string
		url      string
		protocol string
		row      row
	}{
		{name: "basic", protocol: "HTTP 2", url: "https://google.com/", row: row{"https", "HTTP 2"}},
	}

	s, err := NewStore("get_scheme_id.db")
	if err != nil {
		t.Fatalf("unable to open database: %s", err)
	}
	defer os.Remove("get_scheme_id.db")

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			getId := func() int64 {
				tx, err := s.db.Begin()
				if err != nil {
					t.Fatalf("unexpected error when creating transaction: %s", err)
				}

				id, err := txStore{tx}.getSchemeId(kraaler.BrowserAction{
					Protocol: &tc.protocol,
					Request: kraaler.BrowserRequest{
						URL: tc.url,
					},
				})

				tx.Commit()

				if err != nil {
					t.Fatalf("unexpected error when retrieving host id: %s", err)
				}

				if id == 0 {
					t.Fatalf("expected id to be greater than zero")
				}

				return id
			}

			id := getId()

			var dummyId int64
			err = s.db.QueryRow("select id from dim_schemes where kind = ? AND protocol = ?",
				tc.row.kind,
				tc.row.protocol,
			).Scan(&dummyId)
			if err != nil && err != sql.ErrNoRows {
				t.Fatalf("error fetching: %s", err)
			}

			if id != getId() {
				t.Fatalf("expected id to be reused")
			}

		})
	}

}

func TestGetInitiatorId(t *testing.T) {
	type row struct {
		name string
	}

	tt := []struct {
		name      string
		initiator string
		row       row
	}{
		{name: "basic", initiator: "parser", row: row{"parser"}},
	}

	s, err := NewStore("get_initiator_id.db")
	if err != nil {
		t.Fatalf("unable to open database: %s", err)
	}
	defer os.Remove("get_initiator_id.db")

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			getId := func() int64 {
				tx, err := s.db.Begin()
				if err != nil {
					t.Fatalf("unexpected error when creating transaction: %s", err)
				}

				id, err := txStore{tx}.getInitiatorId(kraaler.BrowserAction{
					Initiator: tc.initiator,
				})

				tx.Commit()

				if err != nil {
					t.Fatalf("unexpected error when retrieving initiator id: %s", err)
				}

				if id == 0 {
					t.Fatalf("expected id to be greater than zero")
				}

				return id
			}

			id := getId()

			var dummyId int64
			err = s.db.QueryRow("select id from dim_initiators where name = ?",
				tc.row.name,
			).Scan(&dummyId)
			if err != nil && err != sql.ErrNoRows {
				t.Fatalf("error fetching: %s", err)
			}

			if id != getId() {
				t.Fatalf("expected id to be reused")
			}

		})
	}

}

func TestGetErrorId(t *testing.T) {
	type row struct {
		error string
	}

	tt := []struct {
		name  string
		error string
		row   row
	}{
		{name: "basic", error: "error is bad", row: row{"error is bad"}},
	}

	s, err := NewStore("get_error_id.db")
	if err != nil {
		t.Fatalf("unable to open database: %s", err)
	}
	defer os.Remove("get_error_id.db")

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			getId := func() int64 {
				tx, err := s.db.Begin()
				if err != nil {
					t.Fatalf("unexpected error when creating transaction: %s", err)
				}

				id, err := txStore{tx}.getErrorId(kraaler.BrowserAction{
					ResponseError: &tc.error,
				})

				tx.Commit()

				if err != nil {
					t.Fatalf("unexpected error when retrieving host id: %s", err)
				}

				if id == 0 {
					t.Fatalf("expected id to be greater than zero")
				}

				return id
			}

			id := getId()

			var dummyId int64
			err = s.db.QueryRow("select id from dim_errors where error = ?",
				tc.row.error,
			).Scan(&dummyId)
			if err != nil && err != sql.ErrNoRows {
				t.Fatalf("error fetching: %s", err)
			}

			if id != getId() {
				t.Fatalf("expected id to be reused")
			}

		})
	}

}

func TestGetKeyValueId(t *testing.T) {
	s, err := NewStore("get_keyv_id.db")
	if err != nil {
		t.Fatalf("unable to open database: %s", err)
	}
	defer os.Remove("get_keyv_id.db")

	getId := func() int64 {
		tx, err := s.db.Begin()
		if err != nil {
			t.Fatalf("unexpected error when creating transaction: %s", err)
		}

		id, err := txStore{tx}.getKeyvalueId("keytest", "valuetest")

		tx.Commit()

		if err != nil {
			t.Fatalf("unexpected error when retrieving keyvalue id: %s", err)
		}

		if id == 0 {
			t.Fatalf("expected id to be greater than zero")
		}

		return id
	}

	id := getId()

	var count int64
	err = s.db.QueryRow("select count(*) from dim_header_keyvalues").Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		t.Fatalf("error fetching: %s", err)
	}

	if count <= 0 {
		t.Fatalf("expected atleast one column in dim_header_keyvalues")
	}

	err = s.db.QueryRow("select count(*) from dim_header_keys").Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		t.Fatalf("error fetching: %s", err)
	}

	if count <= 0 {
		t.Fatalf("expected atleast one column dim_header_keys")
	}

	if id != getId() {
		t.Fatalf("expected id to be reused")
	}

}
