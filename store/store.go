package store

import (
	"database/sql"
	"fmt"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aau-network-security/kraaler"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

func NewStore(path string) (*Store, error) {
	var performInit bool
	if _, err := os.Stat(path); os.IsNotExist(err) {
		performInit = true
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	if performInit {
		if _, err := db.Exec(initSql); err != nil {
			return nil, err
		}
	}

	return &Store{db}, nil
}

func (s *Store) Save(ac kraaler.BrowserAction) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Commit()

	fmt.Println(txStore{tx: tx}.getHostID(ac))

	return nil
}

type txStore struct {
	tx           *sql.Tx
	fileStoreDir string
}

func (s txStore) lastId() (int64, error) {
	var id int64
	err := s.tx.QueryRow("select last_insert_rowid()").Scan(&id)
	if err != nil {
		return 0, err
	}

	return id, nil
}

func (s txStore) getHostID(ac kraaler.BrowserAction) (int64, error) {
	u, err := url.Parse(ac.Request.URL)
	if err != nil {
		return 0, err
	}

	parts := strings.Split(u.Host, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("malformed domain")
	}
	tld := parts[len(parts)-1]

	var id int64
	err = s.tx.QueryRow("SELECT id FROM dim_hosts WHERE domain = ? AND tld = ? AND ipv4 = ? LIMIT 1",
		u.Host,
		tld,
		ac.HostIP,
	).Scan(&id)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	if id > 0 {
		return id, nil
	}

	stmt, err := s.tx.Prepare("insert into dim_hosts(domain, tld, ipv4) values(?, ?, ?)")
	if err != nil {
		return 0, err
	}

	if _, err := stmt.Exec(
		u.Host,
		tld,
		ac.HostIP,
	); err != nil {
		return 0, nil
	}

	return s.lastId()
}

func (s txStore) getSchemeId(ac kraaler.BrowserAction) (int64, error) {
	u, err := url.Parse(ac.Request.URL)
	if err != nil {
		return 0, err
	}

	var id int64
	err = s.tx.QueryRow("SELECT id FROM dim_schemes WHERE kind = ? AND protocol = ? LIMIT 1",
		u.Scheme,
		ac.Protocol,
	).Scan(&id)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	if id > 0 {
		return id, nil
	}

	stmt, err := s.tx.Prepare("insert into dim_schemes(kind, protocol) values(?, ?)")
	if err != nil {
		return 0, err
	}

	if _, err := stmt.Exec(
		u.Scheme,
		ac.Protocol,
	); err != nil {
		return 0, nil
	}

	return s.lastId()
}

func (s txStore) getInitiatorId(ac kraaler.BrowserAction) (int64, error) {
	var id int64
	err := s.tx.QueryRow("SELECT id FROM dim_initiators WHERE name = ? LIMIT 1",
		ac.Initiator,
	).Scan(&id)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	if id > 0 {
		return id, nil
	}

	stmt, err := s.tx.Prepare("insert into dim_initiators(name) values(?)")
	if err != nil {
		return 0, err
	}

	if _, err := stmt.Exec(
		ac.Initiator,
	); err != nil {
		return 0, nil
	}

	return s.lastId()
}

func (s txStore) getErrorId(ac kraaler.BrowserAction) (int64, error) {
	if ac.ResponseError == nil {
		return 0, fmt.Errorf("response error is empty")
	}

	var id int64
	err := s.tx.QueryRow("SELECT id FROM dim_errors WHERE error = ? LIMIT 1",
		*ac.ResponseError,
	).Scan(&id)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	if id > 0 {
		return id, nil
	}

	stmt, err := s.tx.Prepare("insert into dim_errors(error) values(?)")
	if err != nil {
		return 0, err
	}

	if _, err := stmt.Exec(
		*ac.ResponseError,
	); err != nil {
		return 0, nil
	}

	return s.lastId()
}

func (s txStore) getKeyvalueId(key, value string) (int64, error) {
	var keyId int64
	err := s.tx.QueryRow("SELECT id FROM dim_header_keys WHERE key = ? LIMIT 1",
		key,
	).Scan(&keyId)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	if keyId == 0 {
		stmt, err := s.tx.Prepare("insert into dim_header_keys(key) values(?)")
		if err != nil {
			return 0, err
		}

		if _, err := stmt.Exec(
			key,
		); err != nil {
			return 0, nil
		}

		keyId, err = s.lastId()
		if err != nil {
			return 0, err
		}
	}

	var kvId int64
	err = s.tx.QueryRow("SELECT id FROM dim_header_keyvalues WHERE key_id = ? AND value = ? LIMIT 1",
		keyId,
		value,
	).Scan(&kvId)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	if kvId > 0 {
		return kvId, nil
	}

	stmt, err := s.tx.Prepare("insert into dim_header_keyvalues(key_id, value) values(?,?)")
	if err != nil {
		return 0, err
	}

	if _, err := stmt.Exec(
		keyId,
		value,
	); err != nil {
		return 0, nil
	}

	return s.lastId()
}

func (s txStore) insertBody(ac kraaler.BrowserAction, aid int64) error {
	u, err := url.Parse(ac.Request.URL)
	if err != nil {
		return err
	}

	folder := filepath.Join(s.fileStoreDir, "bodies", strings.ToLower(u.Host))
	if err := os.MkdirAll(folder, os.ModePerm); err != nil {
		return err
	}

	var mimeId int64
	mimeType := ac.Response.MimeType
	err = s.tx.QueryRow("SELECT id FROM dim_mime_types WHERE mime_type = ? LIMIT 1",
		mimeType,
	).Scan(&mimeId)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	if mimeId == 0 {
		stmt, err := s.tx.Prepare("insert into dim_mime_types(mime_type) values(?)")
		if err != nil {
			return err
		}

		if _, err := stmt.Exec(
			mimeType,
		); err != nil {
			return err
		}

		mimeId, err = s.lastId()
		if err != nil {
			return err
		}
	}

	stmt, err := s.tx.Prepare("insert into fact_bodies(action_id, path, mime_id, hash256) values(?,?,?,?)")
	if err != nil {
		return err
	}

	checksum := ac.Response.BodyChecksumSha256
	file := checksum
	exts, _ := mime.ExtensionsByType(mimeType)
	if len(exts) > 0 {
		file += exts[0]
	}

	path := filepath.Join(folder, file)
	if _, err := stmt.Exec(
		aid,
		path,
		mimeType,
		checksum,
	); err != nil {
		return err
	}

	return nil
}

func (s txStore) insertConsoleOutput(ac kraaler.BrowserAction, aid int64) error {

}
