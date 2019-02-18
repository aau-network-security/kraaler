package store

import (
	"database/sql"
	"fmt"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aau-network-security/kraaler"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db   *sql.DB
	path string
}

func NewStore(dbpath string, path string) (*Store, error) {
	var performInit bool
	if _, err := os.Stat(dbpath); os.IsNotExist(err) {
		performInit = true
	}

	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return nil, err
	}

	if performInit {
		if _, err := db.Exec(initSql); err != nil {
			return nil, err
		}
	}

	return &Store{db, path}, nil
}

func (s *Store) Save(ac kraaler.BrowserAction) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}

	txs := txStore{
		tx:   tx,
		path: s.path,
	}

	aid, err := txs.insertActionFact(ac)
	if err != nil {
		return err
	}

	if err := txs.insertConsoleOutput(ac, aid); err != nil {
		return err
	}

	if err := txs.insertHeaders(ac, aid); err != nil {
		return err
	}

	if err := txs.insertBody(ac, aid); err != nil {
		return err
	}

	if err := txs.insertTimings(ac, aid); err != nil {
		return err
	}

	if err := txs.insertPostdata(ac, aid); err != nil {
		return err
	}

	if err := txs.insertSecurityDetails(ac, aid); err != nil {
		return err
	}

	tx.Commit()

	return nil
}

type txStore struct {
	tx   *sql.Tx
	path string
}

func (s txStore) insertActionFact(ac kraaler.BrowserAction) (int64, error) {
	ids := map[string]int64{}
	for id, f := range map[string]func(kraaler.BrowserAction) (int64, error){
		"host_id":      s.getHostId,
		"method_id":    s.getMethodId,
		"initiator_id": s.getInitiatorId,
		"scheme_id":    s.getSchemeId,
		"path_id":      s.getPathId,
	} {
		numId, err := f(ac)
		if err != nil {
			return 0, err
		}

		ids[id] = numId
	}

	insertq := insertQuery("fact_actions",
		"parent_id",
		"method_id",
		"scheme_id",
		"path_id",
		"host_id",
		"status_code",
	)
	stmt, err := s.tx.Prepare(insertq)
	if err != nil {
		return 0, err
	}

	if _, err := stmt.Exec(
		nil,
		ids["method_id"],
		ids["scheme_id"],
		ids["path_id"],
		ids["host_id"],
		ac.Response.StatusCode,
	); err != nil {
		return 0, err
	}

	var id int64
	err = s.tx.QueryRow("select last_insert_rowid()").Scan(&id)
	if err != nil {
		return 0, err
	}

	return id, nil
}

func (s txStore) retriveFunc(table string, fields ...string) func(...interface{}) (int64, error) {
	var conds string
	for _, f := range fields {
		conds += fmt.Sprintf("%s = ? and ", f)
	}

	conds = conds[0 : len(conds)-5]
	sQuery := fmt.Sprintf("SELECT id FROM %s WHERE %s LIMIT 1", table, conds)

	return func(items ...interface{}) (int64, error) {
		var id int64
		err := s.tx.QueryRow(
			sQuery,
			items...,
		).Scan(&id)
		if err != nil && err != sql.ErrNoRows {
			return 0, err
		}

		if id > 0 {
			return id, nil
		}

		stmt, err := s.tx.Prepare(insertQuery(table, fields...))
		if err != nil {
			return 0, err
		}

		if _, err := stmt.Exec(
			items...,
		); err != nil {
			return 0, err
		}

		err = s.tx.QueryRow("select last_insert_rowid()").Scan(&id)
		if err != nil {
			return 0, err
		}

		return id, nil
	}
}

func (s txStore) getHostId(ac kraaler.BrowserAction) (int64, error) {
	u, err := url.Parse(ac.Request.URL)
	if err != nil {
		return 0, err
	}

	parts := strings.Split(u.Host, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("malformed domain")
	}
	tld := parts[len(parts)-1]

	fetch := s.retriveFunc("dim_hosts", "domain", "tld", "ipv4")
	return fetch(u.Host, tld, ac.HostIP)
}

func (s txStore) getPathId(ac kraaler.BrowserAction) (int64, error) {
	u, err := url.Parse(ac.Request.URL)
	if err != nil {
		return 0, err
	}

	u.Scheme = ""
	u.Host = ""
	u.User = nil

	fetch := s.retriveFunc("dim_paths", "path")
	return fetch(u.String())
}

func (s txStore) getSchemeId(ac kraaler.BrowserAction) (int64, error) {
	fetch := s.retriveFunc("dim_schemes", "scheme", "protocol_id")
	u, err := url.Parse(ac.Request.URL)
	if err != nil {
		return 0, err
	}

	fetchProto := s.retriveFunc("dim_protocols", "protocol")
	protoId, err := fetchProto(ac.Protocol)
	if err != nil {
		return 0, err
	}

	return fetch(u.Scheme, protoId)
}

func (s txStore) getMethodId(ac kraaler.BrowserAction) (int64, error) {
	fetch := s.retriveFunc("dim_methods", "method")
	return fetch(ac.Request.Method)
}

func (s txStore) getInitiatorId(ac kraaler.BrowserAction) (int64, error) {
	fetch := s.retriveFunc("dim_initiators", "name")

	return fetch(ac.Initiator)
}

func (s txStore) getErrorId(ac kraaler.BrowserAction) (int64, error) {
	if ac.ResponseError == nil {
		return 0, fmt.Errorf("response error is empty")
	}

	fetch := s.retriveFunc("dim_errors", "error")
	return fetch(*ac.ResponseError)
}

func (s txStore) getKeyvalueId(key, value string) (int64, error) {
	fetchKeyId := s.retriveFunc("dim_header_keys", "key")

	keyId, err := fetchKeyId(key)
	if err != nil {
		return 0, err
	}

	fetchKV := s.retriveFunc("dim_header_keyvalues", "key_id", "value")
	return fetchKV(keyId, value)
}

func (s txStore) insertBody(ac kraaler.BrowserAction, aid int64) error {
	u, err := url.Parse(ac.Request.URL)
	if err != nil {
		return err
	}

	folder := filepath.Join(s.path, "bodies", strings.ToLower(u.Host))
	if err := os.MkdirAll(folder, os.ModePerm); err != nil {
		return err
	}

	fetchMime := s.retriveFunc("dim_mime_types", "mime_type")
	mimeType := ac.Response.MimeType
	mimeId, err := fetchMime(mimeType)
	if err != nil {
		return err
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
		mimeId,
		checksum,
	); err != nil {
		return err
	}

	return nil
}

func (s txStore) insertHeaders(ac kraaler.BrowserAction, aid int64) error {
	stmt, err := s.tx.Prepare("insert into fact_request_headers(action_id, header_keyvalue_id) values(?,?)")
	if err != nil {
		return err
	}

	for k, v := range ac.Request.Headers {
		hid, err := s.getKeyvalueId(k, v)
		if err != nil {
			return err
		}

		if _, err := stmt.Exec(
			aid,
			hid,
		); err != nil {
			return err
		}
	}

	if ac.Response == nil {
		return nil
	}

	stmt, err = s.tx.Prepare("insert into fact_response_headers(action_id, header_keyvalue_id) values(?,?)")
	if err != nil {
		return err
	}

	for k, v := range ac.Response.Headers {
		hid, err := s.getKeyvalueId(k, v)
		if err != nil {
			return err
		}

		if _, err := stmt.Exec(
			aid,
			hid,
		); err != nil {
			return err
		}
	}

	return nil
}

func (s txStore) insertConsoleOutput(ac kraaler.BrowserAction, aid int64) error {
	stmt, err := s.tx.Prepare("insert into fact_console_output(action_id, seq, message) values(?,?,?)")
	if err != nil {
		return err
	}

	for i, msg := range ac.Console {
		seq := i + 1
		if _, err := stmt.Exec(
			aid,
			seq,
			msg,
		); err != nil {
			return err
		}
	}

	return nil
}

func (s txStore) insertTimings(ac kraaler.BrowserAction, aid int64) error {
	q := insertQuery("fact_action_timings",
		"action_id",
		"start_datetime",
		"end_datetime",
		"connect_start_time",
		"connect_end_time",
		"send_start_time",
		"send_end_time",
		"push_start_time",
		"push_end_time",
	)
	stmt, err := s.tx.Prepare(q)
	if err != nil {
		return err
	}

	ac.Timings.Align()

	if _, err := stmt.Exec(
		aid,
		ac.StartTime,
		ac.EndTime,
		ac.Timings.ConnectStartTime,
		ac.Timings.ConnectEndTime,
		ac.Timings.SendStartTime,
		ac.Timings.SendEndTime,
		ac.Timings.PushStartTime,
		ac.Timings.PushEndTime,
	); err != nil {
		return err
	}

	return nil
}

func (s txStore) insertPostData(ac kraaler.BrowserAction, aid int64) error {
	q := insertQuery("fact_post_data",
		"action_id",
		"data",
	)
	stmt, err := s.tx.Prepare(q)
	if err != nil {
		return err
	}

	if _, err := stmt.Exec(
		aid,
		ac.Request.PostData,
	); err != nil {
		return err
	}

	return nil
}

func (s txStore) insertSecurityDetails(ac kraaler.BrowserAction, aid int64) error {
	fetchProto := s.retriveFunc("dim_protocols", "protocol")
	pid, err := fetchProto(ac.SecurityDetails.Protocol)
	if err != nil {
		return err
	}

	fetchKeyX := s.retriveFunc("dim_key_exchanges", "key_exchange")
	kxid, err := fetchKeyX(ac.SecurityDetails.KeyExchange)
	if err != nil {
		return err
	}

	fetchCiph := s.retriveFunc("dim_ciphers", "cipher")
	cid, err := fetchCiph(ac.SecurityDetails.Cipher)
	if err != nil {
		return err
	}

	fetchIss := s.retriveFunc("dim_issuers", "issuer")
	iid, err := fetchIss(ac.SecurityDetails.Issuer)
	if err != nil {
		return err
	}

	fetchSanList := s.retriveFunc("dim_san_lists", "list")
	sanList := sort.StringSlice(ac.SecurityDetails.SanList)
	sanList.Sort()
	slid, err := fetchSanList(strings.Join(sanList, "|"))
	if err != nil {
		return err
	}

	q := insertQuery("fact_security_details",
		"action_id",
		"protocol_id",
		"key_exchange_id",
		"issuer_id",
		"cipher_id",
		"san_list_id",
		"subject_name",
		"valid_from",
		"valid_to",
	)
	stmt, err := s.tx.Prepare(q)
	if err != nil {
		return err
	}

	if _, err := stmt.Exec(
		aid,
		pid,
		kxid,
		iid,
		cid,
		slid,
		ac.SecurityDetails.SubjectName,
		ac.SecurityDetails.ValidFrom,
		ac.SecurityDetails.ValidTo,
	); err != nil {
		return err
	}

	return nil
}

func insertQuery(table string, fields ...string) string {
	var qmarks string
	for range fields {
		qmarks += "?,"
	}
	qmarks = qmarks[0 : len(qmarks)-1]

	return fmt.Sprintf("insert into %s(%s) values(%s)", table, strings.Join(fields, ","), qmarks)
}

func (s txStore) insertScreenshot(ac kraaler.BrowserAction, aid int64) error {
	u, err := url.Parse(ac.Request.URL)
	if err != nil {
		return err
	}

	folder := filepath.Join(s.path, "screenshots", strings.ToLower(u.Host))
	if err := os.MkdirAll(folder, os.ModePerm); err != nil {
		return err
	}

	fetchRes := s.retriveFunc("dim_resolutions", "resolution")
	resId, err := fetchRes(ac.Resolution)
	if err != nil {
		return err
	}

	q := insertQuery("fact_screenshots",
		"action_id",
		"resolution_id",
		"is_mobile",
		"path",
	)
	stmt, err := s.tx.Prepare(q)
	if err != nil {
		return err
	}

	file := uuid.New().String() + ".png"
	path := filepath.Join(folder, file)
	if _, err := stmt.Exec(
		aid,
		resId,
		false, // fix this to not be hardcoded
		path,
	); err != nil {
		return err
	}

	return nil
}
