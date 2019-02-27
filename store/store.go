package store

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aau-network-security/kraaler"
	_ "github.com/mattn/go-sqlite3"
	cache "github.com/patrickmn/go-cache"
)

type sessStoreFunc func(*sql.Tx, *kraaler.CrawlSession) (interface{}, error)
type actionStoreFunc func(*sql.Tx, *kraaler.CrawlAction) (interface{}, error)

type Store struct {
	db          *sql.DB
	path        string
	screenStore *ScreenshotStore
	sessStore   *SessionStore
	acStore     *ActionStore
}

func NewStore(dbpath string, path string) (*SessionStore, error) {
	// var performInit bool
	// if _, err := os.Stat(dbpath); os.IsNotExist(err) {
	// 	performInit = true
	// }

	// db, err := sql.Open("sqlite3", dbpath)
	// if err != nil {
	// 	return nil, err
	// }

	// if performInit {
	// 	if _, err := db.Exec(initSql); err != nil {
	// 		return nil, err
	// 	}
	// }

	// return &SessionStore{
	// 	db:            db,
	// 	path:          path,
	// 	dimResolution: NewIDStore("dim_resolutions", cache.New(15*time.Minute, 15*time.Minute), "resolution"),
	// 	dimMethod:     NewIDStore("dim_methods", cache.New(15*time.Minute, 15*time.Minute), "method"),
	// 	dimProto:      NewIDStore("dim_protocols", cache.New(15*time.Minute, 15*time.Minute), "protocol"),
	// 	dimHosts:      NewIDStore("dim_hosts", cache.New(time.Minute, 10*time.Minute), "domain", "tld", "ipv4"),
	// 	dimInitiators: NewIDStore("dim_initiators", cache.New(15*time.Minute, 15*time.Minute), "initiator"),
	// 	dimErrors:     NewIDStore("dim_errors", nil, "error"),
	// }, nil

	return nil, nil
}

type SessionStore struct {
	dimResolution *IDStore
}

func NewSessionStore(db *sql.DB) (*SessionStore, error) {
	if db != nil {
		if _, err := db.Exec(sessionSchema); err != nil {
			return nil, err
		}
	}

	return &SessionStore{
		dimResolution: NewIDStore("dim_resolutions", cache.New(15*time.Minute, 15*time.Minute), "resolution"),
	}, nil
}

func (ss *SessionStore) Save(tx *sql.Tx, sess *kraaler.CrawlSession) (int64, error) {
	ins := WarehouseInserter{
		"resolution_id": func(tx *sql.Tx) (interface{}, error) {
			id, err := ss.dimResolution.Get(tx, sess.Resolution)
			if err != nil {
				return nil, err
			}

			return id, nil
		},
		"start_time": func(tx *sql.Tx) (interface{}, error) {
			return sess.StartTime.Unix(), nil
		},
		"loaded_time": func(tx *sql.Tx) (interface{}, error) {
			return sess.LoadedTime.Unix(), nil
		},
		"terminated_time": func(tx *sql.Tx) (interface{}, error) {
			return sess.TerminatedTime.Unix(), nil
		},
		"amount_of_actions": func(tx *sql.Tx) (interface{}, error) {
			return len(sess.Actions), nil
		},
		"error": func(tx *sql.Tx) (interface{}, error) {
			return sess.Error, nil
		},
	}

	id, err := ins.Store(tx, "fact_sessions")
	if err != nil {
		return 0, err
	}

	return id, nil
}

type ConsoleStore struct{}

func NewConsoleStore(db *sql.DB) (*ConsoleStore, error) {
	if db != nil {
		if _, err := db.Exec(consoleSchema); err != nil {
			return nil, err
		}
	}

	return &ConsoleStore{}, nil
}

func (cs *ConsoleStore) Save(tx *sql.Tx, id int64, console []string) error {
	cins := inserter{tx, GetInsertQuery("fact_console_output", "session_id", "seq", "message"), true}
	for i, msg := range console {
		if _, err := cins.Insert(id, i+1, msg); err != nil {
			return err
		}
	}

	return nil
}

type ScreenStore struct {
	ssStore *ScreenshotStore
}

func NewScreenStore(db *sql.DB, ss *ScreenshotStore) (*ScreenStore, error) {
	if db != nil {
		if _, err := db.Exec(screenshotSchema); err != nil {
			return nil, err
		}
	}

	return &ScreenStore{ss}, nil
}

func (ss *ScreenStore) Save(tx *sql.Tx, id int64, urlstr string, screenshots []*kraaler.BrowserScreenshot) error {
	sins := inserter{tx, GetInsertQuery("fact_screenshots", "session_id", "time_taken", "path"), true}
	u, err := url.Parse(urlstr)
	if err != nil {
		return err
	}

	for _, screen := range screenshots {
		path, err := ss.ssStore.Store(screen, u.Host)
		if err != nil {
			return err
		}

		if _, err := sins.Insert(id, screen.Taken.Unix(), path); err != nil {
			return err
		}
	}

	return nil
}

type ActionStore struct {
	headerStore         *HeaderStore
	urlStore            *UrlStore
	bodyStore           *BodyStore
	securityStore       *SecurityStore
	postDataStore       *PostDataStore
	initiatorStackStore *InitiatorStackStore

	dimMethod     *IDStore
	dimProto      *IDStore
	dimHosts      *IDStore
	dimInitiators *IDStore
	dimErrors     *IDStore
}

func NewActionStore(db *sql.DB, fs *FileStore) (*ActionStore, error) {
	if _, err := db.Exec(actionSchema); err != nil {
		return nil, err
	}

	hs, err := NewHeaderStore(db)
	if err != nil {
		return nil, err
	}

	us, err := NewUrlStore(db)
	if err != nil {
		return nil, err
	}

	bs, err := NewBodyStore(db, fs)
	if err != nil {
		return nil, err
	}

	pds, err := NewPostDataStore(db)
	if err != nil {
		return nil, err
	}

	iss, err := NewInitiatorStackStore(db)
	if err != nil {
		return nil, err
	}

	ss, err := NewSecurityStore(db)
	if err != nil {
		return nil, err
	}

	return &ActionStore{
		headerStore:         hs,
		urlStore:            us,
		bodyStore:           bs,
		securityStore:       ss,
		postDataStore:       pds,
		initiatorStackStore: iss,

		dimMethod:     NewIDStore("dim_methods", cache.New(15*time.Minute, 15*time.Minute), "method"),
		dimProto:      NewIDStore("dim_protocols", cache.New(15*time.Minute, 15*time.Minute), "protocol"),
		dimHosts:      NewIDStore("dim_hosts", cache.New(time.Minute, 10*time.Minute), "domain", "tld", "ipv4"),
		dimInitiators: NewIDStore("dim_initiators", cache.New(15*time.Minute, 15*time.Minute), "initiator"),
		dimErrors:     NewIDStore("dim_errors", nil, "error"),
	}, nil
}

func (as *ActionStore) Save(tx *sql.Tx, id int64, actions []*kraaler.CrawlAction) error {
	acids := map[*kraaler.CrawlAction]int64{}
	actionFuncs := map[string]func(*sql.Tx, *kraaler.CrawlAction) (interface{}, error){
		"session_id": func(tx *sql.Tx, a *kraaler.CrawlAction) (interface{}, error) {
			return id, nil
		},
		"method_id": func(tx *sql.Tx, a *kraaler.CrawlAction) (interface{}, error) {
			id, err := as.dimMethod.Get(tx, a.Request.Method)
			if err != nil {
				return nil, err
			}

			return id, nil
		},
		"protocol_id": func(tx *sql.Tx, a *kraaler.CrawlAction) (interface{}, error) {
			id, err := as.dimProto.Get(tx, a.Protocol)
			if err != nil {
				return nil, err
			}

			return id, nil
		},
		"host_id": func(tx *sql.Tx, a *kraaler.CrawlAction) (interface{}, error) {
			u, err := url.Parse(a.Request.URL)
			if err != nil {
				return nil, err
			}

			parts := strings.Split(u.Host, ".")
			if len(parts) < 2 {
				return nil, fmt.Errorf("malformed domain")
			}
			tld := parts[len(parts)-1]

			id, err := as.dimHosts.Get(tx, u.Host, tld, a.HostIP)
			if err != nil {
				return nil, err
			}

			return id, nil
		},
		"initiator_id": func(tx *sql.Tx, a *kraaler.CrawlAction) (interface{}, error) {
			id, err := as.dimInitiators.Get(tx, a.Initiator.Kind)
			if err != nil {
				return nil, err
			}

			return id, nil
		},
		"error_id": func(tx *sql.Tx, a *kraaler.CrawlAction) (interface{}, error) {
			if a.ResponseError == nil {
				return nil, nil
			}

			id, err := as.dimErrors.Get(tx, a.ResponseError)
			if err != nil {
				return nil, err
			}

			return id, nil
		},
		"parent_id": func(tx *sql.Tx, a *kraaler.CrawlAction) (interface{}, error) {
			if a.Parent != nil {
				return acids[a.Parent], nil
			}

			return nil, nil
		},
		"status_code": func(tx *sql.Tx, a *kraaler.CrawlAction) (interface{}, error) {
			if a.Response != nil {
				return a.Response.StatusCode, nil
			}

			return nil, nil
		},
	}

	wrap := func(f func(tx *sql.Tx, a *kraaler.CrawlAction) (interface{}, error), a *kraaler.CrawlAction) func(tx *sql.Tx) (interface{}, error) {
		return func(tx *sql.Tx) (interface{}, error) { return f(tx, a) }
	}
	for _, a := range actions {
		ins := WarehouseInserter{}
		for k, f := range actionFuncs {
			ins[k] = wrap(f, a)
		}

		id, err := ins.Store(tx, "fact_actions")
		if err != nil {
			return err
		}

		if a.Request.PostData != nil {
			if err := as.postDataStore.Save(tx, id, *a.Request.PostData); err != nil {
				return err
			}
		}

		if a.Initiator.Stack != nil {
			if err := as.initiatorStackStore.Save(tx, id, *a.Initiator.Stack); err != nil {
				return err
			}
		}

		if err := as.urlStore.Save(tx, id, a.Request.URL); err != nil {
			return err
		}

		for k, v := range a.Request.Headers {
			if err := as.headerStore.SaveRequest(tx, id, k, v); err != nil {
				return err
			}
		}

		if a.SecurityDetails != nil {
			if err := as.securityStore.Save(tx, id, *a.SecurityDetails); err != nil {
				return err
			}
		}

		if a.Response != nil {
			for k, v := range a.Response.Headers {
				if err := as.headerStore.SaveResponse(tx, id, k, v); err != nil {
					return err
				}
			}

			if err := as.bodyStore.Save(tx, id, *a.Response); err != nil {
				return err
			}
		}

		acids[a] = id
	}

	return nil
}

type UrlStore struct {
	dimScheme   *IDStore
	dimUser     *IDStore
	dimHost     *IDStore
	dimPath     *IDStore
	dimFragment *IDStore
	dimQuery    *IDStore
}

func NewUrlStore(db *sql.DB) (*UrlStore, error) {
	if db != nil {
		if _, err := db.Exec(urlSchema); err != nil {
			return nil, err
		}
	}

	return &UrlStore{
		dimScheme:   NewIDStore("dim_url_schemes", cache.New(15*time.Minute, 15*time.Minute), "scheme"),
		dimUser:     NewIDStore("dim_url_users", cache.New(15*time.Minute, 15*time.Minute), "user"),
		dimHost:     NewIDStore("dim_url_hosts", cache.New(time.Minute, time.Minute), "host"),
		dimPath:     NewIDStore("dim_url_paths", nil, "path"),
		dimFragment: NewIDStore("dim_url_fragments", nil, "fragment"),
		dimQuery:    NewIDStore("dim_url_raw_queries", nil, "query"),
	}, nil
}

func (us *UrlStore) Save(tx *sql.Tx, id int64, urlstr string) error {
	u, err := url.Parse(urlstr)
	if err != nil {
		return err
	}

	ins := WarehouseInserter{
		"action_id": func(tx *sql.Tx) (interface{}, error) {
			return id, nil
		},
		"scheme_id": func(tx *sql.Tx) (interface{}, error) {
			id, err := us.dimScheme.Get(tx, u.Scheme)
			if err != nil {
				return nil, err
			}
			return id, nil
		},
		"user_id": func(tx *sql.Tx) (interface{}, error) {
			if u.User == nil {
				return nil, nil
			}

			id, err := us.dimUser.Get(tx, u.User)
			if err != nil {
				return nil, err
			}
			return id, nil
		},
		"host_id": func(tx *sql.Tx) (interface{}, error) {
			id, err := us.dimHost.Get(tx, u.Host)
			if err != nil {
				return nil, err
			}
			return id, nil
		},
		"path_id": func(tx *sql.Tx) (interface{}, error) {
			id, err := us.dimPath.Get(tx, u.Path)
			if err != nil {
				return nil, err
			}
			return id, nil
		},
		"fragment_id": func(tx *sql.Tx) (interface{}, error) {
			if u.Fragment == "" {
				return nil, nil
			}

			id, err := us.dimFragment.Get(tx, u.Fragment)
			if err != nil {
				return nil, err
			}
			return id, nil
		},
		"raw_query_id": func(tx *sql.Tx) (interface{}, error) {
			if u.RawQuery == "" {
				return nil, nil
			}

			id, err := us.dimQuery.Get(tx, u.RawQuery)
			if err != nil {
				return nil, err
			}
			return id, nil
		},
		"url": func(tx *sql.Tx) (interface{}, error) {
			return urlstr, nil
		},
	}

	if _, err := ins.Store(tx, "fact_urls"); err != nil {
		return err
	}

	return nil
}

type HeaderStore struct {
	dimHeaderKey      *IDStore
	dimHeaderKeyValue *IDStore
}

func NewHeaderStore(db *sql.DB) (*HeaderStore, error) {
	if db != nil {
		if _, err := db.Exec(headerSchema); err != nil {
			return nil, err
		}
	}

	return &HeaderStore{
		dimHeaderKey:      NewIDStore("dim_header_keys", cache.New(30*time.Minute, 3*time.Minute), "key"),
		dimHeaderKeyValue: NewIDStore("dim_header_keyvalues", cache.New(5*time.Minute, time.Minute), "key_id", "value"),
	}, nil
}

func (hs *HeaderStore) saveHeader(tx *sql.Tx, id int64, key, value string, table string) error {
	ins := WarehouseInserter{
		"action_id": func(tx *sql.Tx) (interface{}, error) {
			return id, nil
		},
		"header_keyvalue_id": func(tx *sql.Tx) (interface{}, error) {
			kid, err := hs.dimHeaderKey.Get(tx, key)
			if err != nil {
				return nil, err
			}

			id, err := hs.dimHeaderKeyValue.Get(tx, kid, value)
			if err != nil {
				return nil, err
			}

			return id, nil
		},
	}

	if _, err := ins.Store(tx, table); err != nil {
		return err
	}

	return nil
}

func (hs *HeaderStore) SaveRequest(tx *sql.Tx, id int64, key, value string) error {
	return hs.saveHeader(tx, id, key, value, "fact_request_headers")
}

func (hs *HeaderStore) SaveResponse(tx *sql.Tx, id int64, key, value string) error {
	return hs.saveHeader(tx, id, key, value, "fact_response_headers")
}

type SecurityStore struct {
	dimProtocol    *IDStore
	dimIssuer      *IDStore
	dimKeyExchange *IDStore
	dimCipher      *IDStore
	dimSanList     *IDStore
}

func NewSecurityStore(db *sql.DB) (*SecurityStore, error) {
	if db != nil {
		if _, err := db.Exec(securitySchema); err != nil {
			return nil, err
		}
	}

	return &SecurityStore{
		dimProtocol:    NewIDStore("dim_protocols", cache.New(15*time.Minute, 5*time.Minute), "protocol"),
		dimIssuer:      NewIDStore("dim_issuers", cache.New(time.Minute, time.Minute), "issuer"),
		dimKeyExchange: NewIDStore("dim_key_exchanges", cache.New(5*time.Minute, time.Minute), "key_exchange"),
		dimCipher:      NewIDStore("dim_ciphers", cache.New(5*time.Minute, time.Minute), "cipher"),
		dimSanList:     NewIDStore("dim_san_lists", nil, "list"),
	}, nil
}

func (ss *SecurityStore) Save(tx *sql.Tx, id int64, sd kraaler.BrowserSecurityDetails) error {
	get := func(s *IDStore, i interface{}) func(tx *sql.Tx) (interface{}, error) {
		return func(tx *sql.Tx) (interface{}, error) {
			id, err := s.Get(tx, i)
			if err != nil {
				return nil, err
			}
			return id, nil
		}
	}
	ins := WarehouseInserter{
		"action_id": func(tx *sql.Tx) (interface{}, error) {
			return id, nil
		},
		"protocol_id":     get(ss.dimProtocol, sd.Protocol),
		"key_exchange_id": get(ss.dimKeyExchange, sd.KeyExchange),
		"cipher_id":       get(ss.dimCipher, sd.Cipher),
		"issuer_id":       get(ss.dimIssuer, sd.Issuer),
		"san_list_id":     get(ss.dimSanList, strings.Join(sd.SanList, ",")),
		"subject_name": func(tx *sql.Tx) (interface{}, error) {
			return sd.SubjectName, nil
		},
		"valid_from": func(tx *sql.Tx) (interface{}, error) {
			return sd.ValidFrom.Unix(), nil
		},
		"valid_to": func(tx *sql.Tx) (interface{}, error) {
			return sd.ValidTo.Unix(), nil
		},
	}

	if _, err := ins.Store(tx, "fact_security_details"); err != nil {
		return err
	}

	return nil
}

type BodyStore struct {
	fs      *FileStore
	dimMime *IDStore
}

func NewBodyStore(db *sql.DB, fs *FileStore) (*BodyStore, error) {
	if db != nil {
		if _, err := db.Exec(bodySchema); err != nil {
			return nil, err
		}
	}

	return &BodyStore{
		fs:      fs,
		dimMime: NewIDStore("dim_mime_types", cache.New(10*time.Minute, time.Minute), "mime_type"),
	}, nil
}

func (ss *BodyStore) Save(tx *sql.Tx, id int64, resp kraaler.BrowserResponse) error {
	get := func(s *IDStore, i interface{}) func(tx *sql.Tx) (interface{}, error) {
		return func(tx *sql.Tx) (interface{}, error) {
			id, err := s.Get(tx, i)
			if err != nil {
				return nil, err
			}
			return id, nil
		}
	}

	sf, err := ss.fs.Store(resp.Body)
	if err != nil && err != NotAllowedMimeErr {
		return err
	}

	ins := WarehouseInserter{
		"action_id": func(tx *sql.Tx) (interface{}, error) {
			return id, nil
		},
		"browser_mime_id": get(ss.dimMime, resp.MimeType),
		"determined_mime_id": func(tx *sql.Tx) (interface{}, error) {
			return sf.MimeType, nil
		},
		"path": func(tx *sql.Tx) (interface{}, error) {
			if sf.Path == "" {
				return nil, nil
			}
			return sf.Path, nil
		},
		"hash256": func(tx *sql.Tx) (interface{}, error) {
			return sf.Hash, nil
		},
		"org_size": func(tx *sql.Tx) (interface{}, error) {
			return sf.OrgSize, nil
		},
		"comp_size": func(tx *sql.Tx) (interface{}, error) {
			if sf.CompSize == 0 {
				return nil, nil
			}
			return sf.CompSize, nil
		},
	}

	if _, err := ins.Store(tx, "fact_bodies"); err != nil {
		return err
	}

	return nil
}

type PostDataStore struct{}

func NewPostDataStore(db *sql.DB) (*PostDataStore, error) {
	if db != nil {
		if _, err := db.Exec(postDataSchema); err != nil {
			return nil, err
		}
	}

	return &PostDataStore{}, nil
}

func (ps *PostDataStore) Save(tx *sql.Tx, id int64, data string) error {
	ins := WarehouseInserter{
		"action_id": func(tx *sql.Tx) (interface{}, error) {
			return id, nil
		},
		"data": func(tx *sql.Tx) (interface{}, error) {
			return data, nil
		},
	}

	if _, err := ins.Store(tx, "fact_post_data"); err != nil {
		return err
	}

	return nil
}

type InitiatorStackStore struct{}

func NewInitiatorStackStore(db *sql.DB) (*InitiatorStackStore, error) {
	if db != nil {
		if _, err := db.Exec(initiatorStackSchema); err != nil {
			return nil, err
		}
	}

	return &InitiatorStackStore{}, nil
}

func (is *InitiatorStackStore) Save(tx *sql.Tx, id int64, cf kraaler.CallFrame) error {
	ins := WarehouseInserter{
		"action_id": func(tx *sql.Tx) (interface{}, error) {
			return id, nil
		},
		"col": func(tx *sql.Tx) (interface{}, error) {
			return cf.Column, nil
		},
		"line": func(tx *sql.Tx) (interface{}, error) {
			return cf.LineNumber, nil
		},
		"func": func(tx *sql.Tx) (interface{}, error) {
			return cf.Function, nil
		},
	}

	if _, err := ins.Store(tx, "fact_initiator_stack"); err != nil {
		return err
	}

	return nil
}

func GetInsertQuery(table string, fields ...string) string {
	var qmarks string
	for range fields {
		qmarks += "?,"
	}
	qmarks = qmarks[0 : len(qmarks)-1]
	return fmt.Sprintf("INSERT INTO %s(%s) VALUES(%s)", table, strings.Join(fields, ","), qmarks)
}

type WarehouseInserter map[string]func(tx *sql.Tx) (interface{}, error)

func (m WarehouseInserter) Add(s string, i interface{}) {
	m[s] = func(*sql.Tx) (interface{}, error) { return i, nil }
}

func (m WarehouseInserter) Store(tx *sql.Tx, table string) (int64, error) {
	var fields []string
	var values []interface{}
	for f, get := range m {
		v, err := get(tx)
		if err != nil {
			return 0, err
		}

		values = append(values, v)
		fields = append(fields, f)
	}

	return inserter{tx: tx, query: GetInsertQuery(table, fields...)}.Insert(values...)
}

type IDStore struct {
	getQ    string
	insertQ string
	cache   *cache.Cache
}

func NewIDStore(table string, cache *cache.Cache, fields ...string) *IDStore {
	var conds string
	for _, f := range fields {
		conds += fmt.Sprintf("%s = ? and ", f)
	}

	conds = conds[0 : len(conds)-5]
	get := fmt.Sprintf("SELECT id FROM %s WHERE %s LIMIT 1", table, conds)

	return &IDStore{
		getQ:    get,
		insertQ: GetInsertQuery(table, fields...),
		cache:   cache,
	}
}

func (is *IDStore) Get(tx *sql.Tx, items ...interface{}) (int64, error) {
	key := fmt.Sprintf("%v", items)
	if is.cache != nil {
		if p, ok := is.cache.Get(key); ok {
			if id, ok := p.(*int64); ok {
				return *id, nil
			}
		}
	}

	foundId := func(id int64) (int64, error) {
		if is.cache != nil {
			is.cache.Set(key, &id, cache.DefaultExpiration)
		}
		return id, nil
	}

	var id int64
	err := tx.QueryRow(
		is.getQ,
		items...,
	).Scan(&id)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}

	if id > 0 {
		return foundId(id)
	}

	id, err = inserter{tx: tx, query: is.insertQ}.Insert(items...)
	if err != nil {
		return 0, err
	}

	return foundId(id)
}

type inserter struct {
	tx     *sql.Tx
	query  string
	skipId bool
}

func (i inserter) Insert(items ...interface{}) (int64, error) {
	stmt, err := i.tx.Prepare(i.query)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	if _, err := stmt.Exec(
		items...,
	); err != nil {
		return 0, err
	}

	if i.skipId {
		return 0, nil
	}

	var id int64
	err = i.tx.QueryRow("select last_insert_rowid()").Scan(&id)
	if err != nil {
		return 0, err
	}

	return id, nil
}
