package store

import (
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aau-network-security/kraaler"
)

var (
	NotAllowedMimeErr = errors.New("mime type is not allowed to be stored")
)

type Compressor interface {
	NewWriter(io.Writer) (io.Writer, error)
	Ext() string
}

type noComp struct{}

func (noComp) NewWriter(w io.Writer) (io.Writer, error) { return w, nil }
func (noComp) Ext() string                              { return "" }

var NoCompression = noComp{}

type gzipComp struct{}

func (gzipComp) NewWriter(w io.Writer) (io.Writer, error) {
	return gzip.NewWriterLevel(w, flate.BestCompression)
}
func (gzipComp) Ext() string { return ".gz" }

var GzipCompression = gzipComp{}

type Hasher interface {
	Sum([]byte) string
	Name() string
}

type hasher struct {
	sum  func([]byte) string
	name string
}

func (h *hasher) Sum(d []byte) string { return h.sum(d) }
func (h *hasher) Name() string        { return h.name }

var Sha256Hasher = &hasher{sum: func(d []byte) string { return fmt.Sprintf("%x", sha256.Sum256(d)) }, name: "sha256"}

type MimeValidator func(string) bool

func MimeIsText(mime string) bool { return strings.HasPrefix(mime, "text/") }
func MimeAny(string) bool         { return true }

type FileStoreOpt func(fs *FileStore)

func WithCompression(c Compressor) FileStoreOpt {
	return func(fs *FileStore) {
		fs.comp = c
	}
}

func WithMimeTypes(types ...MimeValidator) FileStoreOpt {
	return func(fs *FileStore) {
		fs.allowedMime = types
	}
}

type StoredFile struct {
	HashType string
	Hash     string
	Path     string
	OrgSize  int
	CompSize int
	MimeType string
}

type FileStore struct {
	comp        Compressor
	hasher      Hasher
	rootDir     string
	allowedMime []MimeValidator
	known       map[string]StoredFile
}

func NewFileStore(root string, opts ...FileStoreOpt) (*FileStore, error) {
	fs := FileStore{
		rootDir:     root,
		comp:        NoCompression,
		hasher:      Sha256Hasher,
		allowedMime: []MimeValidator{MimeAny},
		known:       map[string]StoredFile{},
	}

	for _, opt := range opts {
		opt(&fs)
	}

	return &fs, nil
}

func (fs *FileStore) mimeAllowed(mimeType string) bool {
	for _, f := range fs.allowedMime {
		if f(mimeType) {
			return true
		}
	}

	return false
}

func (fs *FileStore) Store(raw []byte) (StoredFile, error) {
	hash := fs.hasher.Sum(raw)
	mimeType := http.DetectContentType(raw)
	storedf := StoredFile{
		HashType: fs.hasher.Name(),
		Hash:     hash,
		OrgSize:  len(raw),
		MimeType: mimeType,
	}

	sendErr := func(err error) (StoredFile, error) {
		return storedf, err
	}

	if !fs.mimeAllowed(mimeType) {
		return sendErr(NotAllowedMimeErr)
	}

	if storedf, ok := fs.known[hash]; ok {
		return storedf, nil
	}

	filename := hash
	exts, _ := mime.ExtensionsByType(mimeType)
	if len(exts) > 0 {
		filename += exts[0]
	}

	filename += fs.comp.Ext()
	absFilepath := filepath.Join(fs.rootDir, filename)
	f, err := os.Create(absFilepath)
	if err != nil {
		return sendErr(err)
	}
	defer f.Close()

	w, err := fs.comp.NewWriter(f)
	if err != nil {
		return sendErr(err)
	}
	storedf.Path = absFilepath

	_, err = w.Write(raw)
	if err != nil {
		return sendErr(err)
	}

	fi, err := f.Stat()
	if err != nil {
		return sendErr(err)
	}
	storedf.CompSize = int(fi.Size())

	fs.known[hash] = storedf

	return storedf, nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func randStringOfLen(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

type ScreenshotStore struct {
	rootDir string
}

func NewScreenshotStore(dir string) *ScreenshotStore {
	return &ScreenshotStore{dir}
}

func (ss *ScreenshotStore) Store(s *kraaler.BrowserScreenshot, domain string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("screenshot cannot be nil")
	}

	filename := fmt.Sprintf(
		"%s-%s.%s",
		randStringOfLen(16),
		s.Resolution,
		strings.ToLower(s.Kind),
	)

	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	folder := filepath.Join(ss.rootDir, domain)
	if err := os.MkdirAll(folder, os.ModePerm); err != nil {
		return "", err
	}

	path := filepath.Join(folder, filename)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	_, err = f.Write(s.Screenshot)
	if err != nil {
		return "", err
	}

	return path, nil
}
