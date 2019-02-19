package store

import (
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	sendErr := func(err error) (StoredFile, error) { return StoredFile{}, err }

	mimeType := http.DetectContentType(raw)
	if !fs.mimeAllowed(mimeType) {
		return sendErr(NotAllowedMimeErr)
	}

	hash := fs.hasher.Sum(raw)
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

	_, err = w.Write(raw)
	if err != nil {
		return sendErr(err)
	}

	fi, err := f.Stat()
	if err != nil {
		return sendErr(err)
	}

	storedf := StoredFile{
		Path:     absFilepath,
		HashType: fs.hasher.Name(),
		OrgSize:  len(raw),
		CompSize: int(fi.Size()),
		MimeType: mimeType,
	}

	fs.known[hash] = storedf
	return storedf, nil
}
