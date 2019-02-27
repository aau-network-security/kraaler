package store

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aau-network-security/kraaler"
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

func TestScreenshotStore(t *testing.T) {
	tt := []struct {
		name       string
		domain     string
		screenshot kraaler.BrowserScreenshot
	}{
		{name: "basic", domain: "test.com", screenshot: kraaler.BrowserScreenshot{
			Screenshot: []byte(`not_image_bytes`),
			Resolution: kraaler.Resolution{800, 600},
			Kind:       "png",
			Taken:      time.Now(),
		}},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir("", fmt.Sprintf("kraaler-screenshotstore-test-%s", tc.name))
			if err != nil {
				t.Fatalf("error when creating temp dir: %s", err)
			}
			defer os.RemoveAll(dir)

			ss := NewScreenshotStore(dir)
			if _, err := ss.Store(&tc.screenshot, tc.domain); err != nil {
				t.Fatalf("error when storing in screenshot store: %s", err)
			}

			folders, err := ioutil.ReadDir(dir)
			if err != nil {
				t.Fatalf("unable to read temp dir: %s", err)
			}

			if len(folders) != 1 {
				t.Fatalf("expected one folder to be created")
			}

			domainDir := filepath.Join(dir, folders[0].Name())
			files, err := ioutil.ReadDir(domainDir)
			if err != nil {
				t.Fatalf("unable to read temp dir: %s", err)
			}

			if len(files) != 1 {
				t.Fatalf("expected one file to be created")
			}

			file := files[0].Name()
			if ext := "." + tc.screenshot.Kind; !strings.HasSuffix(file, ext) {
				t.Fatalf("expected file (%s) to have extension: %s", file, ext)
			}

			if res := tc.screenshot.Resolution.String(); !strings.Contains(file, res) {
				t.Fatalf("expected file (%s) to contain resolution: %s", file, res)
			}

			content, err := ioutil.ReadFile(filepath.Join(domainDir, file))
			if err != nil {
				t.Fatalf("unable to read screenshot file: %s", err)
			}

			if bytes.Compare(content, tc.screenshot.Screenshot) != 0 {
				t.Fatalf("expected file to be stored directly without modification")
			}
		})
	}
}
