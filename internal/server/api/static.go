package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// staticFiles serves the dashboard. The files are small and few, so they
// are read into memory once, each with a content hash for cache validation:
// browsers revalidate on every load and get a 304 unless the server was
// upgraded.
type staticFiles struct {
	files map[string]*staticFile
}

type staticFile struct {
	data  []byte
	etag  string
	ctype string
}

var contentTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".ico":   "image/x-icon",
	".json":  "application/json",
	".txt":   "text/plain; charset=utf-8",
	".woff2": "font/woff2",
}

func newStaticFiles(fsys fs.FS) (*staticFiles, error) {
	s := &staticFiles{files: make(map[string]*staticFile)}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		ctype, ok := contentTypes[strings.ToLower(path.Ext(p))]
		if !ok {
			ctype = "application/octet-stream"
		}
		sum := sha256.Sum256(data)
		s.files[p] = &staticFile{data: data, etag: `"` + hex.EncodeToString(sum[:12]) + `"`, ctype: ctype}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if s.files["index.html"] == nil {
		return nil, fs.ErrNotExist
	}
	return s, nil
}

func (s *staticFiles) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	f := s.files[name]
	if f == nil {
		// The dashboard is a single page; any path that is not a file (and
		// does not look like one) loads the application.
		if name != "" && path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		f = s.files["index.html"]
	}
	h := w.Header()
	h.Set("Content-Type", f.ctype)
	h.Set("ETag", f.etag)
	h.Set("Cache-Control", "no-cache")
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, f.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		return
	}
	w.Write(f.data)
}
