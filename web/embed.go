// Package web embeds the administrator dashboard so that the server ships
// as a single binary.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:admin
var files embed.FS

// Admin returns the dashboard's files rooted at its index.html.
func Admin() fs.FS {
	sub, err := fs.Sub(files, "admin")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	return sub
}
