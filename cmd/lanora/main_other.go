//go:build !windows && lanoraui

// Command lanora is the Lanora window. On systems other than Windows it
// connects to a daemon started separately ("lanora-cli daemon"); this build
// exists mainly so the interface can be developed and checked on Linux.
package main

import (
	"context"
	"fmt"
	"os"

	"gioui.org/app"

	"lanora/internal/client/ui"
)

func main() {
	a := ui.New(context.Background(), ui.Platform{
		Dark:           os.Getenv("LANORA_THEME") == "dark",
		OnWindowClosed: func() { os.Exit(0) },
		OnWindowError: func(err error) {
			fmt.Fprintln(os.Stderr, "lanora: the window could not be shown:", err)
			os.Exit(1)
		},
	})
	a.ShowWindow()
	app.Main()
}
