//go:build !windows && !lanoraui

// Command lanora is the Lanora app for Windows. On other systems use
// lanora-cli; the window can be built there for development with
// "-tags lanoraui" (it needs the X11 and OpenGL ES development libraries).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "The Lanora window is built for Windows. On this system use lanora-cli.")
	os.Exit(2)
}
