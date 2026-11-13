package ipc

import (
	"bufio"
	"context"
	"io"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// The rules for who may use the service's pipe must be ones Windows
// accepts; a mistake in them would only show when the service starts.
func TestPipeSecurityDescriptor(t *testing.T) {
	sd, err := winio.SddlToSecurityDescriptor(pipeSecurity)
	if err != nil || len(sd) == 0 {
		t.Fatalf("%q is not a valid security descriptor: %v", pipeSecurity, err)
	}
}

// The service's end and a window's end of the pipe, in one process.
func TestPipeRoundTrip(t *testing.T) {
	if windows.NewLazySystemDLL("ntdll.dll").NewProc("wine_get_version").Find() == nil {
		t.Skip("Wine does not support the way the pipe library creates a pipe")
	}
	l, err := Listen()
	if err != nil {
		t.Skipf("the pipe could not be created; is the Lanora service running? (%v)", err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c)
		c.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(c).ReadString('\n'); err != nil || line != "ping\n" {
		t.Fatalf("read %q, %v", line, err)
	}
}
