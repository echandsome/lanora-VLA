// Package winsvc runs the Lanora client as a Windows service and installs
// it.
//
// The service hosts the network engine. Running there, rather than in the
// window the user sees, has three effects: no elevation prompt is needed to
// use Lanora after it is installed; the room connection survives the window
// being closed; and the engine's sockets are out of reach of socket-layer
// hooks that other software injects into ordinary programs but that Windows
// does not load into services.
package winsvc

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"

	"lanora/internal/client/daemon"
	"lanora/internal/client/ipc"
	"lanora/internal/client/netcfg"
	"lanora/internal/client/settings"
	"lanora/internal/version"
)

// Service identity.
const (
	ServiceName = "Lanora"
	DisplayName = "Lanora Virtual LAN"
	Description = "Connects this computer to Lanora virtual LAN rooms. If this service is stopped, Lanora cannot connect."
)

// Power events delivered to services (winuser.h).
const (
	pbtResumeSuspend   = 0x7
	pbtResumeAutomatic = 0x12
)

// IsService reports whether this process was started by the service
// control manager.
func IsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// Run runs the service until Windows stops it.
func Run() error { return svc.Run(ServiceName, handler{}) }

type handler struct{}

func (handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	dir, err := settings.DefaultDir()
	if err != nil {
		return false, 1
	}
	os.MkdirAll(dir, 0o755)
	logger, closeLog := openLog(filepath.Join(dir, "service.log"))
	defer closeLog()
	logger.Info("Lanora service starting", "version", version.Version)
	netcfg.LogDriverMessages(logger)

	store, err := settings.Open(dir)
	if err != nil {
		logger.Error("cannot open the settings", "err", err)
		return false, 2
	}
	listener, err := ipc.Listen()
	if err != nil {
		logger.Error("cannot open the local pipe", "err", err)
		return false, 3
	}
	d := daemon.New(daemon.Options{
		Store:       store,
		OpenAdapter: netcfg.Open,
		Logger:      logger,
		Diagnostics: netcfg.Diagnostics,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx, listener) }()
	d.AutoConnect()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent}
	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.PowerEvent:
				// After sleep every path and NAT mapping is stale.
				if req.EventType == pbtResumeSuspend || req.EventType == pbtResumeAutomatic {
					d.Rebind()
				}
			case svc.Stop, svc.Shutdown:
				// Leaving the room removes the adapter, so a stop or a
				// Windows shutdown leaves nothing behind.
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-served
				logger.Info("Lanora service stopped")
				return false, 0
			}
		case err := <-served:
			logger.Error("the service loop ended unexpectedly", "err", err)
			return false, 4
		}
	}
}

// openLog opens the service's log file. The file is kept small: when it
// exceeds a couple of megabytes the previous contents move to ".old".
// NoteFailure records a failed installation or removal in install.log,
// next to the service's log. The message box that reports it can be closed
// unread; the file stays for whoever is asked to help.
func NoteFailure(action string, err error) {
	dir, dirErr := settings.DefaultDir()
	if dirErr != nil {
		return
	}
	os.MkdirAll(dir, 0o755)
	f, openErr := os.OpenFile(filepath.Join(dir, "install.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if openErr != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s Lanora %s: %s failed: %v\n", time.Now().UTC().Format(time.RFC3339), version.Version, action, err)
}

func openLog(path string) (*slog.Logger, func()) {
	if info, err := os.Stat(path); err == nil && info.Size() > 2<<20 {
		os.Remove(path + ".old")
		os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil)), func() {}
	}
	return slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelInfo})), func() { f.Close() }
}

// LogPath returns where the service writes its log.
func LogPath() string {
	dir, _ := settings.DefaultDir()
	return filepath.Join(dir, "service.log")
}

// State describes the installed service as far as an ordinary user can
// tell.
type State struct {
	Installed bool
	Running   bool
	Path      string // the program the service runs
}

// Query reports whether the service is installed and running. It needs no
// administrator rights.
func Query() State {
	var st State
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return st
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(ServiceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return st
	}
	defer windows.CloseServiceHandle(h)
	st.Installed = true
	var status windows.SERVICE_STATUS
	if windows.QueryServiceStatus(h, &status) == nil {
		st.Running = status.CurrentState == windows.SERVICE_RUNNING || status.CurrentState == windows.SERVICE_START_PENDING
	}
	// The configured program path is readable from the registry without
	// further rights.
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+ServiceName, registry.QUERY_VALUE); err == nil {
		if image, _, err := key.GetStringValue("ImagePath"); err == nil {
			st.Path = programOf(image)
		}
		key.Close()
	}
	return st
}

// programOf extracts the executable from a service command line such as
// `"C:\Program Files\Lanora\Lanora.exe" --service`.
func programOf(commandLine string) string {
	commandLine = strings.TrimSpace(commandLine)
	if rest, ok := strings.CutPrefix(commandLine, `"`); ok {
		if end := strings.Index(rest, `"`); end >= 0 {
			return rest[:end]
		}
		return rest
	}
	if i := strings.Index(commandLine, " "); i >= 0 {
		return commandLine[:i]
	}
	return commandLine
}

// InstallDir returns the directory Lanora installs itself into.
func InstallDir() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "Lanora")
}

// InstalledExe returns the path of the installed program.
func InstalledExe() string { return filepath.Join(InstallDir(), "Lanora.exe") }
