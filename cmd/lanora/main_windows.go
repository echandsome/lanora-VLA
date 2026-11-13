// Command lanora is the Lanora app for Windows. One executable plays every
// part, chosen by how it is started:
//
//	Lanora.exe              the window (and notification-area icon)
//	Lanora.exe --tray       the same, starting in the notification area
//	Lanora.exe --service    the background service (started by Windows)
//	Lanora.exe --install    install or update the service (needs elevation)
//	Lanora.exe --uninstall  remove Lanora (needs elevation)
package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"fyne.io/systray"
	"gioui.org/app"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"lanora/internal/client/ipc"
	"lanora/internal/client/ui"
	"lanora/internal/client/winsvc"
	"lanora/internal/version"
)

//go:embed icon.ico
var trayIcon []byte

// showEvent is how a second copy of the window asks the first to come to
// the front instead of opening another.
const showEvent = `Local\LanoraShowWindow`

func main() {
	arg := ""
	if len(os.Args) > 1 {
		arg = os.Args[1]
	}
	// Windows starts the service with "--service" (that is how it is
	// registered). The argument decides, not a guess about who started the
	// process; a person who types it gets an explanation instead.
	if arg == "--service" || winsvc.IsService() {
		err := winsvc.Run()
		if errors.Is(err, windows.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
			winsvc.MessageBox("Lanora", "This option is used by Windows to start the Lanora service. To use Lanora, start it without options.", false)
			return
		}
		if err != nil {
			os.Exit(1)
		}
		return
	}
	switch arg {
	case "--install":
		if err := winsvc.Install(); err != nil {
			winsvc.NoteFailure("installation", err)
			winsvc.MessageBox("Lanora", "Lanora could not be installed.\n\n"+err.Error(), true)
			os.Exit(1)
		}
	case "--uninstall":
		if err := winsvc.Uninstall(false); err != nil {
			winsvc.NoteFailure("removal", err)
			winsvc.MessageBox("Lanora", "Lanora could not be removed completely.\n\n"+err.Error(), true)
			os.Exit(1)
		}
		winsvc.MessageBox("Lanora", "Lanora was removed from this computer.", false)
	case "--version":
		winsvc.MessageBox("Lanora", "Lanora "+version.Version, false)
	default:
		runWindow(arg == "--tray")
	}
}

func runWindow(hidden bool) {
	// Only one window per user session: a second start brings the first
	// one forward.
	name, _ := windows.UTF16PtrFromString(showEvent)
	event, err := windows.CreateEvent(nil, 0, 0, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.SetEvent(event)
		return
	}

	a := ui.New(context.Background(), ui.Platform{
		ServiceState: func() (bool, bool) {
			st := winsvc.Query()
			return st.Installed, st.Running
		},
		InstallService:   installService,
		UninstallService: uninstall,
		StartAtSignIn:    winsvc.StartWithWindows,
		SetStartAtSignIn: winsvc.SetStartWithWindows,
		OpenLogFolder: func() {
			exec.Command("explorer.exe", "/select,"+winsvc.LogPath()).Start()
		},
		Dark: appsUseDarkTheme(),
		Tray: true,
		OnWindowError: func(err error) {
			winsvc.MessageBox("Lanora", "Lanora could not show its window.\n\n"+err.Error()+
				"\n\nA room you are connected to is not affected. Lanora stays in the notification area; "+
				"choose Quit there to close it.", true)
		},
	})

	if event != 0 {
		go func() {
			for {
				if r, _ := windows.WaitForSingleObject(event, windows.INFINITE); r != windows.WAIT_OBJECT_0 {
					return
				}
				a.ShowWindow()
			}
		}()
	}
	go runTray(a)
	if !hidden {
		a.ShowWindow()
	}
	app.Main()
}

// installService asks Windows for elevation, installs the service and waits
// for it to answer.
func installService() error {
	if err := winsvc.Elevate("--install"); err != nil {
		if errors.Is(err, winsvc.ErrDeclined) {
			return errors.New("Lanora cannot work without its service. Choose Install again and answer Yes when Windows asks.")
		}
		return fmt.Errorf("Windows could not start the installer: %w", err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		client, err := ipc.Dial(ctx)
		cancel()
		if err == nil {
			client.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("The Lanora service did not start. Its log may say why: " + winsvc.LogPath())
}

// uninstall removes Lanora and closes this window, whose program file is
// about to be deleted.
func uninstall() error {
	if err := winsvc.Elevate("--uninstall"); err != nil {
		if errors.Is(err, winsvc.ErrDeclined) {
			return errors.New("Lanora was not removed.")
		}
		return err
	}
	systray.Quit()
	os.Exit(0)
	return nil
}

// appsUseDarkTheme reports the user's Windows colour mode for apps.
func appsUseDarkTheme() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	light, _, err := key.GetIntegerValue("AppsUseLightTheme")
	return err == nil && light == 0
}

// runTray shows the notification-area icon and its menu.
func runTray(a *ui.App) {
	systray.Run(func() {
		systray.SetIcon(trayIcon)
		systray.SetTitle("Lanora")
		systray.SetTooltip("Lanora")
		systray.SetOnTapped(a.ShowWindow)
		open := systray.AddMenuItem("Open Lanora", "")
		leave := systray.AddMenuItem("Leave room", "")
		systray.AddSeparator()
		quit := systray.AddMenuItem("Quit", "Close the window and this icon. The room stays connected.")
		leave.Disable()

		go func() {
			for {
				select {
				case <-open.ClickedCh:
					a.ShowWindow()
				case <-leave.ClickedCh:
					a.Disconnect()
				case <-quit.ClickedCh:
					systray.Quit()
					os.Exit(0)
				}
			}
		}()
		// Keep the tooltip and menu in step with the connection.
		go func() {
			last := ""
			for {
				st, ok := a.Status()
				tip, inRoom := "Lanora", false
				switch {
				case !ok:
					tip = "Lanora: service not running"
				case st.Connection.Phase == ipc.PhaseConnected:
					tip, inRoom = "Lanora: "+st.Connection.RoomName+" ("+st.Connection.IP+")", true
				case st.Connection.Phase == ipc.PhaseReconnecting:
					tip, inRoom = "Lanora: reconnecting to "+st.Connection.RoomName, true
				case st.Connection.Phase == ipc.PhaseConnecting:
					tip, inRoom = "Lanora: connecting…", true
				default:
					tip = "Lanora: not in a room"
				}
				if tip != last {
					last = tip
					systray.SetTooltip(tip)
					if inRoom {
						leave.Enable()
					} else {
						leave.Disable()
					}
				}
				time.Sleep(time.Second)
			}
		}()
	}, func() {})
}
