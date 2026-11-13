//go:build windows || lanoraui

package ui

import (
	"context"
	"fmt"
	"image"
	"sync"
	"time"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"

	"lanora/internal/client/ipc"
)

// Platform supplies what differs between operating systems. Fields left nil
// hide the feature they stand for.
type Platform struct {
	// ServiceState reports whether the Lanora service is installed and
	// running. Nil where there is no service to install and the daemon is
	// started by other means.
	ServiceState func() (installed, running bool)
	// InstallService installs (or repairs) and starts the service. It may
	// block while the operating system asks for approval.
	InstallService func() error
	// UninstallService removes Lanora from the computer.
	UninstallService func() error

	// StartAtSignIn reads and SetStartAtSignIn changes whether the window
	// opens when the user signs in.
	StartAtSignIn    func() bool
	SetStartAtSignIn func(bool) error

	// OpenLogFolder shows the service's log in the file manager.
	OpenLogFolder func()

	// Dark selects the dark colours.
	Dark bool
	// Tray means the program stays in the notification area when its
	// window is closed, so minimising can close the window too.
	Tray bool
	// OnWindowClosed is called after the window has closed.
	OnWindowClosed func()
	// OnWindowError is called when the window could not be shown, or
	// stopped for a reason other than being closed. Without it nobody
	// would find out: the program has no console to complain on.
	OnWindowError func(error)
}

// App is the Lanora window application. It outlives any one window: the
// connection to the service is kept while the program sits in the
// notification area with no window open.
type App struct {
	platform Platform
	link     *link

	mu     sync.Mutex
	window *app.Window
}

// New returns an application following the service until ctx is cancelled.
func New(ctx context.Context, p Platform) *App {
	a := &App{platform: p}
	a.link = newLink(a.invalidate)
	go a.link.run(ctx)
	return a
}

func (a *App) invalidate() {
	a.mu.Lock()
	w := a.window
	a.mu.Unlock()
	if w != nil {
		w.Invalidate()
	}
}

// Status returns the service's latest status and whether the service is
// reachable.
func (a *App) Status() (ipc.Status, bool) {
	connected, _, st := a.link.snapshot()
	return st, connected
}

// Disconnect leaves the room.
func (a *App) Disconnect() {
	a.link.call(func(ctx context.Context, c *ipc.Client) error { return c.Disconnect(ctx) })
}

// ShowWindow opens the window, or brings it to the front if it is already
// open. It does not wait for the window to close.
func (a *App) ShowWindow() {
	a.mu.Lock()
	if w := a.window; w != nil {
		a.mu.Unlock()
		w.Perform(system.ActionRaise)
		return
	}
	w := new(app.Window)
	w.Option(app.Title("Lanora"), app.Size(400, 660), app.MinSize(360, 540))
	a.window = w
	a.mu.Unlock()

	go func() {
		err := a.runWindow(w)
		a.mu.Lock()
		a.window = nil
		a.mu.Unlock()
		if err != nil && a.platform.OnWindowError != nil {
			a.platform.OnWindowError(err)
		}
		if a.platform.OnWindowClosed != nil {
			a.platform.OnWindowClosed()
		}
	}()
}

// runWindow runs one window until it closes, and reports why if that was
// not the user's doing.
func (a *App) runWindow(w *app.Window) (err error) {
	defer func() {
		// The toolkit panics when the operating system will not create a
		// window at all (no usable graphics, for instance). The rest of the
		// program, and the room connection in the service, are unaffected.
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return a.windowLoop(w)
}

// windowLoop runs one window until it is closed. A closed window releases
// everything it drew with; while Lanora sits in the notification area it
// holds no window at all.
func (a *App) windowLoop(w *app.Window) error {
	v := newView(a, newTheme(a.platform.Dark))
	var ops op.Ops
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return e.Err
		case app.ConfigEvent:
			// With a notification-area icon to come back from, minimising
			// puts Lanora there instead of on the taskbar.
			if a.platform.Tray && e.Config.Mode == app.Minimized {
				w.Perform(system.ActionClose)
			}
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			v.layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}

// page is which screen the window shows on top of the connection state.
type page int

const (
	pageMain page = iota
	pageSettings
)

// view is the state of one open window.
type view struct {
	app *App
	th  *theme

	page    page
	results chan func() // outcomes of background requests, applied on the next frame

	// Join form.
	server, room, password, nickname *field
	remember                         widget.Bool
	join, cancel, leave              widget.Clickable
	prefilled                        bool
	busy                             bool
	formError                        string
	returnToPassword                 bool // focus the password when the form is next shown

	// Room.
	peers    widget.List
	copyIP   widget.Clickable
	peerRows map[string]*widget.Clickable

	// Settings.
	openSettings, back                              widget.Clickable
	settingsList                                    widget.List
	settingsServer                                  *field
	saveServer                                      widget.Clickable
	settingsFilled                                  bool
	autoConnect, lanPriority, privateNet, relayOnly widget.Bool
	startAtSignIn                                   widget.Bool
	copyDiagnostics, openLogs, uninstall            widget.Clickable
	uninstallArmed                                  time.Time
	settingsError                                   string
	pendingCopy                                     string // text to put on the clipboard on the next frame

	// Service set-up.
	install    widget.Clickable
	installing bool
	installErr string

	toast      string
	toastUntil time.Time
}

func newView(a *App, th *theme) *view {
	v := &view{
		app: a, th: th,
		results:        make(chan func(), 16),
		server:         newField("Server", "lan.example.com", false),
		room:           newField("Room ID", "7KQ-2MX-9DW", false),
		password:       newField("Password", "", true),
		nickname:       newField("Your name in the room", "", false),
		settingsServer: newField("Server address", "https://lan.example.com", false),
		peerRows:       make(map[string]*widget.Clickable),
	}
	v.peers.Axis = layout.Vertical
	v.settingsList.Axis = layout.Vertical
	return v
}

// run performs fn off the frame loop and applies done on the next frame.
func (v *view) run(fn func() error, done func(error)) {
	go func() {
		err := fn()
		v.results <- func() { done(err) }
		v.app.invalidate()
	}()
}

func (v *view) showToast(gtx C, msg string) {
	v.toast, v.toastUntil = msg, gtx.Now.Add(2*time.Second)
}

// layout draws one frame.
func (v *view) layout(gtx C) D {
	for {
		select {
		case apply := <-v.results:
			apply()
			continue
		default:
		}
		break
	}
	th := v.th
	fill(gtx, th.pal.Bg, gtx.Constraints.Max, 0)

	connected, tried, st := v.app.link.snapshot()
	if v.openSettings.Clicked(gtx) {
		v.page, v.settingsFilled, v.settingsError = pageSettings, false, ""
	}
	if v.back.Clicked(gtx) {
		v.page = pageMain
	}

	body := func(gtx C) D {
		switch {
		case !connected:
			return v.layoutService(gtx, tried)
		case v.page == pageSettings:
			return v.layoutSettings(gtx, st)
		case st.Connection.Phase == ipc.PhaseConnecting:
			return v.layoutConnecting(gtx, st)
		case st.Connection.Phase == ipc.PhaseConnected || st.Connection.Phase == ipc.PhaseReconnecting:
			return v.layoutRoom(gtx, st)
		default:
			return v.layoutJoin(gtx, st)
		}
	}

	dims := layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D { return v.layoutHeader(gtx, connected) }),
		layout.Flexed(1, func(gtx C) D {
			return layout.Inset{Left: sp4, Right: sp4, Bottom: sp4}.Layout(gtx, body)
		}),
	)
	v.layoutToast(gtx)
	return dims
}

// layoutHeader is the bar across the top: the name, and the way into or out
// of the settings.
func (v *view) layoutHeader(gtx C, connected bool) D {
	th := v.th
	return layout.Inset{Left: sp4, Right: sp2, Top: sp3, Bottom: sp3}.Layout(gtx, func(gtx C) D {
		return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx C) D {
				if v.page == pageSettings && connected {
					return layout.Inset{Right: sp1}.Layout(gtx, func(gtx C) D {
						return th.iconButton(gtx, &v.back, th.iconBack, "Back")
					})
				}
				return D{}
			}),
			layout.Flexed(1, func(gtx C) D {
				title := "Lanora"
				if v.page == pageSettings && connected {
					title = "Settings"
				}
				return th.bold(textTitle, th.pal.Text, title).Layout(gtx)
			}),
			layout.Rigid(func(gtx C) D {
				if v.page == pageSettings || !connected {
					// Keeps the bar the same height on every screen.
					return layout.Spacer{Width: 36, Height: 36}.Layout(gtx)
				}
				return th.iconButton(gtx, &v.openSettings, th.iconSettings, "Settings")
			}),
		)
	})
}

// layoutToast shows a short confirmation at the bottom of the window.
func (v *view) layoutToast(gtx C) {
	if v.toast == "" || !gtx.Now.Before(v.toastUntil) {
		v.toast = ""
		return
	}
	gtx.Execute(op.InvalidateCmd{At: v.toastUntil})
	th := v.th
	layout.S.Layout(gtx, func(gtx C) D {
		gtx.Constraints.Min = image.Point{} // as wide as its text, not the window
		// Clear of the button at the bottom of the window.
		return layout.Inset{Bottom: sp4 + controlHeight + sp4}.Layout(gtx, func(gtx C) D {
			return layout.Background{}.Layout(gtx,
				func(gtx C) D {
					fill(gtx, th.pal.Text, gtx.Constraints.Min, unit.Dp(18))
					return D{Size: gtx.Constraints.Min}
				},
				func(gtx C) D {
					return layout.Inset{Left: sp4, Right: sp4, Top: sp2, Bottom: sp2}.Layout(gtx,
						th.label(textBody, th.pal.Bg, v.toast).Layout)
				})
		})
	})
}
