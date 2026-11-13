//go:build windows || lanoraui

package ui

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"net/url"
	"time"

	"gioui.org/io/key"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"lanora/internal/client/ipc"
	"lanora/internal/proto"
)

// layoutService is shown while the window cannot reach the Lanora service:
// it is not installed yet, or it is installed but not running.
func (v *view) layoutService(gtx C, tried bool) D {
	th, p := v.th, v.app.platform
	if !tried {
		return D{Size: gtx.Constraints.Max} // the first connection attempt has not finished
	}

	title, text, action := "Lanora is not running",
		"The Lanora background service is not reachable. Start it, then this window will connect by itself.", ""
	if p.ServiceState != nil {
		installed, _ := p.ServiceState()
		if !installed {
			title = "Finish setting up Lanora"
			text = "Lanora needs to install its network service. Windows will ask for your permission once. " +
				"After that, Lanora runs without asking again."
			action = "Install"
		} else {
			text = "The Lanora service is installed but not running."
			action = "Start the service"
		}
	}
	if v.install.Clicked(gtx) && p.InstallService != nil && !v.installing {
		v.installing, v.installErr = true, ""
		v.run(p.InstallService, func(err error) {
			v.installing = false
			if err != nil {
				v.installErr = err.Error()
			}
		})
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		gap(sp6),
		layout.Rigid(func(gtx C) D {
			return th.card(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(th.bold(textLarge, th.pal.Text, title).Layout),
					gap(sp2),
					layout.Rigid(th.label(textBody, th.pal.Muted, text).Layout),
					layout.Rigid(func(gtx C) D {
						if v.installErr == "" {
							return D{}
						}
						return layout.Inset{Top: sp3}.Layout(gtx, func(gtx C) D {
							return th.notice(gtx, th.pal.BadSurface, th.pal.Bad, th.pal.Bad, v.installErr)
						})
					}),
					layout.Rigid(func(gtx C) D {
						if action == "" || p.InstallService == nil {
							return D{}
						}
						label := action
						if v.installing {
							label = "Waiting for Windows…"
						}
						return layout.Inset{Top: sp4}.Layout(gtx, func(gtx C) D {
							return th.button(gtx, &v.install, buttonPrimary, label, !v.installing)
						})
					}),
				)
			})
		}),
	)
}

// layoutJoin is the form for entering a room.
func (v *view) layoutJoin(gtx C, st ipc.Status) D {
	th := v.th
	saved := st.Settings
	if !v.prefilled {
		v.prefilled = true
		v.server.SetText(saved.Server)
		if saved.RoomID != "" {
			v.room.SetText(proto.FormatRoomID(saved.RoomID))
		}
		nick := saved.Nickname
		if nick == "" {
			nick = st.Hostname
		}
		v.nickname.SetText(nick)
		v.remember.Value = saved.Remember
		// Start typing where the first missing piece goes.
		first := v.room
		switch {
		case saved.Server == "":
			first = v.server
		case saved.RoomID != "":
			first = v.password
		}
		gtx.Execute(key.FocusCmd{Tag: &first.Editor})
	}

	// The saved password can stand in for an empty field only for the room
	// it was saved for.
	typedRoom, _ := proto.NormalizeRoomID(v.room.Value())
	useSaved := st.HasPassword && typedRoom != "" && typedRoom == saved.RoomID
	v.password.Hint = ""
	if useSaved {
		v.password.Hint = "Saved. Leave empty to use it"
	}
	needServer := saved.Server == ""

	submit := v.join.Clicked(gtx)
	for _, f := range []*field{v.server, v.room, v.password, v.nickname} {
		if f.submitted(gtx) {
			submit = true
		}
	}
	if submit && !v.busy {
		args := ipc.ConnectArgs{
			Server: saved.Server, RoomID: v.room.Value(), Password: v.password.Text(),
			Nickname: v.nickname.Value(), Remember: v.remember.Value,
		}
		if needServer {
			args.Server = v.server.Value()
		}
		switch {
		case args.Server == "":
			v.formError = "Enter the address of your Lanora server."
		case args.RoomID == "":
			v.formError = "Enter the room ID."
		case args.Password == "" && !useSaved:
			v.formError = "Enter the room password."
		default:
			v.busy, v.formError = true, ""
			v.run(func() error {
				return v.app.link.call(func(ctx context.Context, c *ipc.Client) error { return c.Connect(ctx, args) })
			}, func(err error) {
				v.busy = false
				if err != nil {
					v.formError = err.Error()
					return
				}
				v.password.SetText("")
			})
		}
	}

	// What went wrong last time: something the form rejected, or the reason
	// the service gave for stopping.
	problem := v.formError
	if problem == "" && st.Connection.Phase == ipc.PhaseStopped {
		problem = st.Connection.Error
	}
	// Coming back to the form after a refused attempt, the password is the
	// thing to type again.
	if v.returnToPassword {
		v.returnToPassword = false
		gtx.Execute(key.FocusCmd{Tag: &v.password.Editor})
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return th.card(gtx, func(gtx C) D {
				children := []layout.FlexChild{
					layout.Rigid(th.bold(textLarge, th.pal.Text, "Join a room").Layout),
					gap(sp1),
					layout.Rigid(th.label(textBody, th.pal.Muted, "Enter the room ID and password you were given.").Layout),
					gap(sp4),
				}
				if needServer {
					children = append(children, layout.Rigid(func(gtx C) D { return v.server.Layout(gtx, th) }), gap(sp3))
				}
				children = append(children,
					layout.Rigid(func(gtx C) D { return v.room.Layout(gtx, th) }),
					gap(sp3),
					layout.Rigid(func(gtx C) D { return v.password.Layout(gtx, th) }),
					gap(sp3),
					layout.Rigid(func(gtx C) D { return v.nickname.Layout(gtx, th) }),
					gap(sp3),
					layout.Rigid(func(gtx C) D {
						cb := material.CheckBox(th.Theme, &v.remember, "Remember this room on this computer")
						cb.Color, cb.IconColor, cb.TextSize = th.pal.Text, th.pal.Line, textBody
						return cb.Layout(gtx)
					}),
				)
				if problem != "" {
					children = append(children, gap(sp3), layout.Rigid(func(gtx C) D {
						return th.notice(gtx, th.pal.BadSurface, th.pal.Bad, th.pal.Bad, problem)
					}))
				}
				label := "Join room"
				if v.busy {
					label = "Joining…"
				}
				children = append(children, gap(sp4), layout.Rigid(func(gtx C) D {
					return th.button(gtx, &v.join, buttonPrimary, label, !v.busy)
				}))
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
			})
		}),
		gap(sp3),
		layout.Rigid(func(gtx C) D {
			if needServer {
				return D{}
			}
			return layout.Center.Layout(gtx, th.label(textSmall, th.pal.Muted, "Server: "+displayServer(saved.Server)).Layout)
		}),
	)
}

// displayServer shortens a server address for display: the scheme and the
// certificate pin are not what a person recognises it by.
func displayServer(addr string) string {
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return addr
	}
	return u.Host
}

func layoutSquare(gtx C, side unit.Dp) image.Point {
	px := gtx.Dp(side)
	return image.Pt(px, px)
}

// layoutConnecting shows progress while a room is being entered.
func (v *view) layoutConnecting(gtx C, st ipc.Status) D {
	th := v.th
	if v.cancel.Clicked(gtx) {
		v.disconnect()
	}
	v.returnToPassword = true
	detail := st.Connection.Detail
	if detail == "" {
		detail = "Connecting…"
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		gap(sp6),
		layout.Rigid(func(gtx C) D {
			return th.card(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
					gap(sp4),
					layout.Rigid(func(gtx C) D {
						// Exactly this size, whatever the card asks for: the
						// spinner draws itself as wide as its minimum width,
						// and the card's minimum is the card's whole width.
						gtx.Constraints = layout.Exact(layoutSquare(gtx, 36))
						loader := material.Loader(th.Theme)
						loader.Color = th.pal.Line
						return loader.Layout(gtx)
					}),
					gap(sp4),
					layout.Rigid(th.label(textBody, th.pal.Text, detail).Layout),
					gap(sp6),
					layout.Rigid(func(gtx C) D { return th.button(gtx, &v.cancel, buttonPlain, "Cancel", true) }),
				)
			})
		}),
	)
}

func (v *view) disconnect() {
	v.run(func() error {
		return v.app.link.call(func(ctx context.Context, c *ipc.Client) error { return c.Disconnect(ctx) })
	}, func(error) {})
}

// layoutRoom is the main screen once in a room: who you are there, and who
// else is.
func (v *view) layoutRoom(gtx C, st ipc.Status) D {
	th, c := v.th, st.Connection
	if v.leave.Clicked(gtx) {
		v.disconnect()
	}
	if v.copyIP.Clicked(gtx) {
		copyToClipboard(gtx, c.IP)
		v.showToast(gtx, "Address copied")
	}

	state, stateColor := "Connected", th.pal.Good
	if c.Phase == ipc.PhaseReconnecting {
		state, stateColor = "Reconnecting to the server", th.pal.Warn
	}
	relay := "Relay ready"
	switch c.Relay {
	case "tcp":
		relay = "Relay over TCP (UDP is blocked here)"
	case "":
		relay = "Relay not reachable"
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return th.card(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx C) D {
						return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx C) D {
								l := th.bold(textLarge, th.pal.Text, c.RoomName)
								l.MaxLines = 1
								return l.Layout(gtx)
							}),
							hgap(sp2),
							layout.Rigid(func(gtx C) D { return th.pill(gtx, stateColor, state) }),
						)
					}),
					gap(sp3),
					layout.Rigid(th.label(textSmall, th.pal.Muted, "Your address in this room").Layout),
					layout.Rigid(func(gtx C) D {
						return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(th.bold(textTitle, th.pal.Text, c.IP).Layout),
							hgap(sp1),
							layout.Rigid(func(gtx C) D { return th.iconButton(gtx, &v.copyIP, th.iconCopy, "Copy address") }),
						)
					}),
					layout.Rigid(th.label(textSmall, th.pal.Muted, relay).Layout),
				)
			})
		}),
		gap(sp4),
		layout.Rigid(th.bold(textSmall, th.pal.Muted, memberCount(len(c.Peers))).Layout),
		gap(sp2),
		layout.Flexed(1, func(gtx C) D {
			if len(c.Peers) == 0 {
				return th.card(gtx, th.label(textBody, th.pal.Muted,
					"Nobody else is here yet. Give the room ID and password to the people you want to connect with.").Layout)
			}
			return th.surface(gtx, th.pal.Surface, th.pal.Border, 0, func(gtx C) D {
				return material.List(th.Theme, &v.peers).Layout(gtx, len(c.Peers), func(gtx C, i int) D {
					return v.layoutPeer(gtx, c.Peers[i], i > 0)
				})
			})
		}),
		gap(sp4),
		layout.Rigid(func(gtx C) D { return th.button(gtx, &v.leave, buttonDanger, "Leave room", true) }),
	)
}

func memberCount(others int) string {
	switch others {
	case 0:
		return "MEMBERS"
	case 1:
		return "1 OTHER MEMBER"
	}
	return fmt.Sprintf("%d OTHER MEMBERS", others)
}

// layoutPeer is one row of the member list. Clicking it copies the member's
// address, which is what one pastes into a game's "connect to IP" box.
func (v *view) layoutPeer(gtx C, p ipc.Peer, separator bool) D {
	th := v.th
	click := v.peerRows[p.IP]
	if click == nil {
		click = new(widget.Clickable)
		v.peerRows[p.IP] = click
	}
	if click.Clicked(gtx) {
		copyToClipboard(gtx, p.IP)
		v.showToast(gtx, p.IP+" copied")
	}

	var (
		col  color.NRGBA
		path string
	)
	switch p.Via {
	case proto.ViaDirect:
		col, path = th.pal.Good, "Direct"
	case proto.ViaRelay:
		col, path = th.pal.Warn, "Relayed"
	default:
		col, path = th.pal.OnDisabled, "Connecting…"
	}
	latency := ""
	if p.RTTms >= 0 && p.Via != proto.ViaNone {
		latency = fmt.Sprintf("%d ms", p.RTTms)
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			if !separator {
				return D{}
			}
			return th.divider(gtx)
		}),
		layout.Rigid(func(gtx C) D {
			return click.Layout(gtx, func(gtx C) D {
				return layout.Background{}.Layout(gtx,
					func(gtx C) D {
						if click.Hovered() {
							fill(gtx, th.pal.Hover, gtx.Constraints.Min, 0)
						}
						return D{Size: gtx.Constraints.Min}
					},
					func(gtx C) D {
						gtx.Constraints.Min.X = gtx.Constraints.Max.X
						return layout.Inset{Left: sp4, Right: sp4, Top: sp3, Bottom: sp3}.Layout(gtx, func(gtx C) D {
							return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
								layout.Rigid(func(gtx C) D { return dot(gtx, col) }),
								hgap(sp3),
								layout.Flexed(1, func(gtx C) D {
									name := th.bold(textBody, th.pal.Text, p.Nickname)
									name.MaxLines = 1
									return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
										layout.Rigid(name.Layout),
										layout.Rigid(th.label(textSmall, th.pal.Muted, p.IP).Layout),
									)
								}),
								hgap(sp2),
								layout.Rigid(func(gtx C) D {
									return layout.Flex{Axis: layout.Vertical, Alignment: layout.End}.Layout(gtx,
										layout.Rigid(th.label(textSmall, th.pal.Text, path).Layout),
										layout.Rigid(th.label(textSmall, th.pal.Muted, latency).Layout),
									)
								}),
							)
						})
					})
			})
		}),
	)
}

// layoutSettings is the preferences screen.
func (v *view) layoutSettings(gtx C, st ipc.Status) D {
	th, p := v.th, v.app.platform
	s := st.Settings
	if !v.settingsFilled {
		v.settingsFilled = true
		v.settingsServer.SetText(s.Server)
	}

	// Switches show what the service has saved. A change is sent at once
	// and shown at once; if the service refuses it, its next status puts
	// the switch back.
	sync := func(b *widget.Bool, current bool, change func(on bool) ipc.SettingsArgs) {
		if b.Update(gtx) {
			v.sendSettings(change(b.Value))
			return
		}
		b.Value = current
	}
	sync(&v.autoConnect, s.AutoConnect, func(on bool) ipc.SettingsArgs { return ipc.SettingsArgs{AutoConnect: &on} })
	sync(&v.lanPriority, s.LANPriority, func(on bool) ipc.SettingsArgs { return ipc.SettingsArgs{LANPriority: &on} })
	sync(&v.privateNet, s.PrivateNetwork, func(on bool) ipc.SettingsArgs { return ipc.SettingsArgs{PrivateNetwork: &on} })
	sync(&v.relayOnly, s.RelayOnly, func(on bool) ipc.SettingsArgs { return ipc.SettingsArgs{RelayOnly: &on} })

	if p.StartAtSignIn != nil && p.SetStartAtSignIn != nil {
		if v.startAtSignIn.Update(gtx) {
			if err := p.SetStartAtSignIn(v.startAtSignIn.Value); err != nil {
				v.settingsError = err.Error()
			}
		} else {
			v.startAtSignIn.Value = p.StartAtSignIn()
		}
	}

	if v.saveServer.Clicked(gtx) || v.settingsServer.submitted(gtx) {
		addr := v.settingsServer.Value()
		v.sendSettings(ipc.SettingsArgs{Server: &addr})
		// The join form shows the server only when none is saved; let it
		// pick the new value up.
		v.prefilled = false
	}
	if v.copyDiagnostics.Clicked(gtx) {
		var report string
		v.run(func() error {
			return v.app.link.call(func(ctx context.Context, c *ipc.Client) (err error) {
				report, err = c.Diagnostics(ctx)
				return err
			})
		}, func(err error) {
			if err != nil {
				v.settingsError = err.Error()
				return
			}
			v.pendingCopy = report
		})
	}
	if v.pendingCopy != "" {
		copyToClipboard(gtx, v.pendingCopy)
		v.pendingCopy = ""
		v.showToast(gtx, "Diagnostics copied")
	}
	if v.openLogs.Clicked(gtx) && p.OpenLogFolder != nil {
		p.OpenLogFolder()
	}
	uninstallLabel := "Uninstall Lanora…"
	if gtx.Now.Before(v.uninstallArmed) {
		uninstallLabel = "Click again to uninstall"
	}
	if v.uninstall.Clicked(gtx) && p.UninstallService != nil {
		if gtx.Now.Before(v.uninstallArmed) {
			v.uninstallArmed = time.Time{}
			v.run(p.UninstallService, func(err error) {
				if err != nil {
					v.settingsError = err.Error()
				}
			})
		} else {
			v.uninstallArmed = gtx.Now.Add(4 * time.Second)
		}
	}

	section := func(title string, rows ...layout.Widget) layout.Widget {
		return func(gtx C) D {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(th.bold(textSmall, th.pal.Muted, title).Layout),
				gap(sp2),
				layout.Rigid(func(gtx C) D {
					return th.card(gtx, func(gtx C) D {
						children := make([]layout.FlexChild, 0, 2*len(rows))
						for i, row := range rows {
							if i > 0 {
								children = append(children, gap(sp3), layout.Rigid(th.divider), gap(sp3))
							}
							children = append(children, layout.Rigid(row))
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
					})
				}),
				gap(sp4),
			)
		}
	}

	connection := []layout.Widget{
		func(gtx C) D {
			return th.toggle(gtx, &v.autoConnect, "Rejoin automatically",
				"Join the remembered room when this computer starts.")
		},
	}
	if p.StartAtSignIn != nil && p.SetStartAtSignIn != nil {
		connection = append(connection, func(gtx C) D {
			return th.toggle(gtx, &v.startAtSignIn, "Open Lanora when I sign in",
				"Starts in the notification area.")
		})
	}

	sections := []layout.Widget{
		func(gtx C) D {
			if v.settingsError == "" {
				return D{}
			}
			return layout.Inset{Bottom: sp4}.Layout(gtx, func(gtx C) D {
				return th.notice(gtx, th.pal.BadSurface, th.pal.Bad, th.pal.Bad, v.settingsError)
			})
		},
		section("SERVER", func(gtx C) D {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx C) D { return v.settingsServer.Layout(gtx, th) }),
				gap(sp1),
				layout.Rigid(th.label(textSmall, th.pal.Muted,
					"For a server with a self-signed certificate, paste the whole address including the part after #.").Layout),
				gap(sp3),
				layout.Rigid(func(gtx C) D { return th.button(gtx, &v.saveServer, buttonPlain, "Save server", true) }),
			)
		}),
		section("STARTING UP", connection...),
		section("IN A ROOM",
			func(gtx C) D {
				return th.toggle(gtx, &v.lanPriority, "Prefer the room for LAN games",
					"Games that search the local network find room members. While in a room, they will not find devices on your own network.")
			},
			func(gtx C) D {
				return th.toggle(gtx, &v.privateNet, "Treat the room as a private network",
					"Lets file sharing and games you host accept connections from room members.")
			},
			func(gtx C) D {
				return th.toggle(gtx, &v.relayOnly, "Always use the relay",
					"Hides your internet address from other members. Slower.")
			},
			th.label(textSmall, th.pal.Muted, "These take effect the next time you join a room.").Layout,
		),
	}
	help := []layout.Widget{
		func(gtx C) D { return th.button(gtx, &v.copyDiagnostics, buttonPlain, "Copy diagnostics", true) },
	}
	if p.OpenLogFolder != nil {
		help = append(help, func(gtx C) D { return th.button(gtx, &v.openLogs, buttonPlain, "Open the log folder", true) })
	}
	sections = append(sections, section("TROUBLESHOOTING", help...))

	about := []layout.Widget{th.label(textBody, th.pal.Text, "Lanora "+st.Version).Layout}
	if p.UninstallService != nil {
		about = append(about, func(gtx C) D { return th.button(gtx, &v.uninstall, buttonDanger, uninstallLabel, true) })
	}
	sections = append(sections, section("ABOUT", about...))

	return material.List(th.Theme, &v.settingsList).Layout(gtx, len(sections), func(gtx C, i int) D {
		return sections[i](gtx)
	})
}

// sendSettings saves a preference change with the service.
func (v *view) sendSettings(args ipc.SettingsArgs) {
	v.settingsError = ""
	v.run(func() error {
		return v.app.link.call(func(ctx context.Context, c *ipc.Client) error {
			st, err := c.UpdateSettings(ctx, args)
			if err == nil {
				v.app.link.setStatus(st)
			}
			return err
		})
	}, func(err error) {
		if err != nil {
			v.settingsError = err.Error()
			return
		}
		if args.Server != nil {
			v.settingsFilled = false // show the address as the service normalised it
		}
	})
}
