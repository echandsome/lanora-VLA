//go:build windows || lanoraui

package ui

import (
	"image"
	"image/color"
	"io"
	"strings"

	"gioui.org/io/clipboard"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// field is a labelled single-line text input.
type field struct {
	widget.Editor
	Label string
	Hint  string
}

func newField(label, hint string, mask bool) *field {
	f := &field{Label: label, Hint: hint}
	f.SingleLine, f.Submit = true, true
	if mask {
		f.Mask = '•'
	}
	return f
}

// Value returns the trimmed text.
func (f *field) Value() string { return strings.TrimSpace(f.Text()) }

// submitted reports whether Enter was pressed in the field this frame.
func (f *field) submitted(gtx C) bool {
	hit := false
	for {
		ev, ok := f.Update(gtx)
		if !ok {
			return hit
		}
		if _, ok := ev.(widget.SubmitEvent); ok {
			hit = true
		}
	}
}

func (f *field) Layout(gtx C, th *theme) D {
	border := th.pal.Border
	width := unit.Dp(1)
	if gtx.Focused(&f.Editor) {
		border, width = th.pal.Line, 2
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(th.label(textSmall, th.pal.Muted, f.Label).Layout),
		gap(sp1),
		layout.Rigid(func(gtx C) D {
			return widget.Border{Color: border, CornerRadius: radiusControl, Width: width}.Layout(gtx, func(gtx C) D {
				return layout.Background{}.Layout(gtx,
					func(gtx C) D {
						fill(gtx, th.pal.Surface, gtx.Constraints.Min, radiusControl)
						return D{Size: gtx.Constraints.Min}
					},
					func(gtx C) D {
						gtx.Constraints.Min.X = gtx.Constraints.Max.X
						gtx.Constraints.Min.Y = gtx.Dp(controlHeight)
						return layout.Inset{Left: sp3, Right: sp3}.Layout(gtx, func(gtx C) D {
							return layout.W.Layout(gtx, func(gtx C) D {
								// Full width, natural height: the text is then
								// centred vertically in the box.
								gtx.Constraints.Min = image.Pt(gtx.Constraints.Max.X, 0)
								ed := material.Editor(th.Theme, &f.Editor, f.Hint)
								ed.TextSize = textBody
								ed.Color, ed.HintColor = th.pal.Text, th.pal.OnDisabled
								return ed.Layout(gtx)
							})
						})
					})
			})
		}),
	)
}

// buttonKind selects a button's emphasis.
type buttonKind int

const (
	buttonPrimary buttonKind = iota // the one main action of a screen
	buttonPlain                     // secondary actions
	buttonDanger                    // leaving, removing
)

// button lays out a full-width button. A disabled button does not react.
func (th *theme) button(gtx C, click *widget.Clickable, kind buttonKind, label string, enabled bool) D {
	bg, fg, border := th.pal.Accent, th.pal.OnAccent, th.pal.Accent
	switch kind {
	case buttonPlain:
		bg, fg, border = th.pal.Surface, th.pal.Text, th.pal.Border
	case buttonDanger:
		bg, fg, border = th.pal.Surface, th.pal.Bad, th.pal.Border
	}
	if !enabled {
		bg, fg, border = th.pal.Disabled, th.pal.OnDisabled, th.pal.Disabled
		gtx = gtx.Disabled()
	} else if click.Hovered() && kind != buttonPrimary {
		bg = th.pal.Hover
	}
	// Someone using the keyboard must be able to see where they are.
	width := unit.Dp(1)
	if gtx.Focused(click) {
		border, width = th.pal.Text, 2
	}
	return widget.Border{Color: border, CornerRadius: radiusControl, Width: width}.Layout(gtx, func(gtx C) D {
		return click.Layout(gtx, func(gtx C) D {
			gtx.Constraints.Min = image.Pt(gtx.Constraints.Max.X, gtx.Dp(controlHeight))
			fill(gtx, bg, gtx.Constraints.Min, radiusControl)
			return layout.Center.Layout(gtx, func(gtx C) D {
				gtx.Constraints.Min = image.Point{}
				return th.bold(textBody, fg, label).Layout(gtx)
			})
		})
	})
}

// iconButton is a small square button showing only an icon.
func (th *theme) iconButton(gtx C, click *widget.Clickable, icon *widget.Icon, description string) D {
	border := color.NRGBA{}
	if gtx.Focused(click) {
		border = th.pal.Text
	}
	return widget.Border{Color: border, CornerRadius: radiusControl, Width: 2}.Layout(gtx, func(gtx C) D {
		return click.Layout(gtx, func(gtx C) D {
			size := gtx.Dp(36)
			if click.Hovered() {
				fill(gtx, th.pal.Hover, image.Pt(size, size), radiusControl)
			}
			gtx.Constraints = layout.Exact(image.Pt(size, size))
			return layout.Center.Layout(gtx, func(gtx C) D {
				gtx.Constraints = layout.Exact(image.Pt(gtx.Dp(20), gtx.Dp(20)))
				return icon.Layout(gtx, th.pal.Muted)
			})
		})
	})
}

// toggle is a switch with a title and a line of explanation.
func (th *theme) toggle(gtx C, value *widget.Bool, title, help string) D {
	return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
		layout.Flexed(1, func(gtx C) D {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(th.label(textBody, th.pal.Text, title).Layout),
				gap(2),
				layout.Rigid(th.label(textSmall, th.pal.Muted, help).Layout),
			)
		}),
		hgap(sp3),
		layout.Rigid(func(gtx C) D {
			sw := material.Switch(th.Theme, value, title)
			sw.Color.Enabled = th.pal.Line
			sw.Color.Disabled = th.pal.OnDisabled
			sw.Color.Track = th.pal.Border
			return sw.Layout(gtx)
		}),
	)
}

// divider is a hairline across the available width.
func (th *theme) divider(gtx C) D {
	size := image.Pt(gtx.Constraints.Max.X, gtx.Dp(1))
	fill(gtx, th.pal.Border, size, 0)
	return D{Size: size}
}

// pill is a small rounded status label with a coloured dot.
func (th *theme) pill(gtx C, col color.NRGBA, txt string) D {
	return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx C) D { return dot(gtx, col) }),
		hgap(6),
		layout.Rigid(th.label(textSmall, th.pal.Muted, txt).Layout),
	)
}

// notice is a tinted box for a message the user must not miss.
func (th *theme) notice(gtx C, bg, border, fg color.NRGBA, txt string) D {
	return widget.Border{Color: border, CornerRadius: radiusControl, Width: 1}.Layout(gtx, func(gtx C) D {
		return layout.Background{}.Layout(gtx,
			func(gtx C) D {
				fill(gtx, bg, gtx.Constraints.Min, radiusControl)
				return D{Size: gtx.Constraints.Min}
			},
			func(gtx C) D {
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				return layout.UniformInset(sp3).Layout(gtx, th.label(textBody, fg, txt).Layout)
			})
	})
}

// copyToClipboard puts text on the clipboard.
func copyToClipboard(gtx C, text string) {
	gtx.Execute(clipboard.WriteCmd{Type: "application/text", Data: io.NopCloser(strings.NewReader(text))})
}
