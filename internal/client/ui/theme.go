//go:build windows || lanoraui

// Package ui is Lanora's window. It shows what the Lanora service reports
// and sends it the user's requests; it does no networking of its own.
package ui

import (
	"image"
	"image/color"

	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"golang.org/x/exp/shiny/materialdesign/icons"
)

type (
	C = layout.Context
	D = layout.Dimensions
)

// palette is the window's colours. Every colour used anywhere comes from
// here, so the light and dark themes cannot drift apart.
type palette struct {
	Bg, Surface, Border  color.NRGBA
	Text, Muted          color.NRGBA
	Accent, OnAccent     color.NRGBA // filled buttons and the text on them
	Line                 color.NRGBA // the accent as a line or mark on a surface
	Good, Warn, Bad      color.NRGBA
	BadSurface, Hover    color.NRGBA
	Disabled, OnDisabled color.NRGBA
}

func rgb(c uint32) color.NRGBA {
	return color.NRGBA{R: uint8(c >> 16), G: uint8(c >> 8), B: uint8(c), A: 0xff}
}

var lightPalette = palette{
	Bg: rgb(0xF4F5F7), Surface: rgb(0xFFFFFF), Border: rgb(0xE2E5EA),
	Text: rgb(0x14171F), Muted: rgb(0x667085),
	Accent: rgb(0x256ABF), OnAccent: rgb(0xFFFFFF), Line: rgb(0x256ABF),
	Good: rgb(0x16A34A), Warn: rgb(0xD97706), Bad: rgb(0xD92D20),
	BadSurface: rgb(0xFEF3F2), Hover: rgb(0xEEF1F5),
	Disabled: rgb(0xE2E5EA), OnDisabled: rgb(0x98A2B3),
}

var darkPalette = palette{
	Bg: rgb(0x101216), Surface: rgb(0x1A1D23), Border: rgb(0x2C313A),
	Text: rgb(0xECEEF2), Muted: rgb(0x98A2B3),
	Accent: rgb(0x256ABF), OnAccent: rgb(0xFFFFFF), Line: rgb(0x5598E7),
	Good: rgb(0x32D074), Warn: rgb(0xF5A524), Bad: rgb(0xF97066),
	BadSurface: rgb(0x2A1614), Hover: rgb(0x242830),
	Disabled: rgb(0x2C313A), OnDisabled: rgb(0x667085),
}

// Spacing and shape, in device-independent pixels. One scale, used
// everywhere.
const (
	sp1 unit.Dp = 4
	sp2 unit.Dp = 8
	sp3 unit.Dp = 12
	sp4 unit.Dp = 16
	sp6 unit.Dp = 24

	radiusControl unit.Dp = 8
	radiusCard    unit.Dp = 12
	controlHeight unit.Dp = 40
)

// Text sizes.
const (
	textSmall unit.Sp = 12
	textBody  unit.Sp = 14
	textLarge unit.Sp = 16
	textTitle unit.Sp = 20
)

type theme struct {
	*material.Theme
	pal palette

	iconSettings, iconBack, iconCopy, iconCheck *widget.Icon
}

func newTheme(dark bool) *theme {
	th := material.NewTheme()
	// The Go fonts are embedded so the window looks the same everywhere;
	// system fonts are still consulted, first for the platform's own
	// interface font and then for scripts the embedded fonts lack (a
	// nickname in Chinese, say).
	th.Shaper = text.NewShaper(text.WithCollection(gofont.Collection()))
	// Families are tried in order for each character: the platform's
	// interface font first, then fonts for Chinese, Japanese and Korean,
	// which are named explicitly because automatic fallback does not find a
	// match for every weight.
	th.Face = `"Segoe UI", Inter, "Noto Sans", "Microsoft YaHei UI", "Yu Gothic UI", "Malgun Gothic", "Noto Sans CJK SC", Go`
	th.TextSize = textBody

	pal := lightPalette
	if dark {
		pal = darkPalette
	}
	th.Palette = material.Palette{Bg: pal.Bg, Fg: pal.Text, ContrastBg: pal.Accent, ContrastFg: pal.OnAccent}

	icon := func(data []byte) *widget.Icon {
		ic, err := widget.NewIcon(data)
		if err != nil {
			panic(err) // the icon data is compiled in
		}
		return ic
	}
	return &theme{
		Theme:        th,
		pal:          pal,
		iconSettings: icon(icons.ActionSettings),
		iconBack:     icon(icons.NavigationArrowBack),
		iconCopy:     icon(icons.ContentContentCopy),
		iconCheck:    icon(icons.NavigationCheck),
	}
}

// label returns a text label in the given size and colour.
func (th *theme) label(size unit.Sp, col color.NRGBA, txt string) material.LabelStyle {
	l := material.Label(th.Theme, size, txt)
	l.Color = col
	return l
}

// bold returns an emphasised label. It uses the bold weight rather than
// semi-bold because every font family has one, including the ones that
// supply Chinese, Japanese and Korean characters.
func (th *theme) bold(size unit.Sp, col color.NRGBA, txt string) material.LabelStyle {
	l := th.label(size, col, txt)
	l.Font.Weight = font.Bold
	return l
}

// fill paints a rounded rectangle covering the given size.
func fill(gtx C, col color.NRGBA, size image.Point, radius unit.Dp) {
	defer clip.UniformRRect(image.Rectangle{Max: size}, gtx.Dp(radius)).Push(gtx.Ops).Pop()
	paint.ColorOp{Color: col}.Add(gtx.Ops)
	paint.PaintOp{}.Add(gtx.Ops)
}

// surface lays out w on a rounded, bordered panel that fills the available
// width.
func (th *theme) surface(gtx C, bg, border color.NRGBA, inset unit.Dp, w layout.Widget) D {
	return widget.Border{Color: border, CornerRadius: radiusCard, Width: 1}.Layout(gtx, func(gtx C) D {
		return layout.Background{}.Layout(gtx,
			func(gtx C) D {
				fill(gtx, bg, gtx.Constraints.Min, radiusCard)
				return D{Size: gtx.Constraints.Min}
			},
			func(gtx C) D {
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				return layout.UniformInset(inset).Layout(gtx, w)
			})
	})
}

// card is a surface in the standard panel colours.
func (th *theme) card(gtx C, w layout.Widget) D {
	return th.surface(gtx, th.pal.Surface, th.pal.Border, sp4, w)
}

// dot draws a small filled circle, vertically centred on a line of text.
func dot(gtx C, col color.NRGBA) D {
	d := gtx.Dp(8)
	defer clip.Ellipse{Max: image.Pt(d, d)}.Push(gtx.Ops).Pop()
	paint.ColorOp{Color: col}.Add(gtx.Ops)
	paint.PaintOp{}.Add(gtx.Ops)
	return D{Size: image.Pt(d, d)}
}

func gap(h unit.Dp) layout.FlexChild  { return layout.Rigid(layout.Spacer{Height: h}.Layout) }
func hgap(w unit.Dp) layout.FlexChild { return layout.Rigid(layout.Spacer{Width: w}.Layout) }
