// Command genicon draws the Lanora logo and writes the icon files the
// Windows build needs: the multi-size .ico used for the notification area,
// and PNGs that the resource compiler packs into the executable's icon.
//
// The logo is the one in web/admin/logo.svg, drawn here from the same
// numbers so the build needs no SVG renderer: a rounded blue square holding
// an "L" made of three connected nodes. Change one, change the other.
//
// Usage: go run ./build/windows/genicon <output directory>
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"

	"golang.org/x/image/vector"
)

// The logo's geometry on its 32×32 grid.
const (
	grid         = 32
	cornerRadius = 7.5
	nodeRadius   = 3.75
	strokeHalf   = 1.4
)

var (
	background = color.NRGBA{R: 0x2a, G: 0x78, B: 0xd6, A: 0xff}
	foreground = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	nodes      = [3][2]float32{{10, 9}, {10, 22}, {23, 22}}
)

// kappa is the control-point distance for approximating a quarter circle
// with a cubic Bézier curve.
const kappa = 0.5522847498

type canvas struct {
	img   *image.NRGBA
	scale float32
}

func (c *canvas) fill(col color.Color, path func(r *vector.Rasterizer, s float32)) {
	b := c.img.Bounds()
	r := vector.NewRasterizer(b.Dx(), b.Dy())
	path(r, c.scale)
	r.Draw(c.img, b, image.NewUniform(col), image.Point{})
}

func circle(cx, cy, radius float32) func(*vector.Rasterizer, float32) {
	return func(r *vector.Rasterizer, s float32) {
		x, y, rad, k := cx*s, cy*s, radius*s, radius*s*kappa
		r.MoveTo(x+rad, y)
		r.CubeTo(x+rad, y+k, x+k, y+rad, x, y+rad)
		r.CubeTo(x-k, y+rad, x-rad, y+k, x-rad, y)
		r.CubeTo(x-rad, y-k, x-k, y-rad, x, y-rad)
		r.CubeTo(x+k, y-rad, x+rad, y-k, x+rad, y)
		r.ClosePath()
	}
}

func rect(x0, y0, x1, y1 float32) func(*vector.Rasterizer, float32) {
	return func(r *vector.Rasterizer, s float32) {
		r.MoveTo(x0*s, y0*s)
		r.LineTo(x1*s, y0*s)
		r.LineTo(x1*s, y1*s)
		r.LineTo(x0*s, y1*s)
		r.ClosePath()
	}
}

func roundedSquare(size, radius float32) func(*vector.Rasterizer, float32) {
	return func(r *vector.Rasterizer, s float32) {
		n, rad, k := size*s, radius*s, radius*s*(1-kappa)
		r.MoveTo(rad, 0)
		r.LineTo(n-rad, 0)
		r.CubeTo(n-k, 0, n, k, n, rad)
		r.LineTo(n, n-rad)
		r.CubeTo(n, n-k, n-k, n, n-rad, n)
		r.LineTo(rad, n)
		r.CubeTo(k, n, 0, n-k, 0, n-rad)
		r.LineTo(0, rad)
		r.CubeTo(0, k, k, 0, rad, 0)
		r.ClosePath()
	}
}

// draw renders the logo at the given pixel size.
func drawLogo(size int) *image.NRGBA {
	c := &canvas{img: image.NewNRGBA(image.Rect(0, 0, size, size)), scale: float32(size) / grid}
	draw.Draw(c.img, c.img.Bounds(), image.Transparent, image.Point{}, draw.Src)
	c.fill(background, roundedSquare(grid, cornerRadius))
	// The two strokes of the L, then the node at each end and at the corner.
	c.fill(foreground, rect(nodes[0][0]-strokeHalf, nodes[0][1], nodes[0][0]+strokeHalf, nodes[1][1]))
	c.fill(foreground, rect(nodes[1][0], nodes[1][1]-strokeHalf, nodes[2][0], nodes[1][1]+strokeHalf))
	for _, n := range nodes {
		c.fill(foreground, circle(n[0], n[1], nodeRadius))
	}
	return c.img
}

// icoEntry encodes one image for an .ico file. Small sizes use the classic
// bitmap form, which every Windows icon loader accepts; 256 pixels uses
// PNG, as Windows itself does.
func icoEntry(img *image.NRGBA) []byte {
	size := img.Bounds().Dx()
	var buf bytes.Buffer
	if size >= 256 {
		png.Encode(&buf, img)
		return buf.Bytes()
	}
	// BITMAPINFOHEADER; the height counts the colour image and the mask.
	binary.Write(&buf, binary.LittleEndian, struct {
		Size, Width, Height                                 uint32
		Planes, BitCount                                    uint16
		Compression, SizeImage                              uint32
		XPelsPerMeter, YPelsPerMeter, ClrUsed, ClrImportant uint32
	}{Size: 40, Width: uint32(size), Height: uint32(size * 2), Planes: 1, BitCount: 32})
	for y := size - 1; y >= 0; y-- { // bottom-up, BGRA
		for x := 0; x < size; x++ {
			p := img.NRGBAAt(x, y)
			buf.Write([]byte{p.B, p.G, p.R, p.A})
		}
	}
	// The 1-bit mask is unused with an alpha channel but must be present;
	// rows are padded to 32 bits.
	buf.Write(make([]byte, size*((size+31)/32*4)))
	return buf.Bytes()
}

func writeICO(path string, sizes []int) error {
	var entries [][]byte
	for _, s := range sizes {
		entries = append(entries, icoEntry(drawLogo(s)))
	}
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))})
	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		dim := byte(s) // 0 means 256
		binary.Write(&out, binary.LittleEndian, struct {
			Width, Height, Colors, Reserved byte
			Planes, BitCount                uint16
			Size, Offset                    uint32
		}{dim, dim, 0, 0, 1, 32, uint32(len(entries[i])), uint32(offset)})
		offset += len(entries[i])
	}
	for _, e := range entries {
		out.Write(e)
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

func writePNG(path string, size int) error {
	var buf bytes.Buffer
	if err := png.Encode(&buf, drawLogo(size)); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genicon <output directory>")
		os.Exit(2)
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	err := writeICO(filepath.Join(dir, "icon.ico"), []int{16, 20, 24, 32, 40, 48, 64, 256})
	for _, s := range []int{16, 24, 32, 48, 64, 256} {
		if err == nil {
			err = writePNG(filepath.Join(dir, fmt.Sprintf("icon%d.png", s)), s)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
