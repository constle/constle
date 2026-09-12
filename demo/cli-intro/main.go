package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

type cell struct {
	ch      rune
	r, g, b int
	on      bool
}

type point struct {
	x, y int
	ch   rune
}

const (
	canvasW = 78
	canvasH = 20
)

var logo = []string{
	"011110 01110 10001 01111 11111 10000 11111",
	"110000 11011 11001 11000 00100 10000 11000",
	"100000 11011 10101 01110 00100 10000 11110",
	"110000 11011 10011 00011 00100 10000 11000",
	"011110 01110 10001 11110 00100 11111 11111",
}

var particles = []point{
	{8, 3, '·'}, {14, 8, '+'}, {20, 2, ':'}, {25, 11, '·'}, {31, 4, '·'},
	{46, 2, '+'}, {52, 10, ':'}, {60, 4, '·'}, {67, 8, '+'}, {72, 3, '·'},
	{11, 14, ':'}, {18, 16, '·'}, {27, 15, '+'}, {49, 16, '·'}, {59, 14, '+'},
	{69, 15, ':'}, {34, 2, '·'}, {43, 13, '·'}, {5, 10, '·'}, {74, 11, ':'},
}

func main() {
	version := "0.4.0"
	if len(os.Args) > 1 && strings.TrimSpace(os.Args[1]) != "" {
		version = strings.TrimPrefix(os.Args[1], "v")
	}

	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		printPlain(version)
		return
	}

	play(version)
}

func play(version string) {
	// Keep shell history intact: reserve a bounded region and repaint only it.
	fmt.Print("\x1b[?25l")
	defer fmt.Print("\x1b[?25h\x1b[0m")

	fmt.Print(strings.Repeat("\n", canvasH))

	frames := 30
	for i := 0; i < frames; i++ {
		t := float64(i) / float64(frames-1)
		frame := renderFrame(t, version)
		fmt.Printf("\x1b[%dA", canvasH)
		fmt.Print(frame)
		time.Sleep(29 * time.Millisecond)
	}

	// Tiny settle so the reveal lands without making startup feel slow.
	time.Sleep(90 * time.Millisecond)
}

func renderFrame(t float64, version string) string {
	grid := make([][]cell, canvasH)
	for y := range grid {
		grid[y] = make([]cell, canvasW)
	}

	cx := float64(canvasW-1) / 2
	cy := 7.0

	// Background dust becomes visible only after ignition.
	dust := smoothstep(0.08, 0.38, t) * (1 - 0.45*smoothstep(0.72, 1, t))
	for i, p := range particles {
		pulse := 0.58 + 0.42*math.Sin(float64(i)*1.71+t*9.0)
		intensity := clamp01(dust * pulse)
		if intensity > 0.16 {
			setCell(grid, p.x, p.y, p.ch, mixRGB(rgb{65, 73, 105}, rgb{139, 143, 245}, intensity))
		}
	}

	// 0..~0.58: one wave expands from a bright core.
	expand := smoothstep(0.03, 0.58, t)
	radius := 0.35 + 10.7*easeOutCubic(expand)

	// ~0.55..0.85: the wave stops expanding, splits and slides aside.
	split := smoothstep(0.54, 0.84, t)
	ringFade := 1.0 - 0.88*smoothstep(0.83, 1.0, t)
	shift := split * 8.5
	gap := split * 24.0

	for y := 0; y < canvasH; y++ {
		for x := 0; x < canvasW; x++ {
			fx := float64(x)
			fy := float64(y)

			var d float64
			if split < 0.02 {
				d = math.Hypot((fx-cx)*0.47, fy-cy)
			} else {
				side := -1.0
				if fx >= cx {
					side = 1.0
				}
				localCx := cx + side*shift
				d = math.Hypot((fx-localCx)*0.47, fy-cy)
			}

			thickness := 1.28 + 0.22*math.Sin(t*math.Pi)
			edge := 1.0 - math.Abs(d-radius)/thickness
			if edge <= 0 {
				continue
			}

			// At the reveal, physically carve open the center so the logo is
			// literally behind the parted wave instead of merely overlaid.
			if split > 0.03 && math.Abs(fx-cx) < gap/2 {
				continue
			}

			intensity := clamp01(edge) * ringFade
			if intensity < 0.09 {
				continue
			}

			ch := shadeRune(intensity)
			lateral := clamp01(math.Abs(fx-cx) / (canvasW * 0.46))
			base := lerpRGB(rgb{170, 134, 255}, rgb{86, 136, 255}, lateral)
			col := lerpRGB(rgb{77, 55, 117}, base, 0.35+0.65*intensity)
			setCell(grid, x, y, ch, col)
		}
	}

	// Bright ignition core. It disappears as the split becomes the focus.
	core := (1 - smoothstep(0.53, 0.72, t)) * smoothstep(0.0, 0.08, t)
	if core > 0.02 {
		drawCore(grid, int(math.Round(cx)), int(math.Round(cy)), core)
	}

	// The wordmark is revealed by the opening itself.
	reveal := smoothstep(0.58, 0.88, t)
	drawLogo(grid, reveal, cx, cy)

	// Final metadata arrives only after the mark has settled.
	meta := smoothstep(0.84, 0.98, t)
	if meta > 0.05 {
		metaLine := "v" + version + "  ·  agent runtime"
		drawText(grid, centeredX(metaLine), 14, metaLine, lerpRGB(rgb{78, 82, 108}, rgb{150, 158, 205}, meta))

		ready := "constle  ›  ready"
		drawText(grid, centeredX(ready), 16, ready, lerpRGB(rgb{70, 75, 98}, rgb{124, 134, 183}, meta))
	}

	// Tiny top labels make it feel authored, not like a generic spinner.
	label := "CONSTLE / BOOT"
	drawText(grid, 2, 1, label, rgb{86, 91, 127})
	phase := "IGNITION"
	switch {
	case t >= 0.84:
		phase = "READY"
	case t >= 0.54:
		phase = "REVEAL"
	case t >= 0.12:
		phase = "EXPAND"
	}
	drawText(grid, canvasW-len(phase)-2, 1, phase, rgb{95, 101, 145})

	return encode(grid)
}

func drawCore(grid [][]cell, cx, cy int, intensity float64) {
	for dy := -1; dy <= 1; dy++ {
		for dx := -2; dx <= 2; dx++ {
			dist := math.Hypot(float64(dx)*0.5, float64(dy))
			v := clamp01(intensity * (1.15 - dist*0.48))
			if v <= 0.1 {
				continue
			}
			col := lerpRGB(rgb{115, 92, 186}, rgb{238, 235, 255}, v)
			setCell(grid, cx+dx, cy+dy, shadeRune(v), col)
		}
	}
}

func drawLogo(grid [][]cell, reveal, cx, cy float64) {
	if reveal <= 0 {
		return
	}

	width := len(logo[0])
	startX := int(math.Round(cx)) - width/2
	startY := int(math.Round(cy)) - len(logo)/2
	revealHalf := reveal * float64(width) / 2

	for row, line := range logo {
		for col, b := range []byte(line) {
			if b != '1' {
				continue
			}
			x := startX + col
			y := startY + row
			distFromCenter := math.Abs(float64(col) - float64(width-1)/2)
			if distFromCenter > revealHalf {
				continue
			}

			local := 1.0 - distFromCenter/(float64(width)/2+1)
			strength := clamp01(0.72 + 0.28*local)
			glyphs := []rune{'▓', '█', '▒', '▓'}
			ch := glyphs[(col+row*3)%len(glyphs)]
			lateral := clamp01(float64(col) / float64(width-1))
			colr := lerpRGB(rgb{194, 167, 255}, rgb{116, 157, 255}, lateral)
			colr = lerpRGB(rgb{83, 71, 126}, colr, strength)
			setCell(grid, x, y, ch, colr)
		}
	}
}

func printPlain(version string) {
	fmt.Printf("CONSTLE v%s\n", version)
}

func centeredX(s string) int {
	x := (canvasW - len(s)) / 2
	if x < 0 {
		return 0
	}
	return x
}

type rgb struct{ r, g, b int }

func setCell(grid [][]cell, x, y int, ch rune, c rgb) {
	if y < 0 || y >= len(grid) || x < 0 || x >= len(grid[y]) {
		return
	}
	grid[y][x] = cell{ch: ch, r: c.r, g: c.g, b: c.b, on: true}
}

func drawText(grid [][]cell, x, y int, s string, c rgb) {
	for _, r := range s {
		setCell(grid, x, y, r, c)
		x++
	}
}

func shadeRune(v float64) rune {
	switch {
	case v > 0.82:
		return '█'
	case v > 0.58:
		return '▓'
	case v > 0.34:
		return '▒'
	default:
		return '░'
	}
}

func encode(grid [][]cell) string {
	var b strings.Builder
	// Rough capacity: chars + ANSI runs.
	b.Grow(canvasW * canvasH * 5)

	for y := 0; y < canvasH; y++ {
		last := rgb{-1, -1, -1}
		colored := false
		for x := 0; x < canvasW; x++ {
			c := grid[y][x]
			if !c.on {
				if colored {
					b.WriteString("\x1b[0m")
					colored = false
					last = rgb{-1, -1, -1}
				}
				b.WriteByte(' ')
				continue
			}
			now := rgb{c.r, c.g, c.b}
			if !colored || now != last {
				b.WriteString("\x1b[38;2;")
				b.WriteString(strconv.Itoa(now.r))
				b.WriteByte(';')
				b.WriteString(strconv.Itoa(now.g))
				b.WriteByte(';')
				b.WriteString(strconv.Itoa(now.b))
				b.WriteByte('m')
				last = now
				colored = true
			}
			b.WriteRune(c.ch)
		}
		if colored {
			b.WriteString("\x1b[0m")
		}
		b.WriteString("\x1b[K\n")
	}
	return b.String()
}

func mixRGB(a, b rgb, t float64) rgb { return lerpRGB(a, b, t) }

func lerpRGB(a, b rgb, t float64) rgb {
	t = clamp01(t)
	return rgb{
		r: int(math.Round(float64(a.r) + float64(b.r-a.r)*t)),
		g: int(math.Round(float64(a.g) + float64(b.g-a.g)*t)),
		b: int(math.Round(float64(a.b) + float64(b.b-a.b)*t)),
	}
}

func smoothstep(edge0, edge1, x float64) float64 {
	if edge0 == edge1 {
		if x < edge0 {
			return 0
		}
		return 1
	}
	t := clamp01((x - edge0) / (edge1 - edge0))
	return t * t * (3 - 2*t)
}

func easeOutCubic(t float64) float64 {
	t = clamp01(t)
	u := 1 - t
	return 1 - u*u*u
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
