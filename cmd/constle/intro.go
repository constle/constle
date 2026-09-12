package main

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/term"
	"github.com/mattn/go-runewidth"
	"github.com/muesli/termenv"
)

const (
	bootAnimationDuration = 3440 * time.Millisecond
	bootFrameInterval     = time.Second / 30
	bootSizeCheckInterval = 250 * time.Millisecond

	bootMinimumWidth  = 80
	bootMinimumHeight = 24
	bootMaximumWidth  = 100
	bootMaximumHeight = 23
)

// bootAnimationOutcome describes whether the cinematic reached its authored
// final frame. Aborted is deliberately non-fatal: terminal art must never stop
// the command the operator actually asked constle to run.
type bootAnimationOutcome uint8

const (
	bootAnimationComplete bootAnimationOutcome = iota
	bootAnimationInterrupted
	bootAnimationTerminated
	bootAnimationAborted
)

const bootSingleCellGlyphs = "█▓▒░◆·─│[]:"

// bootAnimationPolicy contains only values, rather than reading process state,
// so the precedence rules stay cheap and deterministic to test.
type bootAnimationPolicy struct {
	bareStartup           bool
	styled                bool
	noAnimation           bool
	noColor               bool
	dumbTerminal          bool
	continuousIntegration bool
	mode                  string
	width                 int
	height                int
}

// bootAnimationAllowed is the pure policy decision for the boot cinematic.
// "always" deliberately overrides CI suppression only. It cannot turn a pipe
// into a terminal, defeat reduced-output switches, or make a small viewport
// safe to repaint.
func bootAnimationAllowed(policy bootAnimationPolicy) bool {
	if !policy.bareStartup || !policy.styled || policy.noAnimation || policy.noColor || policy.dumbTerminal {
		return false
	}
	if policy.width < bootMinimumWidth || policy.height < bootMinimumHeight {
		return false
	}

	switch normalizeBootAnimationMode(policy.mode) {
	case "never":
		return false
	case "always":
		return true
	default: // auto, empty, and unknown values all fail safely into auto.
		return !policy.continuousIntegration
	}
}

func normalizeBootAnimationMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "never":
		return "never"
	case "always":
		return "always"
	default:
		return "auto"
	}
}

// shouldPlayBootAnimation is the process-state wrapper used by main. args is
// the already-normalized command argument slice (without argv[0]); consequently
// an empty slice means the bare `constle` startup screen.
func shouldPlayBootAnimation(args []string, noAnimation bool) bool {
	if !bootGlyphsAreSingleWidth() {
		return false
	}

	width, height := 0, 0
	if styled {
		width, height, _ = term.GetSize(os.Stdout.Fd())
	}

	return bootAnimationAllowed(bootAnimationPolicy{
		bareStartup:           len(args) == 0,
		styled:                styled,
		noAnimation:           noAnimation,
		noColor:               noColorRequested(),
		dumbTerminal:          strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb"),
		continuousIntegration: os.Getenv("CI") != "",
		mode:                  os.Getenv("CONSTLE_ANIMATION"),
		width:                 width,
		height:                height,
	})
}

type bootColor uint8

const (
	bootDeepDim bootColor = iota
	bootDeepBlue
	bootElectricDim
	bootElectricBlue
	bootCyanDim
	bootCyan
	bootPeriwinkleDim
	bootPeriwinkle
	bootLavenderDim
	bootLavender
	bootSoftLavenderDim
	bootSoftLavender
	bootHighlight
	bootMetadataDim
	bootMetadata
	bootColorCount
)

var bootColorHex = [bootColorCount]string{
	bootDeepDim:         "#151F49",
	bootDeepBlue:        "#243B86",
	bootElectricDim:     "#334D92",
	bootElectricBlue:    "#5D8CFF",
	bootCyanDim:         "#386D89",
	bootCyan:            "#74D9FF",
	bootPeriwinkleDim:   "#4C568D",
	bootPeriwinkle:      "#8D9BFF",
	bootLavenderDim:     "#5D477F",
	bootLavender:        "#A97CFF",
	bootSoftLavenderDim: "#745F8C",
	bootSoftLavender:    "#D8AEFF",
	bootHighlight:       "#F2F0FF",
	bootMetadataDim:     "#3D4761",
	bootMetadata:        "#7785A8",
}

var bootWaveColors = [7]bootColor{
	bootLavender,
	bootElectricBlue,
	bootPeriwinkle,
	bootDeepBlue,
	bootSoftLavender,
	bootElectricBlue,
	bootCyan,
}

func dimBootColor(color bootColor) bootColor {
	switch color {
	case bootDeepBlue:
		return bootDeepDim
	case bootElectricBlue:
		return bootElectricDim
	case bootCyan:
		return bootCyanDim
	case bootPeriwinkle:
		return bootPeriwinkleDim
	case bootLavender:
		return bootLavenderDim
	case bootSoftLavender:
		return bootSoftLavenderDim
	case bootMetadata:
		return bootMetadataDim
	default:
		return color
	}
}

type bootCell struct {
	glyph    rune
	color    bootColor
	priority uint8
	on       bool
}

type bootFrame struct {
	width  int
	height int
	cells  []bootCell
}

func newBootFrame(width, height int) *bootFrame {
	return &bootFrame{width: width, height: height, cells: make([]bootCell, width*height)}
}

func (frame *bootFrame) clear() {
	clear(frame.cells)
}

func (frame *bootFrame) put(x, y int, glyph rune, color bootColor, priority uint8) {
	if x < 0 || x >= frame.width || y < 0 || y >= frame.height || glyph == 0 {
		return
	}
	index := y*frame.width + x
	if frame.cells[index].on && frame.cells[index].priority > priority {
		return
	}
	frame.cells[index] = bootCell{glyph: glyph, color: color, priority: priority, on: true}
}

type bootParticleKind uint8

const (
	bootParticleShard bootParticleKind = iota
	bootParticleGlyph
	bootParticleDust
)

type bootParticle struct {
	kind    bootParticleKind
	side    float64
	originX float64
	originY float64
	spawn   float64
	life    float64
	speed   float64
	vy      float64
	drag    float64
	curve   float64
	length  float64
	tone    float64
	phase   float64
}

type bootEcho struct {
	angle  float64
	offset float64
	tone   float64
	phase  float64
}

type bootScene struct {
	particles []bootParticle
	echoes    []bootEcho
}

func newBootScene() *bootScene {
	rng := rand.New(rand.NewSource(0xC0571E)) // deterministic brand motion
	scene := &bootScene{
		particles: make([]bootParticle, 0, 168),
		echoes:    make([]bootEcho, 0, 64),
	}

	origin := func(side float64) (float64, float64) {
		x := 1 + rng.Float64()*44
		vertical := math.Max(2.0, 10.6*math.Sqrt(math.Max(0, 1-math.Pow(x/46, 2))))
		return side * x, (rng.Float64()*2 - 1) * vertical
	}

	for index := 0; index < 24; index++ {
		side := -1.0
		if index%2 != 0 {
			side = 1
		}
		x, y := origin(side)
		scene.particles = append(scene.particles, bootParticle{
			kind: bootParticleShard, side: side, originX: x, originY: y,
			spawn: 1.55 + rng.Float64()*.37, life: .52 + rng.Float64()*.50,
			speed: 20.8 + rng.Float64()*34.2, vy: -5.25 + rng.Float64()*10.5,
			drag: 1.8 + rng.Float64()*2, length: 1.2 + rng.Float64()*4.1,
			tone: rng.Float64(), phase: rng.Float64(),
		})
	}

	for index := 0; index < 80; index++ {
		side := -1.0
		if index%2 != 0 {
			side = 1
		}
		x, y := origin(side)
		scene.particles = append(scene.particles, bootParticle{
			kind: bootParticleGlyph, side: side, originX: x, originY: y,
			spawn: 1.58 + rng.Float64()*.52, life: .58 + rng.Float64()*.60,
			speed: 10 + rng.Float64()*29.2, vy: -6.25 + rng.Float64()*12.5,
			drag: 1.4 + rng.Float64()*1.7, curve: -1.2 + rng.Float64()*2.4,
			tone: rng.Float64(), phase: rng.Float64(),
		})
	}

	for index := 0; index < 64; index++ {
		side := -1.0
		if index%2 != 0 {
			side = 1
		}
		x, y := origin(side)
		scene.particles = append(scene.particles, bootParticle{
			kind: bootParticleDust, side: side, originX: x, originY: y,
			spawn: 1.47 + rng.Float64()*.71, life: .64 + rng.Float64()*.71,
			speed: 5.4 + rng.Float64()*18.8, vy: -3.9 + rng.Float64()*7.8,
			drag: 1 + rng.Float64()*1.6, tone: rng.Float64(), phase: rng.Float64(),
		})
	}

	for index := 0; index < 64; index++ {
		scene.echoes = append(scene.echoes, bootEcho{
			angle:  rng.Float64() * math.Pi * 2,
			offset: 2 + rng.Float64()*10,
			tone:   rng.Float64(),
			phase:  rng.Float64(),
		})
	}
	return scene
}

type bootViewport struct {
	terminalWidth  int
	terminalHeight int
	width          int
	height         int
	left           int
	top            int
}

func newBootViewport(terminalWidth, terminalHeight int) bootViewport {
	width := min(terminalWidth-1, bootMaximumWidth)
	height := min(terminalHeight-1, bootMaximumHeight)
	return bootViewport{
		terminalWidth: terminalWidth, terminalHeight: terminalHeight,
		width: width, height: height,
		left: max(0, (terminalWidth-width)/2),
		top:  max(0, (terminalHeight-height)/2),
	}
}

type bootANSI struct {
	foreground [bootColorCount]string
	background string
}

func newBootANSI(profile termenv.Profile) bootANSI {
	var ansi bootANSI
	for index, hex := range bootColorHex {
		sequence := profile.Color(hex).Sequence(false)
		if sequence != "" {
			ansi.foreground[index] = "\x1b[" + sequence + "m"
		}
	}
	if sequence := profile.Color("#050710").Sequence(true); sequence != "" {
		ansi.background = "\x1b[" + sequence + "m"
	}
	return ansi
}

// playBootAnimation renders the complete 3.44 second cinematic. Eligibility
// belongs to shouldPlayBootAnimation, but the physical terminal invariants are
// repeated here so a future direct caller cannot accidentally corrupt output.
func playBootAnimation(version string) (outcome bootAnimationOutcome) {
	if !styled || noColorRequested() || strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return bootAnimationAborted
	}
	if !bootGlyphsAreSingleWidth() {
		return bootAnimationAborted
	}

	terminalWidth, terminalHeight, err := term.GetSize(os.Stdout.Fd())
	if err != nil || terminalWidth < bootMinimumWidth || terminalHeight < bootMinimumHeight {
		return bootAnimationAborted
	}

	profile := termenv.EnvColorProfile()
	if profile == termenv.Ascii {
		return bootAnimationAborted
	}
	ansi := newBootANSI(profile)
	if ansi.background == "" {
		return bootAnimationAborted
	}
	version = safeBootVersion(version)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	// Install cleanup before entering the alternate screen: even a partial
	// first write gets a best-effort reset, visible cursor, and screen restore.
	// On success, the final lockup is appended to the same physical write that
	// restores the primary buffer, avoiding a flash of the old prompt between
	// the cinematic and its persistent settled state.
	defer func() {
		cleanup := "\x1b[0m\x1b[?1049l"
		if outcome == bootAnimationComplete {
			cleanup += encodeBootPrimaryLockup(version, terminalWidth, ansi)
		}
		cleanup += "\x1b[0m\x1b[?25h"
		if err := writeBootOutput(cleanup); err != nil && outcome == bootAnimationComplete {
			outcome = bootAnimationAborted
		}
	}()
	if err := writeBootOutput("\x1b[?1049h" + ansi.background + "\x1b[2J\x1b[H\x1b[?25l"); err != nil {
		return bootAnimationAborted
	}

	viewport := newBootViewport(terminalWidth, terminalHeight)
	frame := newBootFrame(viewport.width, viewport.height)
	scene := newBootScene()

	started := time.Now()
	ends := started.Add(bootAnimationDuration)
	nextFrame := started
	lastSizeCheck := started

	for {
		if nextFrame.After(ends) {
			nextFrame = ends
		}
		if received := waitForBootDeadline(nextFrame, signals); received != nil {
			return bootAnimationOutcomeForSignal(received)
		}

		now := time.Now()
		if now.Sub(lastSizeCheck) >= bootSizeCheckInterval {
			newWidth, newHeight, sizeErr := term.GetSize(os.Stdout.Fd())
			if sizeErr != nil || newWidth < bootMinimumWidth || newHeight < bootMinimumHeight {
				return bootAnimationAborted
			}
			if newWidth != viewport.terminalWidth || newHeight != viewport.terminalHeight {
				terminalWidth, terminalHeight = newWidth, newHeight
				viewport = newBootViewport(newWidth, newHeight)
				frame = newBootFrame(viewport.width, viewport.height)
				if err := writeBootOutput(ansi.background + "\x1b[2J\x1b[H"); err != nil {
					return bootAnimationAborted
				}
			}
			lastSizeCheck = now
		}

		elapsed := now.Sub(started)
		if elapsed > bootAnimationDuration {
			elapsed = bootAnimationDuration
		}
		renderBootFrame(frame, scene, elapsed.Seconds(), version)
		if err := writeBootOutput(encodeBootFrame(frame, viewport, ansi)); err != nil {
			return bootAnimationAborted
		}

		select {
		case received := <-signals:
			return bootAnimationOutcomeForSignal(received)
		default:
		}
		if elapsed >= bootAnimationDuration {
			return bootAnimationComplete
		}

		// Derive the next deadline from the original epoch. If rendering or a
		// slow terminal misses a frame, the next iteration skips ahead instead
		// of stretching the authored timing beyond 3.44 seconds.
		frameNumber := int(time.Since(started)/bootFrameInterval) + 1
		nextFrame = started.Add(time.Duration(frameNumber) * bootFrameInterval)
	}
}

func bootAnimationOutcomeForSignal(received os.Signal) bootAnimationOutcome {
	if received == syscall.SIGTERM {
		return bootAnimationTerminated
	}
	return bootAnimationInterrupted
}

func waitForBootDeadline(deadline time.Time, signals <-chan os.Signal) os.Signal {
	delay := time.Until(deadline)
	if delay <= 0 {
		select {
		case received := <-signals:
			return received
		default:
			return nil
		}
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case received := <-signals:
		return received
	case <-timer.C:
		return nil
	}
}

func bootGlyphsAreSingleWidth() bool {
	for _, glyph := range bootSingleCellGlyphs {
		if runewidth.RuneWidth(glyph) != 1 {
			return false
		}
	}
	return true
}

func writeBootOutput(output string) error {
	stdoutMu.Lock()
	defer stdoutMu.Unlock()
	_, err := os.Stdout.WriteString(output)
	return err
}

func safeBootVersion(version string) string {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	var clean strings.Builder
	for _, char := range version {
		if clean.Len() >= 32 {
			break
		}
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune(".-+_", char) {
			clean.WriteRune(char)
		}
	}
	if clean.Len() == 0 {
		return "dev"
	}
	return clean.String()
}

func renderBootFrame(frame *bootFrame, scene *bootScene, elapsed float64, version string) {
	frame.clear()
	cx := float64(frame.width-1) / 2
	cy := float64(frame.height-1) / 2

	drawBootLogo(frame, elapsed, cx, cy)
	drawBootWave(frame, scene, elapsed, cx, cy)
	drawBootParticles(frame, scene, elapsed, cx, cy)
	drawBootSeedMark(frame, elapsed, cx, cy)
	drawBootSpark(frame, elapsed, cx, cy)
	drawBootSeam(frame, elapsed, cx, cy)
	drawBootStatus(frame, elapsed, version, cx, cy)
}

var bootLogo = [7][9]string{
	{
		"..######.", ".##......", "##.......", "##.......", "##.......",
		"##.......", "##.......", ".##......", "..######.",
	},
	{
		"..##.##..", ".##...##.", "##.....##", "##.....##", "##..#..##",
		"##.....##", "##.....##", ".##...##.", "..##.##..",
	},
	{
		"##.....##", "###....##", "####...##", "##.##..##", "##..##.##",
		"##...####", "##....###", "##.....##", "##.....##",
	},
	{
		"..######.", ".##......", "##.......", "##.......", ".######..",
		".......##", ".......##", "......##.", ".######..",
	},
	{
		".#######.", "...###...", "...###...", "...###...", "...###...",
		"...###...", "...###...", "...###...", "...###...",
	},
	{
		".##......", "##.......", "##.......", "##.......", "##.......",
		"##.......", "##.......", "##.......", ".#######.",
	},
	{
		".#######.", "##.......", "##.......", "##.......", ".######..",
		"##.......", "##.......", "##.......", ".#######.",
	},
}

var bootLetterRank = [7]int{3, 2, 1, 0, 1, 2, 3}

func drawBootLogo(frame *bootFrame, elapsed, cx, cy float64) {
	aperture := easeOutQuart((elapsed - 1.76) / .78)
	if aperture <= 0 {
		return
	}

	const logoWidth = 75
	left := (frame.width - logoWidth) / 2
	top := int(math.Round(cy)) - 4
	halfWidth := float64(logoWidth) * .52 * aperture
	sheenActive := elapsed >= 2.40 && elapsed <= 2.72
	sheenProgress := easeOutCubic((elapsed - 2.40) / .24)
	sheenX := cx + float64(logoWidth)*.55*(sheenProgress-.5)*2

	for letterIndex, letter := range bootLogo {
		letterLeft := left + letterIndex*11
		for row, pattern := range letter {
			for column, value := range pattern {
				if value != '#' {
					continue
				}
				x := letterLeft + column
				y := top + row
				if math.Abs(float64(x)-cx) > halfWidth+1 {
					continue
				}

				cellNoise := bootNoise(letterIndex*13+column, row, 91)
				start := 2.02 + float64(bootLetterRank[letterIndex])*.105 + cellNoise*.045
				progress := easeOutCubic((elapsed - start) / .34)
				threshold := cellNoise * .68
				solidity := clampBoot((progress - threshold) / math.Max(.18, 1-threshold))
				if solidity <= .015 {
					continue
				}

				color := bootLogoColor(float64(x-left) / float64(logoWidth-1))
				if sheenActive && math.Abs(float64(x)-sheenX) < 3.8 {
					color = bootHighlight
				}
				glyph := bootStrengthGlyph(solidity)
				priority := uint8(20)

				isCore := letterIndex == 1 && row == 4 && column == 4
				if isCore {
					glyph = '◆'
					color = bootCyan
					priority = 26
					pulse := math.Exp(-math.Pow((elapsed-2.58)/.095, 2))
					if pulse > .54 {
						color = bootHighlight
					}
					if elapsed >= 2.44 && pulse > .12 {
						for _, offset := range [][2]int{{-2, 0}, {2, 0}, {0, -1}, {0, 1}} {
							frame.put(x+offset[0], y+offset[1], '·', bootCyanDim, 19)
						}
					}
				}
				frame.put(x, y, glyph, color, priority)
			}
		}
	}
}

func bootLogoColor(position float64) bootColor {
	switch {
	case position < .12:
		return bootSoftLavender
	case position < .28:
		return bootLavender
	case position < .43:
		return bootSoftLavender
	case position < .58:
		return bootHighlight
	case position < .75:
		return bootPeriwinkle
	case position < .90:
		return bootElectricBlue
	default:
		return bootCyan
	}
}

func drawBootWave(frame *bootFrame, scene *bootScene, elapsed, cx, cy float64) {
	if elapsed < .33 || elapsed > 2.69 {
		return
	}

	expansion := easeOutQuart((elapsed - .33) / 1.03)
	radius := 1 + 45*expansion
	inhale := smoothBoot((elapsed - 1.36) / .20)
	if elapsed <= 1.56 {
		radius -= 2.25 * inhale
	} else {
		radius -= 2.25
	}
	shift := bootSplitShift(elapsed)
	dissolve := 1 - easeOutCubic((elapsed-1.92)/.77)
	crest := 1 + .18*smoothBoot(1-math.Abs(elapsed-1.43)/.17)
	if dissolve <= 0 {
		return
	}

	maxX := int(math.Ceil(radius)) + 2
	maxY := int(math.Ceil(radius/4.05)) + 2
	for dy := -maxY; dy <= maxY; dy++ {
		for sourceX := -maxX; sourceX <= maxX; sourceX++ {
			distance := math.Hypot(float64(sourceX), float64(dy)*4.05)
			bestStrength := 0.0
			bestBand := -1
			for band := 0; band < len(bootWaveColors); band++ {
				shellRadius := radius - float64(band)*6.45
				if shellRadius <= 0 {
					continue
				}
				thickness := 1.30 + float64(band)*.055
				strength := 1 - math.Abs(distance-shellRadius)/thickness
				if strength > bestStrength {
					bestStrength = strength
					bestBand = band
				}
			}
			if bestBand < 0 || bestStrength <= 0 {
				continue
			}

			noise := bootNoise(sourceX, dy, bestBand+17)
			strength := clampBoot(bestStrength * dissolve * crest * (1 - float64(bestBand)*.035))
			if strength < .11 || (strength < .48 && noise > strength*1.58) {
				continue
			}
			glyph := bootStrengthGlyph(clampBoot(strength + (noise-.5)*.11))
			color := bootWaveColors[bestBand]
			if strength < .46 {
				color = dimBootColor(color)
			} else if strength > .91 && bestBand != 3 {
				color = bootHighlight
			}

			positions := []float64{float64(sourceX)}
			if shift > .2 {
				if sourceX == 0 {
					positions = []float64{-shift, shift}
				} else if sourceX < 0 {
					positions[0] -= shift
				} else {
					positions[0] += shift
				}
			}

			for _, position := range positions {
				x := int(math.Round(cx + position))
				y := int(math.Round(cy)) + dy
				cellGlyph := glyph
				cellColor := color
				priority := uint8(31)
				if shift > .2 && absInt(sourceX) <= 1 && elapsed < 2.03 && dy%2 == 0 {
					cellGlyph = '['
					if position < 0 {
						cellGlyph = ']'
					}
					cellColor = bootHighlight
					priority = 34
				}
				frame.put(x, y, cellGlyph, cellColor, priority)
			}
		}
	}

	drawBootEchoes(frame, scene, elapsed, cx, cy, radius, shift, dissolve)
}

func drawBootEchoes(frame *bootFrame, scene *bootScene, elapsed, cx, cy, radius, shift, dissolve float64) {
	presence := easeOutCubic((elapsed - .42) / .32)
	if presence <= 0 {
		return
	}
	for index, echo := range scene.echoes {
		echoRadius := radius + echo.offset
		dx := math.Cos(echo.angle) * echoRadius
		dy := math.Sin(echo.angle) * echoRadius / 4.05
		if shift > .2 {
			if dx < 0 {
				dx -= shift
			} else {
				dx += shift
			}
		}
		strength := presence * dissolve * (1 - echo.offset/14) * (.34 + echo.phase*.52)
		if strength < .10 || (strength < .35 && bootNoise(index, int(elapsed*30), 7131) > strength*1.85) {
			continue
		}
		glyph := '·'
		if index%8 == 0 {
			glyph = '░'
		} else if index%4 == 0 {
			glyph = ':'
		}
		color := bootDeepDim
		if echo.tone > .58 {
			color = bootLavenderDim
		} else if echo.tone > .30 {
			color = bootElectricDim
		}
		frame.put(int(math.Round(cx+dx)), int(math.Round(cy+dy)), glyph, color, 29)
	}
}

func drawBootParticles(frame *bootFrame, scene *bootScene, elapsed, cx, cy float64) {
	if elapsed < 1.46 || elapsed > 3.05 {
		return
	}
	logoLeft := (frame.width - 75) / 2
	logoTop := int(math.Round(cy)) - 4

	for index, particle := range scene.particles {
		age := elapsed - particle.spawn
		if age < 0 || age > particle.life {
			continue
		}
		strength := bootParticleEnvelope(age, particle.life)
		distance := particle.speed * (1 - math.Exp(-particle.drag*age)) / particle.drag
		spawnShift := bootSplitShift(particle.spawn)
		x := cx + particle.originX + particle.side*(spawnShift+distance)
		y := cy + particle.originY + particle.vy*age + particle.curve*age*age

		if elapsed > 2.20 && x > float64(logoLeft-2) && x < float64(logoLeft+77) &&
			y > float64(logoTop-1) && y < float64(logoTop+12) {
			strength *= .08
		}
		if strength < .055 || (strength < .32 && bootNoise(index, int(age*60), 377) > strength*2.1) {
			continue
		}

		switch particle.kind {
		case bootParticleShard:
			drawBootShard(frame, particle, x, y, strength)
		case bootParticleGlyph:
			drawBootGlyphParticle(frame, particle, x, y, age, strength)
		case bootParticleDust:
			color := bootDeepDim
			if particle.tone > .55 {
				color = bootPeriwinkleDim
			}
			frame.put(int(math.Round(x)), int(math.Round(y)), '·', color, 40)
		}
	}
}

func drawBootShard(frame *bootFrame, particle bootParticle, x, y, strength float64) {
	color := bootLavender
	if particle.tone > .5 {
		color = bootCyan
	}
	if strength < .38 {
		color = dimBootColor(color)
	}
	length := max(1, int(math.Round(particle.length*(.45+.55*strength))))
	headX := int(math.Round(x))
	headY := int(math.Round(y))
	for trail := length; trail >= 1; trail-- {
		trailStrength := strength * (1 - float64(trail)/float64(length+1))
		trailColor := color
		if trailStrength < .46 {
			trailColor = dimBootColor(color)
		}
		frame.put(headX-int(particle.side)*trail, headY, '─', trailColor, 43)
	}
	headGlyph := '▓'
	if strength > .72 {
		headGlyph = '█'
	}
	frame.put(headX, headY, headGlyph, bootHighlight, 46)
}

func drawBootGlyphParticle(frame *bootFrame, particle bootParticle, x, y, age, strength float64) {
	progress := clampBoot(age / particle.life)
	stages := []rune{'█', '▓', '▒', '░', '·'}
	stage := min(len(stages)-1, int(progress*float64(len(stages))))
	glyph := stages[stage]
	color := bootElectricBlue
	if particle.tone > .52 {
		color = bootSoftLavender
	}
	if strength < .43 {
		color = dimBootColor(color)
	}
	headX := int(math.Round(x))
	headY := int(math.Round(y))
	for trail := 2; trail >= 1; trail-- {
		frame.put(headX-int(particle.side)*trail, headY, '·', dimBootColor(color), 41)
	}
	frame.put(headX, headY, glyph, color, 44)
}

func bootParticleEnvelope(age, life float64) float64 {
	progress := clampBoot(age / life)
	attack := easeOutCubic(age / .07)
	fade := 1 - smoothBoot((progress-.42)/.58)
	return clampBoot(attack * fade)
}

var bootSeedMark = [11]string{
	"...##.##...",
	"..##...##..",
	".##.....##.",
	"##.......##",
	"##.......##",
	"##...D...##",
	"##.......##",
	"##.......##",
	".##.....##.",
	"..##...##..",
	"...##.##...",
}

func drawBootSeedMark(frame *bootFrame, elapsed, cx, cy float64) {
	if elapsed < .16 || elapsed > 1.03 {
		return
	}
	fadeIn := easeOutCubic((elapsed - .16) / .26)
	fadeOut := 1 - easeOutCubic((elapsed-.72)/.31)
	overall := fadeIn * fadeOut
	left := int(math.Round(cx)) - 5
	top := int(math.Round(cy)) - 5

	for row, pattern := range bootSeedMark {
		for column, value := range pattern {
			if value == '.' {
				continue
			}
			distance := math.Hypot(float64(column-5), float64(row-5))
			progress := easeOutCubic((elapsed - (.16 + distance*.018)) / .22)
			strength := overall * progress
			if strength < .08 || (strength < .38 && bootNoise(column, row, 211) > strength*1.9) {
				continue
			}
			glyph := bootStrengthGlyph(strength)
			color := bootLavender
			if column > 5 {
				color = bootElectricBlue
			}
			if strength < .46 {
				color = dimBootColor(color)
			}
			priority := uint8(53)
			if value == 'D' {
				glyph = '◆'
				color = bootHighlight
				priority = 56
			}
			frame.put(left+column, top+row, glyph, color, priority)
		}
	}
}

func drawBootSpark(frame *bootFrame, elapsed, cx, cy float64) {
	if elapsed < .06 || elapsed > .55 {
		return
	}
	ignite := easeOutCubic((elapsed - .06) / .23)
	fade := 1 - easeOutCubic((elapsed-.39)/.16)
	breath := .68 + .32*math.Sin(clampBoot((elapsed-.06)/.33)*math.Pi)
	strength := ignite * fade * breath
	if strength <= 0 {
		return
	}

	x := int(math.Round(cx))
	y := int(math.Round(cy))
	if strength > .12 {
		for _, offset := range [][2]int{{-3, 0}, {3, 0}, {0, -2}, {0, 2}, {-2, -1}, {2, -1}, {-2, 1}, {2, 1}} {
			frame.put(x+offset[0], y+offset[1], '·', bootLavenderDim, 57)
		}
	}
	if ignite > .42 {
		for offset := 1; offset <= 2; offset++ {
			frame.put(x-offset, y, '─', bootPeriwinkleDim, 59)
			frame.put(x+offset, y, '─', bootCyanDim, 59)
		}
		frame.put(x, y-1, '│', bootSoftLavenderDim, 59)
		frame.put(x, y+1, '│', bootElectricDim, 59)
	}
	color := bootHighlight
	if strength < .5 {
		color = bootSoftLavender
	}
	frame.put(x, y, '◆', color, 62)
}

func drawBootSeam(frame *bootFrame, elapsed, cx, cy float64) {
	anticipation := smoothBoot((elapsed-1.36)/.16) * (1 - smoothBoot((elapsed-1.67)/.23))
	if anticipation <= 0 {
		return
	}
	halfHeight := int(math.Round(10 * easeOutCubic((elapsed-1.38)/.12)))
	flash := math.Exp(-math.Pow((elapsed-1.555)/.042, 2))
	color := bootSoftLavender
	if flash > .28 {
		color = bootHighlight
	}
	x := int(math.Round(cx))
	y := int(math.Round(cy))
	for offsetY := -halfHeight; offsetY <= halfHeight; offsetY++ {
		if anticipation < .34 && bootNoise(offsetY, int(elapsed*100), 5155) > anticipation*2.2 {
			continue
		}
		frame.put(x-1, y+offsetY, '│', color, 68)
		frame.put(x+1, y+offsetY, '│', color, 68)
	}
}

func drawBootStatus(frame *bootFrame, elapsed float64, version string, cx, cy float64) {
	versionProgress := easeOutCubic((elapsed - 2.67) / .18)
	readyProgress := easeOutCubic((elapsed - 2.79) / .18)
	if versionProgress <= 0 {
		return
	}

	prefix := "v" + version + "   ·   RUNTIME "
	cursor := '_'
	if elapsed >= 3.08 && elapsed < 3.24 {
		cursor = ' '
	}
	ready := "READY" + string(cursor)
	totalWidth := len([]rune(prefix + ready))
	left := int(math.Round(cx)) - totalWidth/2
	y := int(math.Round(cy)) + 7
	if versionProgress < .55 {
		y++
	}

	metadataColor := bootMetadata
	if versionProgress < .48 {
		metadataColor = bootMetadataDim
	}
	drawBootText(frame, left, y, prefix, metadataColor, 78)
	if readyProgress > 0 {
		readyColor := bootCyan
		if readyProgress < .48 {
			readyColor = bootCyanDim
		}
		drawBootText(frame, left+len([]rune(prefix)), y, ready, readyColor, 79)
	}
	frame.put(left-2, y, '◆', bootElectricBlue, 79)
}

func drawBootText(frame *bootFrame, x, y int, text string, color bootColor, priority uint8) {
	for _, glyph := range text {
		frame.put(x, y, glyph, color, priority)
		x++
	}
}

func bootSplitShift(elapsed float64) float64 {
	if elapsed <= 1.56 {
		return 0
	}
	if elapsed < 1.64 {
		return 4 * easeInQuad((elapsed-1.56)/.08)
	}
	return 4 + 43*easeOutExpo((elapsed-1.64)/.60)
}

func bootStrengthGlyph(strength float64) rune {
	switch {
	case strength > .80:
		return '█'
	case strength > .61:
		return '▓'
	case strength > .41:
		return '▒'
	case strength > .19:
		return '░'
	default:
		return '·'
	}
}

func bootNoise(x, y, salt int) float64 {
	value := uint32(int32(x))*0x45d9f3b ^ uint32(int32(y))*0x119de1f3 ^ uint32(salt)*0x27d4eb2d
	value ^= value >> 16
	value *= 0x7feb352d
	value ^= value >> 15
	value *= 0x846ca68b
	value ^= value >> 16
	return float64(value&0xffff) / 65535
}

func clampBoot(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func smoothBoot(value float64) float64 {
	value = clampBoot(value)
	return value * value * (3 - 2*value)
}

func easeInQuad(value float64) float64 {
	value = clampBoot(value)
	return value * value
}

func easeOutCubic(value float64) float64 {
	value = clampBoot(value)
	remaining := 1 - value
	return 1 - remaining*remaining*remaining
}

func easeOutQuart(value float64) float64 {
	value = clampBoot(value)
	remaining := 1 - value
	return 1 - remaining*remaining*remaining*remaining
}

func easeOutExpo(value float64) float64 {
	value = clampBoot(value)
	if value >= 1 {
		return 1
	}
	return 1 - math.Pow(2, -10*value)
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

// encodeBootPrimaryLockup redraws the cinematic's settled state after the
// alternate screen is restored. It uses natural line flow rather than cursor
// addressing so the result becomes ordinary, copy-safe terminal scrollback.
func encodeBootPrimaryLockup(version string, terminalWidth int, ansi bootANSI) string {
	const logoWidth = 75
	left := max(0, (terminalWidth-logoWidth)/2)

	var output strings.Builder
	output.Grow(1600)
	output.WriteString("\r\n")
	for row := 0; row < len(bootLogo[0]); row++ {
		output.WriteString(strings.Repeat(" ", left))
		activeColor := bootColorCount
		for x := 0; x < logoWidth; x++ {
			letterIndex := x / 11
			letterColumn := x % 11
			if letterIndex >= len(bootLogo) || letterColumn >= len(bootLogo[letterIndex][row]) ||
				bootLogo[letterIndex][row][letterColumn] != '#' {
				output.WriteByte(' ')
				continue
			}

			color := bootLogoColor(float64(x) / float64(logoWidth-1))
			glyph := '█'
			if letterIndex == 1 && row == 4 && letterColumn == 4 {
				color = bootCyan
				glyph = '◆'
			}
			if color != activeColor {
				output.WriteString(ansi.foreground[color])
				activeColor = color
			}
			output.WriteRune(glyph)
		}
		output.WriteString("\x1b[39m\r\n")
	}

	version = safeBootVersion(version)
	statusTail := "  v" + version + "   ·   RUNTIME "
	statusReady := "READY_"
	statusWidth := 1 + len([]rune(statusTail+statusReady))
	output.WriteString(strings.Repeat(" ", max(0, (terminalWidth-statusWidth)/2)))
	output.WriteString(ansi.foreground[bootElectricBlue])
	output.WriteRune('◆')
	output.WriteString(ansi.foreground[bootMetadata])
	output.WriteString(statusTail)
	output.WriteString(ansi.foreground[bootCyan])
	output.WriteString(statusReady)
	output.WriteString("\x1b[39m\r\n\r\n")
	return output.String()
}

func encodeBootFrame(frame *bootFrame, viewport bootViewport, ansi bootANSI) string {
	var output strings.Builder
	output.Grow(frame.width * frame.height * 3)

	for y := 0; y < frame.height; y++ {
		fmt.Fprintf(&output, "\x1b[%d;%dH", viewport.top+y+1, viewport.left+1)
		lastActive := -1
		for x := frame.width - 1; x >= 0; x-- {
			if frame.cells[y*frame.width+x].on {
				lastActive = x
				break
			}
		}

		activeColor := bootColorCount
		for x := 0; x <= lastActive; x++ {
			cell := frame.cells[y*frame.width+x]
			if !cell.on {
				if activeColor != bootColorCount {
					output.WriteString("\x1b[39m")
					activeColor = bootColorCount
				}
				output.WriteByte(' ')
				continue
			}
			if cell.color != activeColor {
				output.WriteString(ansi.foreground[cell.color])
				activeColor = cell.color
			}
			output.WriteRune(cell.glyph)
		}
		if activeColor != bootColorCount {
			output.WriteString("\x1b[39m")
		}
		output.WriteString("\x1b[K")
	}
	return output.String()
}
