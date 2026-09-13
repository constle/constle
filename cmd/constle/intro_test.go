package main

import (
	"io"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseGlobalArgs(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantRemaining   []string
		wantNoAnimation bool
	}{
		{
			name: "no arguments",
		},
		{
			name:            "bare no-animation flag",
			args:            []string{"--no-animation"},
			wantNoAnimation: true,
		},
		{
			name:            "global flag before help",
			args:            []string{"--no-animation", "help"},
			wantRemaining:   []string{"help"},
			wantNoAnimation: true,
		},
		{
			name:            "repeated global flag is idempotent",
			args:            []string{"--no-animation", "--no-animation"},
			wantNoAnimation: true,
		},
		{
			name:            "global flag before a subcommand preserves its arguments",
			args:            []string{"--no-animation", "run", "--backend=docker", "agent.yaml"},
			wantRemaining:   []string{"run", "--backend=docker", "agent.yaml"},
			wantNoAnimation: true,
		},
		{
			name:          "flag after a subcommand belongs to that subcommand",
			args:          []string{"run", "--no-animation", "agent.yaml"},
			wantRemaining: []string{"run", "--no-animation", "agent.yaml"},
		},
		{
			name:          "lookalike flag is not consumed",
			args:          []string{"--no-animation=true"},
			wantRemaining: []string{"--no-animation=true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRemaining, gotNoAnimation := parseGlobalArgs(tt.args)
			if !slices.Equal(gotRemaining, tt.wantRemaining) {
				t.Errorf("remaining = %#v, want %#v", gotRemaining, tt.wantRemaining)
			}
			if gotNoAnimation != tt.wantNoAnimation {
				t.Errorf("noAnimation = %v, want %v", gotNoAnimation, tt.wantNoAnimation)
			}
		})
	}
}

func TestMainNonInteractiveStartupContracts(t *testing.T) {
	oldArgs, oldStdout, oldStyled := os.Args, os.Stdout, styled
	t.Cleanup(func() {
		os.Args, os.Stdout, styled = oldArgs, oldStdout, oldStyled
	})
	styled = false

	run := func(args ...string) string {
		t.Helper()
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe() error: %v", err)
		}
		os.Stdout = writer
		os.Args = append([]string{"constle"}, args...)
		main()
		if err := writer.Close(); err != nil {
			t.Fatalf("stdout writer close error: %v", err)
		}
		output, err := io.ReadAll(reader)
		if closeErr := reader.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			t.Fatalf("stdout capture error: %v", err)
		}
		return string(output)
	}

	bare := run()
	noAnimation := run("--no-animation")
	help := run("help")
	if bare != noAnimation || bare != help {
		t.Error("bare, --no-animation, and explicit help output diverged in non-interactive mode")
	}
	if strings.ContainsRune(bare, '\x1b') {
		t.Error("non-interactive startup emitted an ANSI escape")
	}
	if !strings.Contains(bare, "constle [--no-animation]") {
		t.Error("plain help does not document --no-animation")
	}
	if got, want := run("version"), "constle v"+constleVersion+"\n"; got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
}

func TestNoColorRequestedTreatsEmptyValueAsSet(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	presentValue, present := os.LookupEnv("NO_COLOR")
	if !present || presentValue != "" {
		t.Fatalf("test setup did not create an empty-but-present NO_COLOR: present=%v value=%q", present, presentValue)
	}
	if !noColorRequested() {
		t.Error("empty-but-present NO_COLOR was treated as unset")
	}
}

func TestBootAnimationAllowed(t *testing.T) {
	eligible := bootAnimationPolicy{
		bareStartup: true,
		styled:      true,
		mode:        "auto",
		width:       80,
		height:      24,
	}

	tests := []struct {
		name   string
		mutate func(*bootAnimationPolicy)
		want   bool
	}{
		{
			name: "bare interactive startup at minimum size",
			want: true,
		},
		{
			name: "empty mode defaults to auto",
			mutate: func(p *bootAnimationPolicy) {
				p.mode = ""
			},
			want: true,
		},
		{
			name: "always is eligible",
			mutate: func(p *bootAnimationPolicy) {
				p.mode = "always"
			},
			want: true,
		},
		{
			name: "explicit help and every other non-bare invocation are ineligible",
			mutate: func(p *bootAnimationPolicy) {
				p.bareStartup = false
			},
		},
		{
			name: "stdout pipe is ineligible",
			mutate: func(p *bootAnimationPolicy) {
				p.styled = false
			},
		},
		{
			name: "no-animation flag is absolute",
			mutate: func(p *bootAnimationPolicy) {
				p.noAnimation = true
			},
		},
		{
			name: "NO_COLOR is absolute",
			mutate: func(p *bootAnimationPolicy) {
				p.noColor = true
			},
		},
		{
			name: "TERM dumb is absolute",
			mutate: func(p *bootAnimationPolicy) {
				p.dumbTerminal = true
			},
		},
		{
			name: "one column below minimum is ineligible",
			mutate: func(p *bootAnimationPolicy) {
				p.width = 79
			},
		},
		{
			name: "one row below minimum is ineligible",
			mutate: func(p *bootAnimationPolicy) {
				p.height = 23
			},
		},
		{
			name: "unknown terminal size is ineligible",
			mutate: func(p *bootAnimationPolicy) {
				p.width = 0
				p.height = 0
			},
		},
		{
			name: "CI suppresses auto mode",
			mutate: func(p *bootAnimationPolicy) {
				p.continuousIntegration = true
			},
		},
		{
			name: "always overrides CI only",
			mutate: func(p *bootAnimationPolicy) {
				p.continuousIntegration = true
				p.mode = "always"
			},
			want: true,
		},
		{
			name: "never suppresses an otherwise eligible startup",
			mutate: func(p *bootAnimationPolicy) {
				p.mode = "never"
			},
		},
		{
			name: "unknown mode falls back to auto",
			mutate: func(p *bootAnimationPolicy) {
				p.mode = "sometimes"
			},
			want: true,
		},
		{
			name: "unknown mode keeps CI suppression",
			mutate: func(p *bootAnimationPolicy) {
				p.mode = "sometimes"
				p.continuousIntegration = true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := eligible
			if tt.mutate != nil {
				tt.mutate(&policy)
			}
			if got := bootAnimationAllowed(policy); got != tt.want {
				t.Errorf("bootAnimationAllowed(%+v) = %v, want %v", policy, got, tt.want)
			}
		})
	}
}

func TestBootAnimationAlwaysCannotBypassHardGates(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*bootAnimationPolicy)
	}{
		{"non-bare invocation", func(p *bootAnimationPolicy) { p.bareStartup = false }},
		{"stdout pipe", func(p *bootAnimationPolicy) { p.styled = false }},
		{"no-animation flag", func(p *bootAnimationPolicy) { p.noAnimation = true }},
		{"NO_COLOR", func(p *bootAnimationPolicy) { p.noColor = true }},
		{"TERM dumb", func(p *bootAnimationPolicy) { p.dumbTerminal = true }},
		{"narrow terminal", func(p *bootAnimationPolicy) { p.width = 79 }},
		{"short terminal", func(p *bootAnimationPolicy) { p.height = 23 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := bootAnimationPolicy{
				bareStartup:           true,
				styled:                true,
				continuousIntegration: true,
				mode:                  "always",
				width:                 80,
				height:                24,
			}
			tt.mutate(&policy)
			if bootAnimationAllowed(policy) {
				t.Errorf("always bypassed hard gate: %+v", policy)
			}
		})
	}
}

func TestShouldPlayBootAnimationRejectsNonStartupInvocations(t *testing.T) {
	for _, args := range [][]string{
		{"help"},
		{"--help"},
		{"-h"},
		{"version"},
		{"init"},
		{"run", "agent.yaml"},
		{"validate", "agent.yaml"},
		{"identity", "show", "agent"},
		{"webhook-keygen", "approver"},
		{"audit", "verify", "audit.jsonl"},
		{"ps"},
		{"stop", "0123456789abcdef"},
		{"not-a-command"},
	} {
		if shouldPlayBootAnimation(args, false) {
			t.Errorf("shouldPlayBootAnimation(%q, false) = true, want false", args)
		}
	}

	if shouldPlayBootAnimation(nil, true) {
		t.Error("--no-animation did not suppress a bare startup")
	}
}

func TestNormalizeBootAnimationMode(t *testing.T) {
	tests := map[string]string{
		"":             "auto",
		"auto":         "auto",
		" AUTO ":       "auto",
		"never":        "never",
		" NeVeR\t":     "never",
		"always":       "always",
		"\nALWAYS ":    "always",
		"occasionally": "auto",
	}

	for input, want := range tests {
		if got := normalizeBootAnimationMode(input); got != want {
			t.Errorf("normalizeBootAnimationMode(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestBootSplitKeyframeCreatesCleanCentralAperture(t *testing.T) {
	const elapsed = 1.66
	frame := newBootFrame(100, 23)
	cx := float64(frame.width-1) / 2
	cy := float64(frame.height-1) / 2
	drawBootWave(frame, newBootScene(), elapsed, cx, cy)

	shift := bootSplitShift(elapsed)
	if shift <= 4 {
		t.Fatalf("split shift at %.2fs = %.2f, want a clearly opened wave", elapsed, shift)
	}

	// Every wave source cell is translated away from the seam by shift. Leave
	// one cell for rounding and assert that the authored opening is physically
	// empty, rather than merely painted over by the logo later.
	for y := 0; y < frame.height; y++ {
		for x := 0; x < frame.width; x++ {
			if absFloat(float64(x)-cx) >= shift-1 {
				continue
			}
			if cell := frame.cells[y*frame.width+x]; cell.on {
				t.Fatalf("split aperture contains %q at (%d,%d), shift %.2f", cell.glyph, x, y, shift)
			}
		}
	}

	var leftRim, rightRim bool
	for _, cell := range frame.cells {
		leftRim = leftRim || cell.glyph == ']'
		rightRim = rightRim || cell.glyph == '['
	}
	if !leftRim || !rightRim {
		t.Fatalf("split keyframe rims = (left %v, right %v), want both halves visibly edged", leftRim, rightRim)
	}

	if got := bootSplitShift(1.56); got != 0 {
		t.Errorf("split starts before its authored cue: shift at 1.56s = %v", got)
	}
	if got := bootSplitShift(1.64); got != 4 {
		t.Errorf("split anticipation at 1.64s = %v, want 4", got)
	}
}

func TestBootFinalFrameContainsFullLogoAndRuntimeStatus(t *testing.T) {
	viewport := newBootViewport(bootMinimumWidth, bootMinimumHeight)
	frame := newBootFrame(viewport.width, viewport.height)
	renderBootFrame(frame, newBootScene(), bootAnimationDuration.Seconds(), constleVersion)

	const logoWidth = 75
	computedWidth := (len(bootLogo)-1)*11 + len(bootLogo[0][0])
	if computedWidth != logoWidth {
		t.Fatalf("wordmark layout width = %d, want %d columns", computedWidth, logoWidth)
	}

	cy := float64(frame.height-1) / 2
	left := (frame.width - logoWidth) / 2
	top := int(cy+0.5) - 4
	wantCells := 0
	for letterIndex, letter := range bootLogo {
		for row, pattern := range letter {
			for column, value := range pattern {
				if value != '#' {
					continue
				}
				wantCells++
				x := left + letterIndex*11 + column
				y := top + row
				cell := frame.cells[y*frame.width+x]
				if !cell.on {
					t.Errorf("final wordmark is missing letter %d cell (%d,%d)", letterIndex, column, row)
					continue
				}
				if letterIndex == 1 && row == 4 && column == 4 {
					if cell.glyph != '◆' {
						t.Errorf("O core glyph = %q, want ◆", cell.glyph)
					}
				} else if cell.glyph != '█' {
					t.Errorf("settled logo glyph at (%d,%d) = %q, want █", x, y, cell.glyph)
				}
			}
		}
	}
	if wantCells == 0 {
		t.Fatal("test bug: bootLogo contains no cells")
	}

	statusY := int(cy+0.5) + 7
	status := bootFrameRow(frame, statusY)
	wantStatus := "v" + constleVersion + "   ·   RUNTIME READY_"
	if !strings.Contains(status, wantStatus) {
		t.Errorf("final status row = %q, want it to contain %q", status, wantStatus)
	}
	if strings.Contains(status, "v0.8.0") {
		t.Errorf("final status retained preview placeholder version: %q", status)
	}
}

func TestEncodeBootFrameUsesViewportDimensionsWithoutNewlines(t *testing.T) {
	frame := newBootFrame(4, 2)
	frame.put(0, 0, 'A', bootLavender, 1)
	frame.put(3, 0, 'D', bootLavender, 1)
	viewport := bootViewport{left: 7, top: 2, width: 4, height: 2}
	ansi := bootANSI{}
	ansi.foreground[bootLavender] = "<lav>"

	got := encodeBootFrame(frame, viewport, ansi)
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("encoded frame contains a line break: %q", got)
	}
	if gotRows := strings.Count(got, "H"); gotRows != frame.height {
		t.Errorf("encoded cursor rows = %d, want frame height %d", gotRows, frame.height)
	}
	if clears := strings.Count(got, "\x1b[K"); clears != frame.height {
		t.Errorf("encoded line clears = %d, want frame height %d", clears, frame.height)
	}

	firstRowAt := "\x1b[3;8H"
	secondRowAt := "\x1b[4;8H"
	if !strings.HasPrefix(got, firstRowAt) {
		t.Fatalf("encoded frame starts at the wrong viewport position: %q", got)
	}
	second := strings.Index(got, secondRowAt)
	if second < 0 {
		t.Fatalf("encoded frame omits its second viewport row: %q", got)
	}
	visibleFirstRow := got[len(firstRowAt):second]
	for _, control := range []string{"<lav>", "\x1b[39m", "\x1b[K"} {
		visibleFirstRow = strings.ReplaceAll(visibleFirstRow, control, "")
	}
	if visibleFirstRow != "A  D" {
		t.Errorf("first encoded row has visible cells %q, want %q", visibleFirstRow, "A  D")
	}
}

func TestWaitForBootDeadlineHonorsInterrupt(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt
	if got := waitForBootDeadline(time.Now().Add(time.Hour), signals); got != os.Interrupt {
		t.Errorf("queued interrupt = %v, want %v", got, os.Interrupt)
	}

	if got := waitForBootDeadline(time.Now().Add(-time.Millisecond), make(chan os.Signal)); got != nil {
		t.Errorf("elapsed deadline reported signal %v without receiving one", got)
	}
}

func TestBootAnimationOutcomePreservesSignalSemantics(t *testing.T) {
	if got := bootAnimationOutcomeForSignal(os.Interrupt); got != bootAnimationInterrupted {
		t.Errorf("interrupt outcome = %v, want %v", got, bootAnimationInterrupted)
	}
	if got := bootAnimationOutcomeForSignal(syscall.SIGTERM); got != bootAnimationTerminated {
		t.Errorf("SIGTERM outcome = %v, want %v", got, bootAnimationTerminated)
	}
}

func TestEncodeBootPrimaryLockupPersistsSettledBrand(t *testing.T) {
	var ansi bootANSI
	for index := range ansi.foreground {
		ansi.foreground[index] = "<c>"
	}

	got := encodeBootPrimaryLockup("v1.2.3", 80, ansi)
	visible := strings.ReplaceAll(got, "<c>", "")
	visible = strings.ReplaceAll(visible, "\x1b[39m", "")
	if strings.Contains(got, "\x1b[?1049") {
		t.Error("persistent lockup unexpectedly manipulates the alternate screen")
	}
	if count := strings.Count(visible, "\r\n"); count != 12 {
		t.Errorf("persistent lockup line breaks = %d, want 12", count)
	}
	if !strings.Contains(visible, "v1.2.3   ·   RUNTIME READY_") {
		t.Errorf("persistent lockup omits real version/ready state: %q", visible)
	}
	if diamonds := strings.Count(visible, "◆"); diamonds != 2 {
		t.Errorf("persistent lockup diamonds = %d, want split core plus status mark", diamonds)
	}
	if blocks := strings.Count(visible, "█"); blocks < 100 {
		t.Errorf("persistent lockup contains only %d block cells, want the complete wordmark", blocks)
	}
}

func bootFrameRow(frame *bootFrame, y int) string {
	row := make([]rune, frame.width)
	for x := range row {
		row[x] = ' '
		cell := frame.cells[y*frame.width+x]
		if cell.on {
			row[x] = cell.glyph
		}
	}
	return string(row)
}

func absFloat(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}
