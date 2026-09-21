package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mattn/go-runewidth"

	"github.com/constle/constle/pkg/manifest"
)

// hostilePayloads is the shared attack table. Every entry is something a
// terminal does rather than shows, so "it appeared on screen escaped" and "it
// never reached the screen" are both passes, and only "it took effect" fails.
//
// Written as Go escapes on purpose: pasting these as literals would make this
// file itself carry the bytes it exists to keep out of a terminal, and a
// reviewer reading the diff in one would be the first victim.
var hostilePayloads = []struct {
	name    string
	payload string
}{
	{"CSI erase display", "\x1b[2J\x1b[H"},
	{"CSI erase line", "\x1b[2K"},
	{"cursor position query", "\x1b[6n"},
	{"OSC 8 hyperlink", "\x1b]8;;https:" + "//attacker.example\x07harmless\x1b]8;;\x07"},
	{"OSC 52 clipboard write", "\x1b]52;c;ZXZpbA==\x07"},
	{"DCS string", "\x1bP0;1|17/3b\x1b\\"},
	{"carriage return overwrite", "harmless\rEVERYTHING IS FINE"},
	{"bidi override", "invoice\u202Egpj.exe"},
	{"zero width", "a\u200B\uFEFFb"},
	{"blank but printable", "a\u3164\u2800b"},
	{"a C1 control byte", "a\u009Bb"},
}

// forbidden lists what may never survive to the operator's terminal,
// whatever path the text travelled.
func assertNothingDrivesTheTerminal(t *testing.T, where, out string) {
	t.Helper()

	for _, bad := range []struct {
		r    rune
		what string
	}{
		{0x1B, "ESC — begins every CSI, OSC and DCS sequence"},
		{0x0D, "CR — returns the cursor to column zero and overwrites the line"},
		{0x07, "BEL — terminates an OSC string"},
		{0x08, "BS — moves the cursor back over text already drawn"},
		{0x202E, "RIGHT-TO-LEFT OVERRIDE"},
		{0x200B, "ZERO WIDTH SPACE"},
		{0xFEFF, "ZERO WIDTH NO-BREAK SPACE"},
		{0x2028, "LINE SEPARATOR"},
		{0x3164, "HANGUL FILLER — renders as an empty cell"},
		{0x2800, "BRAILLE PATTERN BLANK — renders as an empty cell"},
		{0x009B, "C1 CSI"},
	} {
		if strings.ContainsRune(out, bad.r) {
			t.Errorf("%s: %U (%s) reached the terminal verbatim\noutput: %q",
				where, bad.r, bad.what, out)
		}
	}
}

// capture swaps os.Stdout and os.Stderr for pipes, runs fn, and returns what
// it wrote. printf and errf resolve os.Stdout/os.Stderr at call time, so this
// sees everything this package prints through them.
func capture(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	// Drain concurrently: a pipe's buffer is finite and a test that filled it
	// would deadlock rather than fail.
	outCh, errCh := make(chan string, 1), make(chan string, 1)
	for _, p := range []struct {
		r  *os.File
		ch chan string
	}{{outR, outCh}, {errR, errCh}} {
		go func(r *os.File, ch chan string) {
			var b bytes.Buffer
			_, _ = io.Copy(&b, r)
			ch <- b.String()
		}(p.r, p.ch)
	}

	func() {
		defer func() {
			os.Stdout, os.Stderr = origOut, origErr
			_ = outW.Close()
			_ = errW.Close()
		}()
		fn()
	}()

	return <-outCh, <-errCh
}

// withStyled forces the TTY-only rendering path on or off for one subtest.
//
// `go test` never hands the binary a real terminal, so lipgloss resolves to
// the Ascii profile and its Render is the identity function — which is what
// makes the blanket assertion above sound on this path too: any escape byte
// in the output came from the input, not from styling.
func withStyled(t *testing.T, on bool) {
	t.Helper()
	orig := styled
	t.Cleanup(func() { styled = orig })
	styled = on
}

// withCapturedWarnings points all three warning writers at one buffer, so a
// test that drives cmdValidate sees the warnings too instead of leaking them
// onto the real terminal.
func withCapturedWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()

	og, oi, os_ := gatesWarnOut, identityWarnOut, spendingWarnOut
	t.Cleanup(func() { gatesWarnOut, identityWarnOut, spendingWarnOut = og, oi, os_ })

	buf := &bytes.Buffer{}
	gatesWarnOut, identityWarnOut, spendingWarnOut = buf, buf, buf
	return buf
}

// hostileAgentfile writes an Agentfile carrying payload in every free-form
// string field the CLI prints. The values are emitted with strconv.Quote,
// whose output is a valid YAML double-quoted scalar for everything in the
// table above — so the bytes reach the parser exactly as written here.
//
// identity.name carries a slash-free variant: validateIdentityName rejects
// path separators outright, which is a different guard with a different
// reason, and a manifest rejected there would prove nothing about display.
func hostileAgentfile(t *testing.T, payload string) string {
	t.Helper()

	nameSafe := strings.NewReplacer("/", "", "\\", "").Replace(payload)
	content := "apiVersion: constle.dev/v1alpha1\n" +
		"kind: AgentManifest\n" +
		"identity:\n" +
		"  name: " + strconv.Quote("agent"+nameSafe) + "\n" +
		"  version: " + strconv.Quote(payload) + "\n" +
		"  owner: " + strconv.Quote(payload) + "\n" +
		"sandbox:\n" +
		"  isolation: process\n" +
		"  image: " + strconv.Quote("img"+payload) + "\n" +
		"  memory_mb: 512\n" +
		// One declared server with a tool list, so that the two
		// require_approval_for entries below land on opposite sides of
		// EnforcedGateEntries: the first matches a declared tool and is
		// reported as enforced, the second matches nothing and is reported
		// as unenforced. Both rows carry the payload, and each is rendered
		// by code the other does not reach — the enforced row was outside
		// this test entirely until the fixture declared an MCP server at
		// all, because with no server nothing is ever enforced.
		"mcp:\n" +
		"  servers:\n" +
		"    - id: gated\n" +
		"      url: \"https://mcp.example/mcp\"\n" +
		"      tools:\n" +
		"        - " + strconv.Quote(payload) + "\n" +
		"human_gates:\n" +
		"  enabled: true\n" +
		// Without a valid approver_pubkey, Validate refuses the manifest and
		// cmdValidate returns before either renderer runs — which made an
		// earlier version of this test pass with the validate sanitizers
		// removed. It is asserted below rather than assumed.
		"  approver_pubkey: \"did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP\"\n" +
		"  require_approval_for:\n" +
		"    - " + strconv.Quote(payload) + "\n" +
		"    - " + strconv.Quote(payload+"-matches-no-declared-tool") + "\n"

	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write Agentfile: %v", err)
	}
	return path
}

// TestUntrustedTextNeverReachesTheTerminalVerbatim is the property this change
// exists to establish, asserted across the whole CLI surface at once rather
// than one call site at a time.
//
// Per-site tests prove that the sites someone remembered are covered. This one
// is the guard against the failure mode this project keeps hitting — a fix
// that is correct on the path it was written for and absent on the next one.
// A new command, or a new field printed by an old one, fails here without
// anybody having to think of it.
func TestUntrustedTextNeverReachesTheTerminalVerbatim(t *testing.T) {
	for _, tc := range hostilePayloads {
		for _, mode := range []struct {
			name string
			on   bool
			// enforcedRow is a fragment only the "enforced" row of this
			// mode's validate renderer emits. The two renderers word it
			// differently, so one marker cannot serve both.
			enforcedRow string
		}{
			{"plain", false, "(paused at the MCP gate proxy for approval)"},
			{"styled", true, "∙  at gate"},
		} {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				withStyled(t, mode.on)
				warnings := withCapturedWarnings(t)
				path := hostileAgentfile(t, tc.payload)

				var validateErr error
				stdout, stderr := capture(t, func() {
					validateErr = cmdValidate(path)
					if validateErr != nil {
						// The error text is operator-facing too, so it is
						// still asserted on — but see the check below: a
						// manifest that never validates would take the
						// renderers out of this test's reach.
						errf("error: %v\n", validateErr)
					}

					m, err := manifest.ParseFile(path)
					if err != nil {
						return
					}
					if mode.on {
						renderRunSummary(m)
					} else {
						printRunSummaryPlain(m)
					}

					// Every other operator-facing surface that takes a value
					// it did not author.
					renderAgentOutput("agent output", []string{tc.payload})
					printOK("a2a listener: %s (verified peers only)", tc.payload)
					printStep("parsing %s", tc.payload)
					finalStatus(stKindOK, "✓ done", "ok", "",
						"/home/u/.constle/logs/"+tc.payload+"-2026-09-21.jsonl", "abc123", 0)
					if mode.on {
						_ = renderPSStyled([]psRow{newRow("run-1", tc.payload, "running", "00:00:01")})
					}
					errf("  warning: cleanup error: %v\n", fmt.Errorf("%s", tc.payload))
				})

				// Guard against the failure this test had once: if the
				// Agentfile stops validating, cmdValidate returns early and
				// the two validate renderers are never exercised, leaving
				// the assertions below to pass over output they never saw.
				if validateErr != nil {
					t.Fatalf("the hostile Agentfile must still validate, or the "+
						"validate renderers are out of this test's reach: %v", validateErr)
				}
				if !strings.Contains(stdout, "is valid") {
					t.Fatalf("cmdValidate printed no summary:\n%s", stdout)
				}
				// The same guard one level down, and the reason this test
				// grew a fixture: a row that never renders cannot fail, so
				// asserting only that nothing hostile appeared says nothing
				// about a sanitizer on a row nobody reached. Both sides of
				// EnforcedGateEntries are pinned, because a change that
				// moves every entry to one side would otherwise quietly take
				// the other renderer out of the sweep.
				if !strings.Contains(stdout, mode.enforcedRow) {
					t.Fatalf("the enforced row never rendered, so its sanitizer is "+
						"not under test:\n%s", stdout)
				}
				if warnings.String() == "" {
					t.Fatal("the unenforced-gate warning never fired, so its " +
						"sanitizer is not under test")
				}

				for where, out := range map[string]string{
					"stdout": stdout, "stderr": stderr, "warnings": warnings.String(),
				} {
					assertNothingDrivesTheTerminal(t, where, out)
				}
			})
		}
	}
}

// TestAgentOutputCannotForgeItsOwnFraming covers F13/F92 at the one place raw
// guest bytes exist in this package.
//
// The gutter and the spine are drawn before each line's content, so a lone
// carriage return in that content puts the cursor back at column zero and
// overwrites them — letting the agent erase its own framing and print lines
// that read as constle's. Splitting on "\n" alone left that open, so the
// assertion is on the shape of the rendered block, not only on its bytes.
func TestAgentOutputCannotForgeItsOwnFraming(t *testing.T) {
	logs := []byte("real output line\n" +
		"harmless\r  └─────────────────────────────────────────\n" +
		"\x1b[2J\x1b[Hnothing to see\n" +
		"tab\tseparated\tcolumns\n")

	for _, mode := range []struct {
		name   string
		on     bool
		marker string
	}{
		{"plain", false, "  │ "},
		{"styled", true, "▎ "},
	} {
		t.Run(mode.name, func(t *testing.T) {
			withStyled(t, mode.on)

			stdout, _ := capture(t, func() { printAgentOutput(logs) })

			assertNothingDrivesTheTerminal(t, "agent output", stdout)

			if !strings.Contains(stdout, "real output line") {
				t.Errorf("a benign line was lost:\n%s", stdout)
			}
			// Escaped, not stripped: a byte the operator cannot see is as bad
			// silently removed as it is silently obeyed.
			for _, want := range []string{`\u000D`, `\u001B[2J`} {
				if !strings.Contains(stdout, want) {
					t.Errorf("hostile bytes were hidden rather than escaped to %s:\n%s", want, stdout)
				}
			}
			if !strings.Contains(stdout, `tab\u0009separated`) {
				t.Errorf("a tab was not escaped like every other control byte:\n%s", stdout)
			}
			// Four lines of agent output in, four marked lines out: the agent
			// contributed no line of its own, and none of its content escaped
			// the marker that identifies it as the agent's.
			if got := strings.Count(stdout, mode.marker); got != 4 {
				t.Errorf("%d lines carried the %q marker, want 4:\n%s", got, mode.marker, stdout)
			}
		})
	}
}

// TestUnenforcedGateWarningCannotBeRewritten is the sharpest single case in
// the set. require_approval_for is free-form, and the line an injected value
// would overwrite says "will run WITHOUT approval" — so success for the
// attacker is an operator who reads the opposite of the truth about whether a
// gate is enforced.
func TestUnenforcedGateWarningCannotBeRewritten(t *testing.T) {
	buf := withCapturedWarnings(t)

	m := &manifest.AgentManifest{}
	m.Identity.Name = "gate-warning"
	m.HumanGates.Enabled = true
	m.HumanGates.RequireApprovalFor = []string{
		"send_email\r\x1b[2K   enforced: send_email  ∙  at gate",
	}

	warnUnenforcedHumanGates(m)
	out := buf.String()

	assertNothingDrivesTheTerminal(t, "gate warning", out)

	if !strings.Contains(out, "will run WITHOUT approval") {
		t.Errorf("the warning itself went missing:\n%s", out)
	}
	if strings.Contains(out, "\n   enforced:") {
		t.Errorf("an injected value forged a line of its own:\n%s", out)
	}
}

// TestPSRowsEscapeAtTheBoundary pins where `constle ps` is made safe. The
// agent name is read back from a Docker label written from identity.name, so
// the command prints a field out of every manifest that ever ran on this
// host. Escaping in newRow covers both renderers at once, including the plain
// tabwriter path, which writes straight to os.Stdout without going through
// printf.
func TestPSRowsEscapeAtTheBoundary(t *testing.T) {
	row := newRow("run\x1b[2J", "agent\rFORGED", "running", "00:00:01")

	for field, got := range map[string]string{
		"runID": row.runID, "agentName": row.agentName, "status": row.status,
	} {
		assertNothingDrivesTheTerminal(t, "psRow."+field, got)
	}
	if !strings.Contains(row.agentName, `\u000D`) {
		t.Errorf("the carriage return was hidden rather than escaped: %q", row.agentName)
	}
}

// TestErrfStripsTerminalControlFromStderr covers the stderr chokepoint. Almost
// every caller is die("%v", err), and the untrusted material reaching it —
// a guest console tail quoted by a Firecracker startup failure, a docker
// stderr spliced in by cmdError — never passes through printf.
func TestErrfStripsTerminalControlFromStderr(t *testing.T) {
	_, stderr := capture(t, func() {
		errf("\nerror: %v\n\n", fmt.Errorf(
			"firecracker exited during startup: %s", "boot\x1b[2J\x1b[H\rfailed"))
	})

	assertNothingDrivesTheTerminal(t, "errf", stderr)

	// The newlines errf's own format string wrote are still line breaks: this
	// stream carries multi-line validation errors and usage text on purpose.
	if !strings.HasPrefix(stderr, "\nerror: ") || !strings.HasSuffix(stderr, "\n\n") {
		t.Errorf("errf lost the line structure constle wrote: %q", stderr)
	}
}

// TestColumnsAreMeasuredInTerminalColumns covers the width change, which
// nothing else did: reverting all three runewidth.StringWidth call sites left
// the suite green.
//
// It is the same class of problem as the escaping, one step along: a rune
// count is right only for text that is entirely single-width, and an agent
// name is not guaranteed to be. Counting runes under-measures a CJK name, so
// the column to its right lands early and the table stops lining up — which
// is how a row can be made to read as a different row.
func TestColumnsAreMeasuredInTerminalColumns(t *testing.T) {
	// U+754C is two columns wide but one rune. Padding to four columns is two
	// spaces; a rune count would emit three.
	if got, want := padr("\u754C", 4), "\u754C  "; got != want {
		t.Errorf("padr(%q, 4) = %q, want %q — width is being counted in runes", "\u754C", got, want)
	}
	// Single-width text must be unaffected.
	if got, want := padr("ab", 4), "ab  "; got != want {
		t.Errorf("padr(%q, 4) = %q, want %q", "ab", got, want)
	}

	withStyled(t, true)

	// The wide name must be the widest COLUMN but not the longest RUNE
	// sequence, or the table's column width comes out the same under either
	// measure and this fixture proves nothing about ps's own calculation:
	// eight double-width runes are 16 columns against the ASCII row's 11.
	const asciiName = "ascii-agent"
	wide := strings.Repeat("\u754C", 8)
	if len([]rune(wide)) >= len([]rune(asciiName)) ||
		runewidth.StringWidth(wide) <= runewidth.StringWidth(asciiName) {
		t.Fatalf("fixture is not discriminating: wide name is %d runes/%d columns, "+
			"ascii name is %d runes/%d columns — the wide one must be shorter in "+
			"runes and wider in columns, or both measures pick the same maximum",
			len([]rune(wide)), runewidth.StringWidth(wide),
			len([]rune(asciiName)), runewidth.StringWidth(asciiName))
	}
	stdout, _ := capture(t, func() {
		_ = renderPSStyled([]psRow{
			newRow("run-1", asciiName, "running", "00:00:01"),
			newRow("run-2", wide, "running", "00:00:02"),
		})
	})

	// The duration is the last column; both rows must reach it at the same
	// screen position.
	var at []int
	for _, line := range strings.Split(stdout, "\n") {
		i := strings.Index(line, "00:00:0")
		if i < 0 {
			continue
		}
		at = append(at, runewidth.StringWidth(line[:i]))
	}
	if len(at) != 2 {
		t.Fatalf("expected two data rows, found %d:\n%s", len(at), stdout)
	}
	if at[0] != at[1] {
		t.Errorf("the duration column starts at %d on the ASCII row and %d on the wide row:\n%s",
			at[0], at[1], stdout)
	}

	// renderSummaryRows measures its own label column. Every label in the
	// tree today is an ASCII literal, so this is the function's contract
	// rather than a reachable case — which is exactly why it needs a test of
	// its own: nothing else would notice if the measure regressed.
	// As above, the fixture has to discriminate: the label column's width is
	// a max, so two labels only expose the measure when the widest label and
	// the longest one are different labels. Three double-width runes is six
	// columns against four; four ASCII characters is four columns against
	// four runes.
	wideLabel, asciiLabel := strings.Repeat("\u754C", 3), "abcd"
	byCol := max(runewidth.StringWidth(wideLabel), runewidth.StringWidth(asciiLabel))
	byRune := max(len([]rune(wideLabel)), len([]rune(asciiLabel)))
	if byCol == byRune {
		t.Fatalf("fixture is not discriminating: both measures give %d", byCol)
	}
	rowOut, _ := capture(t, func() {
		renderSummaryRows([]kv{{wideLabel, "wide"}, {asciiLabel, "ascii"}})
	})
	var valueAt []int
	for _, line := range strings.Split(rowOut, "\n") {
		i := strings.Index(line, "wide")
		if i < 0 {
			i = strings.Index(line, "ascii")
		}
		if i < 0 {
			continue
		}
		valueAt = append(valueAt, runewidth.StringWidth(line[:i]))
	}
	if len(valueAt) != 2 {
		t.Fatalf("expected two summary rows, found %d:\n%s", len(valueAt), rowOut)
	}
	if valueAt[0] != valueAt[1] {
		t.Errorf("summary values start at columns %d and %d for labels of equal width:\n%s",
			valueAt[0], valueAt[1], rowOut)
	}
}
