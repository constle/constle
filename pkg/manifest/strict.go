package manifest

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Strict decoding turns a key the schema does not define into an error rather
// than a silent no-op (yaml.Decoder.KnownFields in Parse). This file turns the
// decoder's raw complaint into something an author can act on.
//
// yaml.v3 reports an unknown key as
//
//	line 12: field capabilties not found in type manifest.AgentManifest
//
// which names a Go type an Agentfile author never wrote and does not say what
// the key should have been. The rewrite below replaces the type with the YAML
// path it corresponds to, lists the keys that section accepts, and offers the
// nearest one. A typo is the whole reason this check exists, so the message
// has to be about the typo.

// sectionInfo describes one struct in the manifest schema as YAML sees it.
type sectionInfo struct {
	// path is the dotted YAML path of the section, "" for the document root.
	// A repeated section carries a "[]" suffix on the field that repeats
	// (e.g. "mcp.servers[].pricing").
	path string

	// keys are the accepted keys, in the order the struct declares them —
	// which is the order the spec and the annotated reference file use, so
	// the list reads as documentation rather than as a sorted dump.
	keys []string
}

var (
	sectionsOnce sync.Once
	sections     map[string]sectionInfo
)

// manifestSections maps a Go type name as yaml.v3 prints it
// ("manifest.HumanGates") to the YAML section it represents.
//
// It is derived by reflection over AgentManifest rather than written out by
// hand, for the reason capabilityFloor gives about walking the same table
// twice: a hand-maintained copy drifts the moment a field is added, and it
// would drift precisely into telling an author that a key they typed
// correctly is not accepted.
func manifestSections() map[string]sectionInfo {
	sectionsOnce.Do(func() {
		sections = map[string]sectionInfo{}

		type queued struct {
			typ  reflect.Type
			path string
		}
		// Breadth-first, so a type reachable by two routes is described by
		// the shorter one.
		queue := []queued{{reflect.TypeOf(AgentManifest{}), ""}}

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]

			if cur.typ.Kind() != reflect.Struct {
				continue
			}
			if _, seen := sections[cur.typ.String()]; seen {
				continue
			}

			info := sectionInfo{path: cur.path}
			for i := 0; i < cur.typ.NumField(); i++ {
				field := cur.typ.Field(i)
				if field.PkgPath != "" {
					continue // unexported; yaml never binds it
				}

				key, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
				switch key {
				case "-":
					// Deliberately not settable from YAML (Sandbox.
					// IsolationInferred). Rejecting it is the point, so it
					// must not appear in the accepted list either.
					continue
				case "":
					key = strings.ToLower(field.Name) // yaml.v3's default
				}
				info.keys = append(info.keys, key)

				// Descend through pointers and slices to the struct, if any,
				// recording "[]" for each level that repeats.
				elem, suffix := field.Type, ""
				for {
					switch elem.Kind() {
					case reflect.Pointer:
						elem = elem.Elem()
						continue
					case reflect.Slice, reflect.Array:
						elem, suffix = elem.Elem(), suffix+"[]"
						continue
					}
					break
				}
				if elem.Kind() == reflect.Struct {
					child := key + suffix
					if cur.path != "" {
						child = cur.path + "." + child
					}
					queue = append(queue, queued{elem, child})
				}
			}
			sections[cur.typ.String()] = info
		}
	})
	return sections
}

// describeTypeError rewrites a decoder TypeError into an Agentfile-shaped
// message. Anything it does not recognise is passed through verbatim rather
// than dropped — an unrecognised complaint is still a complaint, and swallowing
// it would reintroduce in the reporting the silence this check exists to end.
func describeTypeError(te *yaml.TypeError) error {
	var problems []string
	for _, raw := range te.Errors {
		problems = append(problems, describeDecodeProblem(raw))
	}

	// No "invalid Agentfile" preamble: both callers already wrap this with
	// their own ("parse error:", "cannot parse Agentfile:"), and a third
	// restatement pushes the line number off the first line.
	if len(problems) == 1 {
		return errors.New(problems[0])
	}
	return fmt.Errorf("%d problems:\n  %s", len(problems), strings.Join(problems, "\n  "))
}

// describeDecodeProblem rewrites one line of a yaml.TypeError.
func describeDecodeProblem(raw string) string {
	line, key, typeName, ok := parseUnknownField(raw)
	if !ok {
		// The decoder's own sentence, quoted rather than passed through.
		// It embeds the offending scalar, and yaml.v3 decodes escapes before
		// it formats: a "\n" written into an Agentfile string arrives here
		// as a real newline, and the CLI's stderr writer preserves the
		// newlines of an error it is relaying — deliberately, since for
		// nearly every caller the error IS the message. So a value that
		// reaches the terminal through this branch could open a line of its
		// own that reads as constle speaking.
		//
		// Held here, where the untrusted value enters the error, which is
		// the only place it can be held: downstream the newline is
		// indistinguishable from one constle wrote. Quoting and not dropping,
		// for the same reason the rest of this file rewrites rather than
		// swallows — an unrecognised complaint is still a complaint, and the
		// author needs to read it. Same rule as the %q sites below.
		return strconv.Quote(raw)
	}

	section, known := manifestSections()[typeName]
	if !known {
		// A type outside the schema walk: say what is wrong in the Agentfile's
		// own terms and stop, rather than inventing a key list.
		return fmt.Sprintf("line %d: unknown key %q", line, key)
	}

	where := "at the top level"
	if section.path != "" {
		where = "in " + section.path
	}
	msg := fmt.Sprintf("line %d: unknown key %q %s", line, key, where)

	if suggestion, found := nearestKey(key, section.keys); found {
		msg += fmt.Sprintf("\n    did you mean %q?", suggestion)
	}
	if len(section.keys) > 0 {
		msg += "\n    accepted here: " + strings.Join(section.keys, ", ")
	}
	return msg
}

// parseUnknownField pulls the parts out of yaml.v3's
// "line 12: field capabilties not found in type manifest.AgentManifest".
// A YAML key may contain spaces, so the message is split on its literal
// separators rather than tokenised on whitespace.
func parseUnknownField(raw string) (line int, key, typeName string, ok bool) {
	rest, ok := strings.CutPrefix(raw, "line ")
	if !ok {
		return 0, "", "", false
	}
	lineStr, rest, ok := strings.Cut(rest, ": field ")
	if !ok {
		return 0, "", "", false
	}
	line, err := strconv.Atoi(lineStr)
	if err != nil {
		return 0, "", "", false
	}
	// The delimiter can legitimately occur inside a YAML key, so the split is
	// anchored at the LAST occurrence: yaml appends the type name after the
	// final one. Cutting at the first truncated the key of a manifest whose
	// key genuinely contained "not found in type", and named a key the author
	// never wrote.
	sep := strings.LastIndex(rest, " not found in type ")
	if sep < 0 {
		return 0, "", "", false
	}
	key = rest[:sep]
	typeName = rest[sep+len(" not found in type "):]
	return line, key, typeName, true
}

// nearestKey returns the accepted key closest to what was written, when one is
// close enough to be worth naming. The thresholds are deliberately tight: a
// wrong suggestion is worse than none, because it sends the author to edit a
// line that was never the problem.
//
// Both sides of the proportional threshold are counted in runes. Measuring the
// written key in bytes made a short non-ASCII key look long enough to justify
// any suggestion — a two-emoji key is eight bytes, so a distance of three
// passed and "💣💣" was answered with "did you mean a2a?".
func nearestKey(written string, keys []string) (string, bool) {
	best, bestDist := "", -1
	for _, key := range keys {
		d := editDistance(strings.ToLower(written), strings.ToLower(key))
		if bestDist == -1 || d < bestDist || (d == bestDist && key < best) {
			best, bestDist = key, d
		}
	}
	if bestDist < 0 || bestDist > 3 || bestDist*2 > utf8.RuneCountInString(written) {
		return "", false
	}
	return best, true
}

// editDistance is the Levenshtein distance between two short keys.
func editDistance(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	curr := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		curr[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, min(curr[j-1]+1, prev[j-1]+cost))
		}
		prev, curr = curr, prev
	}
	return prev[len(br)]
}

// sortedSectionPaths is used only by tests, to assert the reflection walk
// reaches every section of the schema.
func sortedSectionPaths() []string {
	paths := make([]string, 0, len(manifestSections()))
	for _, info := range manifestSections() {
		paths = append(paths, info.path)
	}
	sort.Strings(paths)
	return paths
}
