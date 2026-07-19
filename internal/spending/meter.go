package spending

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ParsePath validates and splits a usage_path declaration: dot-separated
// segments, where an all-digit segment indexes an array and anything else
// is an object key. No wildcards and no expression language — the path is
// the same kind of exact, deterministic contract as human-gate tool names.
func ParsePath(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("usage_path is empty")
	}
	segs := strings.Split(path, ".")
	for _, s := range segs {
		if s == "" {
			return nil, fmt.Errorf("usage_path %q has an empty segment", path)
		}
	}
	return segs, nil
}

// ExtractUsage evaluates a parsed usage_path against a JSON document (a
// full JSON-RPC response message) and returns the raw decimal string of
// the number found there. Any missing segment, wrong type, or non-numeric
// leaf is an error — the caller treats it as a metering failure and fails
// closed.
func ExtractUsage(doc []byte, path []string) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return "", fmt.Errorf("response is not valid JSON: %v", err)
	}

	cur := root
	for i, seg := range path {
		where := strings.Join(path[:i+1], ".")
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return "", fmt.Errorf("usage_path %q: key %q not found", strings.Join(path, "."), where)
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil {
				return "", fmt.Errorf("usage_path %q: %q is an array but segment %q is not an index", strings.Join(path, "."), strings.Join(path[:i], "."), seg)
			}
			if idx < 0 || idx >= len(node) {
				return "", fmt.Errorf("usage_path %q: index %d out of range at %q", strings.Join(path, "."), idx, where)
			}
			cur = node[idx]
		default:
			return "", fmt.Errorf("usage_path %q: %q is not an object or array", strings.Join(path, "."), strings.Join(path[:i], "."))
		}
	}

	num, ok := cur.(json.Number)
	if !ok {
		return "", fmt.Errorf("usage_path %q: value is %T, not a number", strings.Join(path, "."), cur)
	}
	return num.String(), nil
}

// Meter is one compiled pricing meter: a parsed usage path plus its
// per-unit price.
type Meter struct {
	Path  []string
	Price MicroCents
}

// MeterResponse applies every meter to one JSON-RPC response document and
// returns the summed cost. Any meter that cannot extract its usage value
// makes the whole response a metering failure.
func MeterResponse(doc []byte, meters []Meter) (MicroCents, error) {
	var total MicroCents
	for _, m := range meters {
		usage, err := ExtractUsage(doc, m.Path)
		if err != nil {
			return 0, err
		}
		cost, err := Cost(usage, m.Price)
		if err != nil {
			return 0, err
		}
		total, err = Add(total, cost)
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}
