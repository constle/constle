// cmd/constle/ps.go

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/constle/constle/internal/sandbox"
)

// psContainer represents a single entry from `docker ps --format "{{json .}}"`.
// Only the fields needed for display are mapped.
type psContainer struct {
	ID    string `json:"ID"`
	State string `json:"State"`
	// Labels is a comma-separated "key=val,key2=val2" string in docker ps JSON,
	// unlike docker inspect which returns a proper map.
	Labels string `json:"Labels"`
}

// psRow is one line of `constle ps` output, backend-agnostic.
type psRow struct {
	runID     string
	agentName string
	status    string
	duration  string
}

func runPS() error {
	rows := append(dockerPSRows(), firecrackerPSRows()...)

	if len(rows) == 0 {
		if styled {
			initStyles()
			printf("\n%s%s\n", indent, stMuted.Render("no agents running"))
			printf("%s%s\n\n", indent, stVer.Render("constle run <agentfile>   to start one"))
			return nil
		}
		fmt.Println("No agents found.")
		fmt.Println("Tip: constle run <agentfile>")
		return nil
	}

	if styled {
		return renderPSStyled(rows)
	}

	// These writes only fill the tabwriter's internal buffer — nothing
	// reaches stdout until Flush, whose error is the one returned below. So
	// the per-row errors are dropped because Flush already carries them.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fprintln(w, "RUN ID\tAGENT\tSTATUS\tDURATION")
	fprintln(w, "------\t-----\t------\t--------")

	for _, row := range rows {
		displayID := row.runID
		if len(displayID) > 12 {
			displayID = displayID[:12] + "..."
		}
		fprintf(w, "%s\t%s\t%s\t%s\n",
			displayID, row.agentName, row.status, row.duration)
	}

	return w.Flush()
}

// renderPSStyled prints the `ps` table with aligned columns, a dim header, and
// a status coloured by liveness (TTY only). run IDs are shortened to 12 chars.
func renderPSStyled(rows []psRow) error {
	initStyles()
	// Truncated run IDs get an ellipsis so a shortened ID never *looks* like a
	// complete one — copy-pasting a silently-cut ID into `constle stop` would
	// target nothing. This mirrors the plain path's "..." convention.
	shortID := func(id string) string {
		if len(id) > 12 {
			return id[:12] + "…"
		}
		return id
	}
	// Widths are measured in runes (not bytes): the "…" is one column but three
	// UTF-8 bytes, and padr() pads by rune count — so a byte-based width would
	// over-pad the RUN ID column. status/agent may also hold non-ASCII.
	runeLen := func(s string) int { return len([]rune(s)) }
	idW, nameW, stW := len("RUN ID"), len("AGENT"), len("STATUS")
	for _, r := range rows {
		if l := runeLen(shortID(r.runID)); l > idW {
			idW = l
		}
		if l := runeLen(r.agentName); l > nameW {
			nameW = l
		}
		if l := runeLen(r.status); l > stW {
			stW = l
		}
	}
	const gap = "   "
	printf("\n%s%s\n", indent, stMuted.Render(
		padr("RUN ID", idW)+gap+padr("AGENT", nameW)+gap+padr("STATUS", stW)+gap+"DURATION"))
	for _, r := range rows {
		status := styledStatus(r.status) + strings.Repeat(" ", stW-runeLen(r.status))
		printf("%s%s%s%s%s%s%s%s\n", indent,
			stInk.Render(padr(shortID(r.runID), idW)), gap,
			stInk.Render(padr(r.agentName, nameW)), gap,
			status, gap,
			stMuted.Render(r.duration))
	}
	printf("\n")
	return nil
}

// dockerPSRows lists constle-managed Docker containers. An unreachable
// Docker daemon yields no rows instead of an error — the host may be
// running Firecracker-only.
func dockerPSRows() []psRow {
	// Using {{json .}} instead of {{index .Labels "key"}} avoids quote escaping
	// issues when passing the format string as an exec.Command argument on Windows.
	out, err := exec.Command(
		"docker", "ps",
		"-a",
		"--filter", "label=constle.managed=true",
		"--format", "{{json .}}",
	).CombinedOutput()
	if err != nil {
		return nil
	}

	var rows []psRow
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}

		var c psContainer
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}

		// docker ps JSON labels are "key1=val1,key2=val2,..." not a map.
		labels := parseDockerLabels(c.Labels)

		rows = append(rows, psRow{
			runID:     labels["constle.run-id"],
			agentName: labels["constle.agent-name"],
			status:    c.State,
			duration:  calcDuration(labels["constle.started-at"]),
		})
	}
	return rows
}

// firecrackerPSRows lists Firecracker runs. Status is verified against the
// live process table (PID + cmdline), never trusted from the state file.
func firecrackerPSRows() []psRow {
	var rows []psRow
	for _, run := range sandbox.ListFirecrackerRuns() {
		status := "exited"
		if run.Running {
			status = "running"
		}
		rows = append(rows, psRow{
			runID:     run.RunID,
			agentName: run.AgentName,
			status:    status,
			duration:  calcDuration(run.StartedAt.Format(time.RFC3339)),
		})
	}
	return rows
}

// parseDockerLabels converts "key1=val1,key2=val2" to map[string]string.
// SplitN with n=2 ensures values containing "=" are not split.
func parseDockerLabels(labelsStr string) map[string]string {
	result := map[string]string{}
	if labelsStr == "" {
		return result
	}
	for _, pair := range strings.Split(labelsStr, ",") {
		pair = strings.TrimSpace(pair)
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

func calcDuration(startedAt string) string {
	if startedAt == "" {
		return "N/A"
	}
	t, err := time.Parse(time.RFC3339, startedAt)
	if err != nil {
		return "N/A"
	}
	return fmtDuration(time.Since(t))
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
