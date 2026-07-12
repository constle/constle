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
		fmt.Println("No agents found.")
		fmt.Println("Tip: constle run <agentfile>")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "RUN ID\tAGENT\tSTATUS\tDURATION")
	fmt.Fprintln(w, "------\t-----\t------\t--------")

	for _, row := range rows {
		displayID := row.runID
		if len(displayID) > 12 {
			displayID = displayID[:12] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			displayID, row.agentName, row.status, row.duration)
	}

	return w.Flush()
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
