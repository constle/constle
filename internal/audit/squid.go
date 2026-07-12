// internal/audit/squid.go
//
// Reads Squid access logs from the proxy container and converts them to
// JSONL audit events.
//
// Call order matters:
//
//	FlushSquidLogs()  ← must run while the proxy container is still alive
//	backend.Stop()    ← destroys the proxy container (logs are lost after this)
//	logger.Close()    ← closes the log file
//
// Squid native access log format:
//
//	1748000400.123    27 172.20.0.3 TCP_DENIED/403   3956 CONNECT evil.com:443    - HIER_NONE/-
//	1748000401.456    89 172.20.0.3 TCP_TUNNEL/200   1234 CONNECT httpbin.org:443 - DIRECT/1.2.3.4
//	[0]timestamp  [1]ms  [2]clientIP  [3]result/status  [4]bytes  [5]method  [6]url ...

package audit

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// FlushSquidLogs reads Squid logs from the proxy container and writes audit events.
// Must be called before backend.Stop() — the logs are lost once the container is removed.
func FlushSquidLogs(runID, agentName, proxyContainerID string, logger *Logger) error {
	cmd := exec.Command(
		"docker", "exec",
		proxyContainerID,
		"cat", "/var/log/squid/access.log",
	)

	output, err := cmd.Output()
	if err != nil {
		// Two possible causes:
		// 1. Container does not exist (Stop() ran first — wrong call order).
		// 2. access.log does not exist (agent made no network requests — normal).
		return fmt.Errorf("cannot read squid log from %s: %w", proxyContainerID, err)
	}

	if len(output) == 0 {
		return nil
	}

	return parseAndLog(strings.NewReader(string(output)), runID, agentName, logger)
}

// FlushSquidLogFile reads a Squid access log from a host file path and
// writes audit events — used by the Firecracker backend, whose per-run
// Squid instance runs on the host. Attribution works exactly like the
// Docker path: each run has its own Squid instance and log file, so every
// line in the file belongs to this run.
// Must be called before backend.Stop() — Stop removes the run directory.
func FlushSquidLogFile(runID, agentName, path string, logger *Logger) error {
	output, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cannot read squid log at %s: %w", path, err)
	}

	if len(output) == 0 {
		return nil
	}

	return parseAndLog(strings.NewReader(string(output)), runID, agentName, logger)
}

// parseAndLog parses an io.Reader of Squid log lines and writes audit events.
// Separated from FlushSquidLogs to allow unit testing with synthetic input.
func parseAndLog(r io.Reader, runID, agentName string, logger *Logger) error {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		action, host, method, status, bytes, err := parseSquidLine(line)
		if err != nil {
			continue
		}

		eventType := EventNetworkAllowed
		if action == "blocked" {
			eventType = EventNetworkBlocked
		}

		logger.Log(runID, agentName, eventType, map[string]any{
			"host":        host,
			"method":      method,
			"http_status": status,
			"bytes":       bytes,
		})
	}

	return scanner.Err()
}

// parseSquidLine parses one line from a Squid access log.
// Returns: action, host, method, http status, bytes transferred, error.
func parseSquidLine(line string) (action, host, method string, status int, bytes int64, err error) {
	fields := strings.Fields(line)

	if len(fields) < 7 {
		err = fmt.Errorf("expected ≥7 fields, got %d", len(fields))
		return
	}

	// Field 3: "TCP_DENIED/403" or "TCP_TUNNEL/200"
	resultParts := strings.SplitN(fields[3], "/", 2)
	if len(resultParts) != 2 {
		err = fmt.Errorf("bad result field: %q", fields[3])
		return
	}
	resultCode := resultParts[0]
	status, _ = strconv.Atoi(resultParts[1])

	// Field 4: bytes transferred
	bytes, _ = strconv.ParseInt(fields[4], 10, 64)

	// Field 5: HTTP method ("CONNECT", "GET", "POST", ...)
	method = fields[5]

	// Field 6: URL → extract hostname.
	// Squid logs protocol-level failures (aborted connections, readiness
	// probes) with an "error:..." pseudo-URL — not a network access attempt,
	// so not an audit event.
	if strings.HasPrefix(fields[6], "error:") {
		err = fmt.Errorf("squid pseudo-URL, not an access record: %q", fields[6])
		return
	}
	host = extractHost(fields[6])

	// TCP_DENIED = blocked by Squid ACL; NONE = connection error; everything else = allowed.
	action = "allowed"
	if strings.Contains(resultCode, "DENIED") || resultCode == "NONE" {
		action = "blocked"
	}

	return
}

// extractHost strips port and path, returning just the hostname.
//
// Handles:
//
//	CONNECT: "evil.com:443"        → "evil.com"
//	HTTP:    "http://google.com/q" → "google.com"
//	IP:      "1.2.3.4:80"          → "1.2.3.4"
func extractHost(rawURL string) string {
	if !strings.Contains(rawURL, "://") {
		// CONNECT request: "hostname:port" — use LastIndex for IPv6 addresses.
		if idx := strings.LastIndex(rawURL, ":"); idx != -1 {
			return rawURL[:idx]
		}
		return rawURL
	}

	// HTTP: "http://hostname:port/path"
	withoutScheme := strings.SplitN(rawURL, "://", 2)
	if len(withoutScheme) < 2 {
		return rawURL
	}
	hostPart := strings.SplitN(withoutScheme[1], "/", 2)[0]
	if idx := strings.LastIndex(hostPart, ":"); idx != -1 {
		hostPart = hostPart[:idx]
	}
	return hostPart
}
