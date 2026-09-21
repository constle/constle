package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"gopkg.in/yaml.v3"

	"github.com/constle/constle/internal/spending"
	"github.com/constle/constle/pkg/did"
)

// ParseFile reads a YAML file from disk and returns an AgentManifest.
func ParseFile(path string) (*AgentManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read Agentfile at %q: %w", path, err)
	}

	m, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// Parse unmarshals YAML bytes into an AgentManifest.
// Useful for tests — callers can supply YAML directly without a file.
//
// Decoding is strict: a key the schema does not define is an error, not a
// silent no-op. Every control in an Agentfile is opt-in, so a key that is
// quietly discarded removes the control it was meant to declare —
// `capabilties:` empties the capability list and drops the isolation floor to
// none, `requre_approval_for:` leaves a gate declared and unarmed. The failure
// is invisible in both cases: the manifest validates, and the CLI reports the
// weakened configuration as though it had been asked for. Strict decoding is
// the same judgement already made for an unrecognised capability value and an
// unrecognised isolation level, applied to the key rather than the value.
//
// An Agentfile is exactly one YAML document. Strictness that stopped at the
// first document would be strictness in name only: a decoder reads one
// document and returns, so everything after a `---` is discarded by the same
// silence, whether it holds an unknown key, a whole second policy, or YAML
// that does not parse at all.
func Parse(data []byte) (*AgentManifest, error) {
	var m AgentManifest

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	// An empty or comment-only document decodes to nothing and returns io.EOF,
	// where yaml.Unmarshal returned no error at all. Keep the old behaviour:
	// the defaults below still apply, and Validate is what refuses the file,
	// naming the missing apiVersion rather than an unexplained EOF.
	if err := dec.Decode(&m); err != nil && !errors.Is(err, io.EOF) {
		var typeErr *yaml.TypeError
		if errors.As(err, &typeErr) {
			return nil, describeTypeError(typeErr)
		}
		return nil, fmt.Errorf("invalid YAML in Agentfile: %w", err)
	}

	// Require the stream to end here. A leading `---` or a trailing `...` is a
	// marker on this one document and still reaches io.EOF; a genuine second
	// document does not.
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case errors.Is(err, io.EOF):
		// Exactly one document, as required.
	case err == nil:
		return nil, fmt.Errorf(
			"an Agentfile must be a single YAML document; found a second one at line %d "+
				"(everything after the first document is ignored, so it would declare nothing)",
			extra.Line)
	default:
		// Not even well-formed. Reported rather than discarded: a file whose
		// tail does not parse must never be answered with "is valid".
		return nil, fmt.Errorf("invalid YAML in Agentfile after the first document: %w", err)
	}

	// If isolation is not set explicitly, infer it from the declared
	// capabilities. An explicitly written level is left exactly as authored —
	// including a malformed one, which Validate rejects rather than repairing.
	if m.Sandbox.Isolation == "" {
		m.Sandbox.Isolation = InferIsolation(m.Capabilities)
		m.Sandbox.IsolationInferred = true
	}

	if m.Sandbox.MemoryMB == 0 {
		m.Sandbox.MemoryMB = 512
	}
	if m.Sandbox.DiskMB == 0 {
		m.Sandbox.DiskMB = 2048
	}
	if m.Sandbox.Network.Egress == "" {
		m.Sandbox.Network.Egress = "restricted"
	}
	if m.HumanGates.OnTimeout == "" {
		m.HumanGates.OnTimeout = "abort"
	}
	if m.HumanGates.ApprovalTimeoutSeconds == 0 {
		m.HumanGates.ApprovalTimeoutSeconds = 300
	}
	if m.Compliance.AuditLogLevel == "" {
		m.Compliance.AuditLogLevel = "standard"
	}

	return &m, nil
}

// Validate checks that the manifest contains all required fields.
func (m *AgentManifest) Validate() error {
	if m.APIVersion != "constle.dev/v1alpha1" {
		return fmt.Errorf(
			"unsupported apiVersion %q — expected \"constle.dev/v1alpha1\"",
			m.APIVersion,
		)
	}

	if m.Kind != "AgentManifest" {
		return fmt.Errorf(
			"unsupported kind %q — expected \"AgentManifest\"",
			m.Kind,
		)
	}

	if err := validateIdentityName(m.Identity.Name); err != nil {
		return err
	}

	if m.Identity.DID != "" {
		if err := did.Validate(m.Identity.DID); err != nil {
			return fmt.Errorf("identity.did: %w", err)
		}
	}

	// A malformed isolation level fails closed here rather than ranking as
	// "none" downstream and quietly selecting the weakest backend on the
	// host. `isolation: kernal` must be a rejected Agentfile, not a kernel
	// requirement silently served by Docker.
	//
	// Empty is exempt because it is the pre-inference state, not a level:
	// Parse fills it from Capabilities, so no parsed manifest reaches here
	// empty, and a manifest built directly in Go may legitimately be
	// validated for its policy content before a level is resolved. Nothing
	// rests on that exemption — IsolationLevel.Satisfies fails closed on an
	// invalid operand, so an unresolved level cannot satisfy a backend
	// comparison either.
	//
	// This is the syntax half of the isolation check. Whether a well-formed
	// level is strong enough for what the agent may actually do is the
	// capability floor, checked by validateIsolationFloor below — after the
	// capability loop, so the floor is never computed from a typo.
	if m.Sandbox.Isolation != "" {
		if _, err := ParseIsolationLevel(string(m.Sandbox.Isolation)); err != nil {
			return fmt.Errorf("sandbox.isolation: %w", err)
		}
	}

	if err := validateSandboxImage(m.Sandbox.Image); err != nil {
		return err
	}

	for _, cap := range m.Capabilities {
		if !isKnownCapability(cap) {
			return fmt.Errorf("unknown capability %q — check the Constle docs for supported capabilities", cap)
		}
	}

	if err := m.validateIsolationFloor(); err != nil {
		return err
	}

	if err := m.validateCredentials(); err != nil {
		return err
	}

	if err := m.validateNetwork(); err != nil {
		return err
	}

	if err := m.validateMCP(); err != nil {
		return err
	}

	if err := m.validateA2A(); err != nil {
		return err
	}

	if err := m.validateLimits(); err != nil {
		return err
	}

	if err := m.validateHumanGates(); err != nil {
		return err
	}

	if err := m.validateSpending(); err != nil {
		return err
	}

	return nil
}

// validateIsolationFloor refuses an Agentfile whose declared sandbox.isolation
// is weaker than its own capabilities require.
//
// The capability-derived minimum used to be consulted only when the field was
// absent, so writing a level by hand was a way to overrule it downward and
// nothing said so: `capabilities: [external_transfer]` beside
// `isolation: network` validated cleanly, selected Docker, satisfied the
// backend contract, recorded no downgrade, and signed an audit entry claiming
// "network" for an agent that can move money. Writing the line made the
// boundary weaker than omitting it would have. Declaring a level may only
// strengthen the boundary, never weaken it.
//
// The manifest is refused rather than quietly raised to the floor. Raising it
// would run the agent behind a boundary nobody wrote, leaving the Agentfile
// saying one thing and the run doing another — the same silent substitution
// IsValid refuses for a typo'd level.
//
// --accept-isolation cannot waive this refusal. That flag is consumed during
// backend selection (internal/sandbox/detect.go), long after validation, so it
// never reaches here. It can still put one run on a boundary below this floor
// — that is what it is for — but only when an operator names it, and the run
// prints and records that it happened. This governs what an Agentfile may
// declare; the flag governs what an operator may knowingly accept for one run.
// Nobody can accept an Agentfile that contradicts itself.
//
// Order matters in both directions, and neither half is cosmetic:
//
//   - It runs after the malformed-level check above. Satisfies fails closed on
//     an invalid operand, so a floor check running first answers
//     `isolation: kernal` with "weaker than kernel" — telling an author to
//     raise a level they already wrote, instead of naming the typo.
//   - It runs after the unknown-capability loop. minIsolationFor maps anything
//     it does not recognize to "process", so a floor computed first answers
//     `capabilities: [reed_file]` by quoting back a capability that does not
//     exist, instead of reporting the typo it is.
//
// Both operands are therefore known-valid here, which is what lets the message
// be specific — and is why the named capabilities can never be empty: the
// declared level is a real level by now, and every real level satisfies
// IsolationNone, so a refusal always has at least one capability above it.
//
// Empty is exempt for the same reason the malformed-level check exempts it: it
// is the pre-inference state, not a level. Parse fills it from these same
// capabilities, so no parsed manifest reaches here empty, and a manifest built
// directly in Go may be validated for its policy content before a level is
// resolved.
func (m *AgentManifest) validateIsolationFloor() error {
	if m.Sandbox.Isolation == "" {
		return nil
	}

	floor, drivers := capabilityFloor(m.Capabilities)
	if m.Sandbox.Isolation.Satisfies(floor) {
		return nil
	}

	// Every capability at the floor is named, not just the first. Naming one
	// of several would make "drop that capability" a lie: the author drops it,
	// revalidates, and meets its sibling at the same floor with nothing having
	// moved.
	quoted := make([]string, len(drivers))
	for i, cap := range drivers {
		quoted[i] = fmt.Sprintf("%q", cap)
	}
	noun, remedy := "capability", "that capability"
	if len(drivers) > 1 {
		noun, remedy = "capabilities", "those capabilities"
	}

	return fmt.Errorf(
		"sandbox.isolation: %q is weaker than the %q minimum required by %s %s — "+
			"a declared level may only strengthen the boundary, never weaken it; "+
			"raise it to %q or drop %s",
		m.Sandbox.Isolation, floor, noun, strings.Join(quoted, ", "), floor, remedy,
	)
}

// validateIdentityName rejects agent names that would escape the directories
// constle derives from them. identity.name is used unmodified as a path
// element — the identity directory (~/.constle/identities/<name>/) and the
// audit log filename (~/.constle/logs/<name>-<date>.jsonl) — so a name
// carrying path separators or dot-segments relocates that state outside the
// intended directory, where constle then creates and chowns it.
//
// This check runs for every manifest, signed or not: the identity-loading
// path only validates the name when identity.did is declared, which leaves
// unsigned manifests unchecked.
//
// The rules below must stay in sync with validateAgentName in
// internal/identity/identity.go, which guards the same name on the identity
// storage path.
func validateIdentityName(name string) error {
	if name == "" {
		return fmt.Errorf("identity.name is required")
	}
	if strings.ContainsAny(name, "/\\") || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return fmt.Errorf("identity.name %q is invalid: must not contain path separators or start with a dot", name)
	}
	return nil
}

// validateSandboxImage rejects an image reference that the Docker backend
// would hand to `docker run` in the shape of an option. The image is the
// first positional argument of that invocation, and an Agentfile value such
// as "-v" or "--privileged" reads as a flag there, with sandbox.command
// supplying its operands: `image: "-v"` plus `command: ["/:/host", "alpine",
// "sh"]` mounts the host filesystem into the sandbox. The backend also ends
// option parsing with "--" before the image (agentRunArgs in
// internal/sandbox), so this check is the early refusal that names the
// field rather than the only guard.
//
// Empty stays allowed for the same reason Validate exempts an empty
// isolation level: a manifest may be validated for its policy content before
// an image is chosen. No image reference legitimately starts with "-", so
// nothing valid is refused.
//
// sandbox.command is deliberately not checked: its elements follow the
// image, past the point where docker run reads options, and they start with
// "-" legitimately when they are arguments to the image's ENTRYPOINT.
func validateSandboxImage(image string) error {
	if strings.HasPrefix(image, "-") {
		return fmt.Errorf("sandbox.image %q is invalid: an image reference cannot start with \"-\"", image)
	}
	return nil
}

// validateSpending checks the spending limits and every mcp.servers pricing
// block. Amounts must parse exactly (never rounded silently), and a daily
// cap without a DID fails closed: durable daily tracking is keyed by DID so
// renaming an agent cannot reset it.
func (m *AgentManifest) validateSpending() error {
	s := m.Spending

	for _, f := range []struct{ name, value string }{
		{"spending.max_per_run_usd", s.MaxPerRunUSD},
		{"spending.max_per_day_usd", s.MaxPerDayUSD},
		{"spending.max_per_month_usd", s.MaxPerMonthUSD},
	} {
		if f.value == "" {
			continue
		}
		v, err := spending.ParseUSD(f.value)
		if err != nil {
			return fmt.Errorf("%s: %v", f.name, err)
		}
		if v == 0 {
			// A zero cap would silently read as "unset" at enforcement time —
			// ambiguous, so it fails closed here instead.
			return fmt.Errorf("%s: a cap of 0 is ambiguous — omit the field to leave the limit unset", f.name)
		}
		if v < 0 {
			// Unreachable while ParseUSD holds: it refuses a leading '-' and
			// guards both of its accumulation loops, so no manifest string
			// reaches here negative, and no test can drive this branch through
			// the public API. It is kept deliberately, as the input boundary's
			// own statement of the invariant: a negative cap reads as "not
			// declared" at every enforcement site, and that failure is far too
			// quiet to rest on one function's arithmetic staying correct.
			return fmt.Errorf("%s: a negative cap (%s) is not a limit — omit the field to leave the limit unset", f.name, v.USD())
		}
	}

	if s.MaxPerDayUSD != "" && m.Identity.DID == "" {
		return fmt.Errorf(
			"spending.max_per_day_usd: identity.did is required — daily spend is tracked durably per DID "+
				"(tracking by name would let a rename reset it); create one with: constle identity create %q",
			m.Identity.Name)
	}

	if pct := s.Alerts.WarnAtPctOfDaily; pct != 0 {
		if pct < 1 || pct > 100 {
			return fmt.Errorf("spending.alerts.warn_at_pct_of_daily must be between 1 and 100, got %d", pct)
		}
		if s.MaxPerDayUSD == "" {
			return fmt.Errorf("spending.alerts.warn_at_pct_of_daily is set but spending.max_per_day_usd is not — there is no daily cap to warn about")
		}
	}

	for _, srv := range m.MCP.Servers {
		if srv.Pricing == nil {
			continue
		}
		if len(srv.Pricing.Meters) == 0 {
			return fmt.Errorf("mcp.servers[%s].pricing: meters must not be empty — a pricing block without meters cannot measure anything", srv.ID)
		}
		for i, meter := range srv.Pricing.Meters {
			if _, err := spending.ParsePath(meter.UsagePath); err != nil {
				return fmt.Errorf("mcp.servers[%s].pricing.meters[%d]: %v", srv.ID, i, err)
			}
			if _, err := spending.ParseUSD(meter.USDPerUnit); err != nil {
				return fmt.Errorf("mcp.servers[%s].pricing.meters[%d].usd_per_unit: %v", srv.ID, i, err)
			}
		}
	}

	return nil
}

// PricedMCPServers returns the ids of MCP servers that declare a pricing
// block — the servers whose traffic the gate proxy actually meters.
func (m *AgentManifest) PricedMCPServers() []string {
	var ids []string
	for _, srv := range m.MCP.Servers {
		if srv.Pricing != nil {
			ids = append(ids, srv.ID)
		}
	}
	return ids
}

// validateMCP checks the declared MCP servers and, critically, that no
// network allowlist entry opens a direct path from the sandbox to a real
// MCP server — that would let the agent bypass the gate proxy entirely, so
// it fails closed as a validation error rather than a warning.
func (m *AgentManifest) validateMCP() error {
	seen := map[string]bool{}

	for _, srv := range m.MCP.Servers {
		if srv.ID == "" {
			return fmt.Errorf("mcp.servers: every server needs an id")
		}
		if !isValidID(srv.ID) {
			return fmt.Errorf("mcp.servers: invalid id %q — use lowercase letters, digits, hyphens, and underscores", srv.ID)
		}
		if seen[srv.ID] {
			return fmt.Errorf("mcp.servers: duplicate id %q", srv.ID)
		}
		seen[srv.ID] = true

		host, err := mcpServerHost(srv.URL)
		if err != nil {
			return fmt.Errorf("mcp.servers[%s]: %w", srv.ID, err)
		}

		for _, allowed := range m.Sandbox.Network.AllowedHosts {
			if hostsOverlap(allowed, host) {
				return fmt.Errorf(
					"mcp.servers[%s]: host %q also appears in network.allowed_hosts — "+
						"that would let the agent reach the MCP server directly, bypassing the gate proxy; "+
						"remove it from allowed_hosts (MCP traffic is routed through the gate automatically)",
					srv.ID, host,
				)
			}
		}
	}

	// The gate transport itself must not be reachable beyond the gate port:
	// allowing these hosts wholesale through Squid would expose every host
	// service to the sandbox, including a locally-run MCP server.
	if len(m.MCP.Servers) > 0 {
		for _, allowed := range m.Sandbox.Network.AllowedHosts {
			if isHostLoopbackAlias(allowed) {
				return fmt.Errorf(
					"network.allowed_hosts: %q must not be allowlisted when mcp.servers are declared — "+
						"it would expose host services (including local MCP servers) directly to the agent, bypassing the gate proxy",
					allowed,
				)
			}
		}
	}

	return nil
}

// validateA2A checks the declared A2A configuration and, critically, that no
// network allowlist entry opens a direct sandbox path to a peer's endpoint —
// that would let the agent talk to the peer without the host-side signing
// gate, so it fails closed as a validation error, exactly like the
// mcp.servers bypass check above.
func (m *AgentManifest) validateA2A() error {
	a := m.A2A
	if a.Listen == "" && len(a.Peers) == 0 {
		return nil
	}

	// Every A2A call is signed (outbound) or verified (inbound) with the
	// agent's own identity in the host process — without a declared identity
	// there is no key to sign with, so A2A cannot exist unsigned.
	if m.Identity.DID == "" {
		return fmt.Errorf(
			"a2a: identity.did is required — every A2A call is signed with the agent's identity; "+
				"create one with: constle identity create %q", m.Identity.Name)
	}

	if len(a.Peers) == 0 {
		// listen without peers: no inbound sender could ever be authorized,
		// so the listener would only ever reject. Refuse the configuration
		// rather than run a listener that silently can never accept.
		return fmt.Errorf("a2a.listen is set but a2a.peers is empty — no peer could ever be authorized to call this agent; declare the peers or remove a2a.listen")
	}

	if a.Listen != "" {
		if _, _, err := net.SplitHostPort(a.Listen); err != nil {
			return fmt.Errorf("a2a.listen: invalid listen address %q — use \"host:port\" or \":port\": %v", a.Listen, err)
		}
	}

	seen := map[string]bool{}
	seenDID := map[string]bool{}
	for _, p := range a.Peers {
		if p.Name == "" {
			return fmt.Errorf("a2a.peers: every peer needs a name")
		}
		if !isValidID(p.Name) {
			return fmt.Errorf("a2a.peers: invalid name %q — use lowercase letters, digits, hyphens, and underscores", p.Name)
		}
		if seen[p.Name] {
			return fmt.Errorf("a2a.peers: duplicate name %q", p.Name)
		}
		seen[p.Name] = true

		if p.DID == "" {
			return fmt.Errorf("a2a.peers[%s]: did is required (the peer's did:key, exchanged out of band)", p.Name)
		}
		if err := did.Validate(p.DID); err != nil {
			return fmt.Errorf("a2a.peers[%s]: %w", p.Name, err)
		}
		if seenDID[p.DID] {
			return fmt.Errorf("a2a.peers: two peers declare the same did %q — sender identity would be ambiguous", p.DID)
		}
		seenDID[p.DID] = true
		if p.DID == m.Identity.DID {
			return fmt.Errorf("a2a.peers[%s]: peer did equals this agent's own identity.did", p.Name)
		}

		host, err := a2aEndpointHost(p.Endpoint)
		if err != nil {
			return fmt.Errorf("a2a.peers[%s]: %w", p.Name, err)
		}

		for _, allowed := range m.Sandbox.Network.AllowedHosts {
			if hostsOverlap(allowed, host) {
				return fmt.Errorf(
					"a2a.peers[%s]: host %q also appears in network.allowed_hosts — "+
						"that would let the agent reach the peer directly, bypassing the signing A2A gate; "+
						"remove it from allowed_hosts (A2A traffic is signed and routed through the gate automatically)",
					p.Name, host,
				)
			}
		}
	}

	// The gate transport itself must not be reachable beyond the gate port —
	// same rule as for mcp.servers above.
	for _, allowed := range m.Sandbox.Network.AllowedHosts {
		if isHostLoopbackAlias(allowed) {
			return fmt.Errorf(
				"network.allowed_hosts: %q must not be allowlisted when a2a.peers are declared — "+
					"it would expose host services (including the A2A gate transport) directly to the agent, bypassing signature enforcement",
				allowed,
			)
		}
	}

	return nil
}

// a2aEndpointHost extracts and validates the host of a peer's A2A endpoint URL.
func a2aEndpointHost(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("endpoint is required (the peer's public A2A URL)")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("endpoint %q must use http or https", rawURL)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("endpoint %q has no host", rawURL)
	}
	if !isASCIIHost(u.Hostname()) {
		return "", nonASCIIHostError("endpoint", rawURL, u.Hostname())
	}
	return normalizeHost(u.Hostname()), nil
}

// maxSecondsField bounds every *_seconds manifest field to what time.Duration
// can represent. Duration is int64 nanoseconds, so above this value
// time.Duration(n) * time.Second no longer means n seconds: the product is
// modular, so it comes back as some other duration entirely. Just past the
// bound that is a negative one, which every use site reads as "already
// elapsed" — the approval context is dead before the prompt is drawn (and
// on_timeout: proceed then forwards the gated call with no human in the
// loop), and the run-duration timer fires at once. Further out it wraps round
// again into small POSITIVE values: 18446744074 seconds converts to 290ms.
// Both are the same defect — the wait that happens is not the wait that was
// declared — which is why the bound is on representability rather than on any
// particular wrong outcome.
//
// Held as int64 rather than int so the constant is representable on 32-bit
// platforms too, where these int fields simply cannot reach it.
const maxSecondsField int64 = int64(math.MaxInt64) / int64(time.Second)

// validateLimits checks the run limits. A limit is enforced by a "> 0" test at
// its use site, so a non-positive value there means "not declared" — the same
// silent unenforcement a negative spending cap used to produce. Both ends of
// the range fail closed here rather than at each reader.
func (m *AgentManifest) validateLimits() error {
	d := m.Limits.MaxDurationSeconds
	if d < 0 {
		return fmt.Errorf("limits.max_duration_seconds must not be negative, got %d — omit the field to leave the run unbounded", d)
	}
	if int64(d) > maxSecondsField {
		return fmt.Errorf("limits.max_duration_seconds: %d exceeds the maximum representable duration of %d seconds — above it the value no longer converts to the time it names, so the run would be killed at some arbitrary earlier moment", d, maxSecondsField)
	}
	return nil
}

// validateHumanGates checks gate timing and notification channels.
func (m *AgentManifest) validateHumanGates() error {
	g := m.HumanGates

	if g.ApprovalTimeoutSeconds < 0 {
		return fmt.Errorf("human_gates.approval_timeout_seconds must be positive, got %d", g.ApprovalTimeoutSeconds)
	}
	if int64(g.ApprovalTimeoutSeconds) > maxSecondsField {
		// Above this the value no longer converts to the time it names. Just
		// past the bound it converts negative, so the approval context is
		// already expired when it is created and on_timeout: proceed forwards
		// the gated tool call before any human could answer; further out it
		// converts to a fraction of a second, which ends the same way. A gate
		// that reads as a 292-year wait must not be a gate that barely waits.
		return fmt.Errorf("human_gates.approval_timeout_seconds: %d exceeds the maximum representable timeout of %d seconds — above it the value no longer converts to the time it names, so the gate would stop waiting almost immediately", g.ApprovalTimeoutSeconds, maxSecondsField)
	}

	switch g.OnTimeout {
	case "", "abort", "proceed":
	default:
		return fmt.Errorf("human_gates.on_timeout must be \"abort\" or \"proceed\", got %q", g.OnTimeout)
	}

	for _, n := range g.Notify {
		// Unsupported channels are an error, not a warning: a declared
		// notification path must never look real when it isn't.
		if n.Channel != "webhook" {
			return fmt.Errorf("human_gates.notify: channel %q is not supported by this version of constle (supported: webhook)", n.Channel)
		}
		if n.URLSecretRef == "" {
			return fmt.Errorf("human_gates.notify: webhook channel requires url_secret_ref (the env var holding the webhook URL)")
		}
	}

	// A gate with no verifiable approver is not a gate: it would either
	// block forever or (worse) need some other, undeclared way to decide
	// approval. Fail closed at validate time, per
	// spec/human-gates-webhook.md §3 and §8.
	if len(g.RequireApprovalFor) > 0 {
		if g.ApproverPubkey == "" {
			return fmt.Errorf("human_gates.approver_pubkey is required when require_approval_for is non-empty (see spec/human-gates-webhook.md §3)")
		}
		if err := did.Validate(g.ApproverPubkey); err != nil {
			return fmt.Errorf("human_gates.approver_pubkey is not a valid did:key Ed25519 string: %w", err)
		}
	}

	return nil
}

// EnforcedGateEntries splits require_approval_for into entries that map to a
// declared MCP tool (enforced by the gate proxy) and entries that provably
// match nothing (unenforced — surfaced as a warning by the CLI).
//
// The master switch comes first: when human_gates.enabled is false, the gate
// proxy arms nothing (spec/agent-manifest.md §14.1), so EVERY entry is
// unenforced however well it matches a declared tool. Consulting the tool
// mapping without consulting HumanGates.GatesArmed first is what let the CLI
// report a gate as "paused at the MCP gate proxy for approval" while the
// proxy forwarded every call to it ungated.
//
// Beyond the switch, an entry is "possibly enforced" when any declared server
// omits its tools allowlist: the runtime match is exact on the tool name of
// every tools/call, so such an entry may still gate a real call. Only entries
// that cannot match under any declared server are reported as unenforced.
func (m *AgentManifest) EnforcedGateEntries() (enforced, unenforced []string) {
	if !m.HumanGates.GatesArmed() {
		if len(m.HumanGates.RequireApprovalFor) == 0 {
			return nil, nil
		}
		return nil, append([]string(nil), m.HumanGates.RequireApprovalFor...)
	}

	anyServerWithoutToolList := false
	declaredTools := map[string]bool{}
	for _, srv := range m.MCP.Servers {
		if len(srv.Tools) == 0 {
			anyServerWithoutToolList = true
		}
		for _, tool := range srv.Tools {
			declaredTools[tool] = true
		}
	}

	for _, entry := range m.HumanGates.RequireApprovalFor {
		switch {
		case declaredTools[entry]:
			enforced = append(enforced, entry)
		case anyServerWithoutToolList:
			// May match at runtime; counted as enforced for warning purposes.
			enforced = append(enforced, entry)
		default:
			unenforced = append(unenforced, entry)
		}
	}
	return enforced, unenforced
}

// mcpServerHost extracts and validates the host of an MCP server URL.
func mcpServerHost(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("url %q must use http or https (streamable HTTP is the only supported MCP transport)", rawURL)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("url %q has no host", rawURL)
	}
	if !isASCIIHost(u.Hostname()) {
		return "", nonASCIIHostError("url", rawURL, u.Hostname())
	}
	return normalizeHost(u.Hostname()), nil
}

// normalizeHost renders a hostname in the one spelling the checks below
// compare, so that two names DNS and the egress proxy treat as the same host
// are the same string here too.
//
// Two spellings differ from the allowlist grammar without naming a different
// host. A DNS name is case-insensitive (RFC 4343), and a URL's host is
// explicitly case-insensitive (RFC 3986 §3.2.2), so "API.EXAMPLE.COM" is
// "api.example.com". A trailing dot is the fully-qualified form of the same
// name, so "api.example.com." is "api.example.com" as well.
//
// This matters because the two sides of every comparison below reach it by
// different routes. An allowed_hosts entry has been through
// ValidateAllowedHost, which admits only lowercase and rejects an empty
// trailing label; a host taken from mcp.servers[].url or
// a2a.peers[].endpoint has been through neither, because it is a URL and
// those spellings are legal in one. Comparing them raw meant an operator
// could declare an MCP server as "https://API.EXAMPLE.COM/mcp", allowlist
// "api.example.com", and have the bypass check see two different hosts —
// while Squid, matching case-insensitively, let the sandbox reach the server
// directly, with the tool allowlist, the human gates, spending metering and
// the gate's audit trail all skipped at once.
//
// Normalising here rather than at the point each host is read is deliberate:
// the guarantee belongs to the comparison, so a future caller that finds a
// host some third way cannot reintroduce the mismatch.
//
// A leading dot is left alone. It is the allowlist's subdomain marker, not
// part of a name.
//
// Trailing dots are stripped to exhaustion rather than one at a time, so the
// result does not depend on how many times this runs — a host reaches the
// comparators already normalised by mcpServerHost, and is normalised again
// there.
func normalizeHost(host string) string {
	return strings.TrimRight(strings.ToLower(host), ".")
}

// isASCIIHost reports whether a hostname is entirely ASCII.
//
// A non-ASCII host cannot be compared against the allowlist, and the gap is
// not cosmetic: Go's HTTP transport runs a URL's host through IDNA before it
// resolves anything, so "api。example.com" — written with U+3002, an
// ideographic full stop — is dialled as "api.example.com", and "bücher.example"
// as "xn--bcher-kva.example". The allowlist grammar admits neither spelling,
// so the bypass check would compare two strings that are different and name
// the same host, declare no overlap, and leave the sandbox a direct route to
// the very server the gate exists to sit in front of.
//
// Refusing is the fix rather than converting here, for the reason the grammar
// in network.go gives: one host, one spelling. The allowlist already requires
// the punycode form of an internationalised name, and requiring the same of a
// declared URL is what keeps both sides of the comparison in one alphabet.
//
// Converting would also make this check depend on tracking net/http's IDNA
// profile exactly and forever, since a validator that maps a name differently
// from the client that dials it reopens this very class of bug. Refusing has
// no such coupling.
func isASCIIHost(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// nonASCIIHostError explains why a declared host cannot be compared against
// the allowlist, naming the ASCII form the operator should have written. That
// form is punycode for an internationalised name, and a plain ASCII name for
// a host that only used characters Unicode maps onto ASCII ones — an
// ideographic or fullwidth full stop, say — so the message does not call it
// punycode.
//
// The form comes from idna.Lookup.ToASCII, which is exactly what net/http
// calls before it resolves a URL's host (idnaASCII, net/http/request.go), so
// the name in the message is the name this manifest would really have dialled
// rather than an approximation of it. That is the whole reason to compute it:
// telling an operator to use the ASCII form leaves them to find a converter,
// while naming it also shows them what their host actually resolves to —
// which for a homoglyph is the point being made. A Cyrillic
// "аpi.example.com" comes back as "xn--pi-6kc.example.com", which is
// visibly not the host they thought they had declared.
//
// ToASCII is only consulted for the message. Nothing decided here depends on
// it, so a future change to the profile can make the hint less apt but cannot
// make the refusal wrong.
func nonASCIIHostError(field, rawURL, host string) error {
	// Only a form that is itself a concrete, writable host is worth naming.
	// Mapping can leave an empty first label behind — a lone zero-width space
	// becomes ".example", which the allowlist grammar reads as a subdomain
	// pattern rather than a host — and suggesting something the operator
	// cannot put in a URL would send them in a circle.
	// Normalise before converting. idna.Lookup is strict about an empty final
	// label, so "bücher.example." - a fully qualified name, and a spelling
	// this package otherwise accepts - would otherwise be reported as having
	// no usable form when its form is xn--bcher-kva.example.
	ascii, err := idna.Lookup.ToASCII(normalizeHost(host))
	if err == nil && (strings.HasPrefix(ascii, ".") || ValidateAllowedHost(ascii) != nil) {
		err = fmt.Errorf("not a usable host")
	}
	if err != nil || ascii == normalizeHost(host) {
		return fmt.Errorf(
			"%s %q has a non-ASCII host that is not a usable name — "+
				"declare a host that can be compared with network.allowed_hosts",
			field, rawURL)
	}
	return fmt.Errorf(
		"%s %q has a non-ASCII host — use the ASCII form it resolves to, %s, "+
			"so that it can be compared with network.allowed_hosts",
		field, rawURL, ascii)
}

// hostsOverlap reports whether an allowed_hosts entry covers the given host.
// Squid dstdomain entries starting with "." match all subdomains.
func hostsOverlap(allowed, host string) bool {
	allowed, host = normalizeHost(allowed), normalizeHost(host)
	if strings.HasPrefix(allowed, ".") {
		return host == strings.TrimPrefix(allowed, ".") || strings.HasSuffix(host, allowed)
	}
	return allowed == host
}

// isHostLoopbackAlias reports whether an allowlist entry addresses the
// sandbox host itself — the gate proxy's transport surface.
func isHostLoopbackAlias(host string) bool {
	switch normalizeHost(host) {
	case "localhost", "127.0.0.1", "::1", "host.docker.internal", ".host.docker.internal":
		return true
	}
	return false
}

// isValidID enforces the shared id charset documented on MCPServer.ID and
// A2APeer.Name — these ids are embedded in environment variable names, gate
// URLs, and audit events.
func isValidID(id string) bool {
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// capabilityFloor returns the weakest isolation level that still covers every
// declared capability, together with every capability that demands exactly
// that level.
//
// It is the single definition of "the isolation these capabilities require":
// Parse fills an omitted level from it and Validate holds a declared one to
// it, so the level Constle would have chosen and the level it will accept can
// never drift apart. A second walk over the same table is how a capability
// wired into one of them and not the other reopens this hole for that one
// capability, with nothing failing.
//
// The capabilities are returned because a refusal has to name what forces the
// floor — "weaker than kernel" leaves an author guessing which entry in their
// own list to look at. All of them are returned, in declaration order, so the
// remediation is a complete one: dropping the named set actually lowers the
// floor, where dropping one of several would only surface the next.
//
// The returned slice is empty only when the floor is IsolationNone, which
// every valid level satisfies: minIsolationFor never returns IsolationNone, so
// any declared capability raises the floor above it and names itself.
func capabilityFloor(caps []Capability) (IsolationLevel, []Capability) {
	floor := IsolationNone
	var drivers []Capability

	for _, cap := range caps {
		switch required := minIsolationFor(cap); {
		case isolationRank(required) > isolationRank(floor):
			// A stronger capability supersedes everything named so far;
			// reusing the backing array keeps this to one allocation.
			floor, drivers = required, append(drivers[:0], cap)
		case required == floor:
			drivers = append(drivers, cap)
		}
	}

	return floor, drivers
}

// InferIsolation returns the strongest IsolationLevel required by any of the
// given capabilities. It is the level Parse writes when the Agentfile omits
// one; capabilityFloor holds the definition, so an inferred level is always
// exactly the floor Validate enforces.
func InferIsolation(caps []Capability) IsolationLevel {
	level, _ := capabilityFloor(caps)
	return level
}

// RequiresHumanGate reports whether the capability involves an irreversible
// action that requires human approval (payments, email, deletion, sub-agents).
func RequiresHumanGate(cap Capability) bool {
	switch cap {
	case CapExternalTransfer, CapSendEmail, CapDeleteRecords, CapSpawnSubagent:
		return true
	default:
		return false
	}
}

// InferRequiredGates returns the list of capability names that require a human
// gate, derived from the declared capabilities.
func InferRequiredGates(caps []Capability) []string {
	var gates []string
	for _, cap := range caps {
		if RequiresHumanGate(cap) {
			gates = append(gates, string(cap))
		}
	}
	return gates
}

// minIsolationFor returns the minimum IsolationLevel required for a capability.
func minIsolationFor(cap Capability) IsolationLevel {
	switch cap {
	case CapReadFile, CapWriteFile:
		return IsolationProcess

	case CapWebSearch, CapExternalAPI:
		return IsolationNetwork

	case CapSendEmail:
		return IsolationNetwork

	case CapExternalTransfer, CapDeleteRecords, CapSpawnSubagent:
		return IsolationKernel

	default:
		return IsolationProcess
	}
}

// isolationRank returns a numeric rank for comparison. Higher = stronger isolation.
func isolationRank(level IsolationLevel) int {
	switch level {
	case IsolationNone:
		return 0
	case IsolationProcess:
		return 1
	case IsolationNetwork:
		return 2
	case IsolationKernel:
		return 3
	default:
		return 0
	}
}

func isKnownCapability(cap Capability) bool {
	known := []Capability{
		CapReadFile, CapWriteFile,
		CapWebSearch, CapExternalAPI,
		CapSendEmail, CapSpawnSubagent,
		CapExternalTransfer, CapDeleteRecords,
	}
	for _, k := range known {
		if cap == k {
			return true
		}
	}
	return false
}
