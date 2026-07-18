package manifest

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/did"
)

// testDID derives a deterministic valid did:key from a seed byte, so tests
// can use several distinct real identities without fixtures.
func testDID(t *testing.T, seed byte) string {
	t.Helper()
	seedBytes := make([]byte, ed25519.SeedSize)
	seedBytes[0] = seed
	pub := ed25519.NewKeyFromSeed(seedBytes).Public().(ed25519.PublicKey)
	d, err := did.FromPublicKey(pub)
	if err != nil {
		t.Fatalf("cannot derive test DID: %v", err)
	}
	return d
}

// validManifestWithA2A builds a minimal valid manifest with one declared
// peer, for validation tests to mutate.
func validManifestWithA2A(t *testing.T) *AgentManifest {
	return &AgentManifest{
		APIVersion: "constle.dev/v1alpha1",
		Kind:       "AgentManifest",
		Identity:   Identity{Name: "my-agent", DID: testDID(t, 1)},
		A2A: A2A{
			Listen: ":7420",
			Peers: []A2APeer{
				{Name: "peer-a", DID: testDID(t, 2), Endpoint: "http://192.168.1.20:7420"},
			},
		},
	}
}

func TestValidateA2A(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T, m *AgentManifest)
		wantErr string // substring the error must contain; "" = no error
	}{
		{
			name:   "valid peer with listen",
			mutate: func(t *testing.T, m *AgentManifest) {},
		},
		{
			name: "valid outbound-only (no listen)",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Listen = ""
			},
		},
		{
			name: "no a2a section at all",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A = A2A{}
			},
		},
		{
			name: "a2a without identity.did fails closed",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.Identity.DID = ""
			},
			wantErr: "identity.did is required",
		},
		{
			name: "listen without peers fails closed",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers = nil
			},
			wantErr: "a2a.peers is empty",
		},
		{
			name: "invalid listen address",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Listen = "no-port-here"
			},
			wantErr: "a2a.listen",
		},
		{
			name: "peer without name",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers[0].Name = ""
			},
			wantErr: "needs a name",
		},
		{
			name: "peer name with invalid charset",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers[0].Name = "Peer A"
			},
			wantErr: "invalid name",
		},
		{
			name: "duplicate peer names",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers = append(m.A2A.Peers,
					A2APeer{Name: "peer-a", DID: testDID(t, 3), Endpoint: "http://192.168.1.21:7420"})
			},
			wantErr: "duplicate name",
		},
		{
			name: "duplicate peer DIDs",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers = append(m.A2A.Peers,
					A2APeer{Name: "peer-b", DID: m.A2A.Peers[0].DID, Endpoint: "http://192.168.1.21:7420"})
			},
			wantErr: "same did",
		},
		{
			name: "peer without did",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers[0].DID = ""
			},
			wantErr: "did is required",
		},
		{
			name: "peer with malformed did",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers[0].DID = "did:web:example.com"
			},
			wantErr: "peer-a",
		},
		{
			name: "peer did equals own identity",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers[0].DID = m.Identity.DID
			},
			wantErr: "own identity.did",
		},
		{
			name: "peer without endpoint",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers[0].Endpoint = ""
			},
			wantErr: "endpoint is required",
		},
		{
			name: "peer endpoint with bad scheme",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers[0].Endpoint = "ftp://192.168.1.20:7420"
			},
			wantErr: "must use http or https",
		},
		{
			name: "peer endpoint host in allowed_hosts fails closed",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.Sandbox.Network.AllowedHosts = []string{"192.168.1.20"}
			},
			wantErr: "bypassing the signing A2A gate",
		},
		{
			name: "peer endpoint domain covered by wildcard allowed_hosts fails closed",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.A2A.Peers[0].Endpoint = "https://a2a.peer.example.com:7420"
				m.Sandbox.Network.AllowedHosts = []string{".example.com"}
			},
			wantErr: "bypassing the signing A2A gate",
		},
		{
			name: "unrelated allowed_hosts stay allowed",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.Sandbox.Network.AllowedHosts = []string{"api.groq.com"}
			},
		},
		{
			name: "host loopback alias in allowed_hosts fails closed with peers",
			mutate: func(t *testing.T, m *AgentManifest) {
				m.Sandbox.Network.AllowedHosts = []string{"host.docker.internal"}
			},
			wantErr: "must not be allowlisted when a2a.peers are declared",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifestWithA2A(t)
			tt.mutate(t, m)
			err := m.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseA2A(t *testing.T) {
	yaml := `
apiVersion: constle.dev/v1alpha1
kind: AgentManifest
identity:
  name: agent-b
  did: "` + testDID(t, 1) + `"
a2a:
  listen: "0.0.0.0:7420"
  peers:
    - name: agent-a
      did: "` + testDID(t, 2) + `"
      endpoint: "http://192.168.1.20:7420"
`
	m, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if m.A2A.Listen != "0.0.0.0:7420" {
		t.Errorf("a2a.listen = %q, want 0.0.0.0:7420", m.A2A.Listen)
	}
	if len(m.A2A.Peers) != 1 || m.A2A.Peers[0].Name != "agent-a" {
		t.Fatalf("a2a.peers not parsed: %+v", m.A2A.Peers)
	}
	if err := m.Validate(); err != nil {
		t.Errorf("valid A2A manifest failed validation: %v", err)
	}
}
