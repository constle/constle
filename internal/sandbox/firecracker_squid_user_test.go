package sandbox

import (
	"testing"
)

// stubSquidDetection pins both detection inputs — the `squid -v` output and
// the host's user database — restoring the real ones on cleanup.
func stubSquidDetection(t *testing.T, versionOutput string, existingUsers ...string) {
	t.Helper()
	origVersion, origExists := squidVersionOutput, squidUserExists
	t.Cleanup(func() { squidVersionOutput, squidUserExists = origVersion, origExists })

	squidVersionOutput = func() string { return versionOutput }
	squidUserExists = func(name string) bool {
		for _, u := range existingUsers {
			if u == name {
				return true
			}
		}
		return false
	}
}

// Abbreviated real `squid -v` shapes. Debian-family builds quote the
// configure options with single quotes; other builds may not.
const (
	squidVersionDebian = `Squid Cache: Version 7.2
Service Name: squid
configure options:  '--prefix=/usr' '--with-logdir=/var/log/squid' '--with-default-user=proxy' '--with-systemd'
`
	squidVersionRHEL = `Squid Cache: Version 6.10
Service Name: squid
configure options:  '--prefix=/usr' '--with-default-user=squid' '--enable-linux-netfilter'
`
	squidVersionUnquoted = `Squid Cache: Version 6.1
configure options: --prefix=/usr/local/squid --with-default-user=squidproxy
`
	squidVersionNoOption = `Squid Cache: Version 6.1
configure options: --prefix=/usr/local/squid
`
)

func TestDetectSquidUser(t *testing.T) {
	tests := []struct {
		name          string
		versionOutput string
		existingUsers []string
		want          string
		wantErr       bool
	}{
		{
			name:          "debian build reports proxy",
			versionOutput: squidVersionDebian,
			existingUsers: []string{"proxy", "nobody"},
			want:          "proxy",
		},
		{
			name: "rhel build reports squid",
			// The exact live-infra failure: no "proxy" user on the host,
			// the package created "squid" instead.
			versionOutput: squidVersionRHEL,
			existingUsers: []string{"squid", "nobody"},
			want:          "squid",
		},
		{
			name:          "unquoted configure option",
			versionOutput: squidVersionUnquoted,
			existingUsers: []string{"squidproxy", "nobody"},
			want:          "squidproxy",
		},
		{
			name: "build user missing on host falls back to package account",
			// A binary built for one user on a host that only has the other:
			// the existing account wins over the baked-in name.
			versionOutput: squidVersionDebian,
			existingUsers: []string{"squid", "nobody"},
			want:          "squid",
		},
		{
			name:          "no configure option probes proxy first",
			versionOutput: squidVersionNoOption,
			existingUsers: []string{"proxy", "squid", "nobody"},
			want:          "proxy",
		},
		{
			name:          "no configure option probes squid second",
			versionOutput: squidVersionNoOption,
			existingUsers: []string{"squid", "nobody"},
			want:          "squid",
		},
		{
			name:          "nobody is the last resort",
			versionOutput: squidVersionNoOption,
			existingUsers: []string{"nobody"},
			want:          "nobody",
		},
		{
			name:          "squid -v unavailable still probes accounts",
			versionOutput: "",
			existingUsers: []string{"proxy"},
			want:          "proxy",
		},
		{
			name:          "no candidate user exists",
			versionOutput: squidVersionNoOption,
			existingUsers: nil,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubSquidDetection(t, tt.versionOutput, tt.existingUsers...)

			got, err := detectSquidUser()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("detectSquidUser() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("detectSquidUser(): %v", err)
			}
			if got != tt.want {
				t.Errorf("detectSquidUser() = %q, want %q", got, tt.want)
			}
		})
	}
}
