package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	// vcs builds the settings table the Go toolchain stamps into a binary built
	// inside a git work tree.
	vcs := func(revision, modified string) *debug.BuildInfo {
		return &debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: revision},
			{Key: "vcs.modified", Value: modified},
		}}
	}
	const rev = "97d283ee5c0a1b2c3d4e5f60718293a4b5c6d7e8" // a full 40-char hash

	for _, tc := range []struct {
		name    string
		stamped string
		info    *debug.BuildInfo
		want    string
	}{
		{"a stamped tag beats the commit", "1.2.3", vcs(rev, "false"), "1.2.3"},
		{"a v prefix is dropped", "v1.2.3", nil, "1.2.3"},
		{"untagged falls back to the short commit", "", vcs(rev, "false"), "97d283ee5c0a"},
		{"a modified tree is marked dirty", "", vcs(rev, "true"), "97d283ee5c0a-dirty"},
		{"a short revision is left alone", "", vcs("abc123", "false"), "abc123"},
		{"no tag and no VCS data", "", &debug.BuildInfo{}, "dev"},
		{"no build info at all", "", nil, "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveVersion(tc.stamped, tc.info); got != tc.want {
				t.Errorf("resolveVersion(%q) = %q, want %q", tc.stamped, got, tc.want)
			}
		})
	}
}

// The User-Agent must always be a well-formed product token - "name/version"
// with both halves present - however the binary was built.
func TestUserAgentIsWellFormed(t *testing.T) {
	name, ver, ok := strings.Cut(userAgent, "/")
	if !ok || name != "crowdsec-apache2-bouncer" || ver == "" {
		t.Fatalf("User-Agent = %q, want crowdsec-apache2-bouncer/<version>", userAgent)
	}
	t.Logf("User-Agent: %s", userAgent)
}
