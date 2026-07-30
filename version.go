package main

import (
	"runtime/debug"
	"strings"
)

// shortRevLen is how much of the commit hash goes in the User-Agent: 12 hex
// chars, the same prefix Go uses in module pseudo-versions, which is well past
// the point of ambiguity for a single repository.
const shortRevLen = 12

// version is the release tag, stamped at link time by the release workflow:
//
//	go build -ldflags="-X main.version=1.2.3"
//
// It stays empty for every other build - a manual workflow run, or a local
// `go build` - and resolveVersion then falls back to the commit hash the Go
// toolchain records in the binary on its own (no flags needed, as long as the
// build runs inside the git work tree).
var version string

// userAgent identifies the bouncer to the LAPI: "crowdsec-apache2-bouncer/1.2.3"
// off a release tag, "crowdsec-apache2-bouncer/97d283ee5c0a" off an untagged
// build. Resolved once at startup - build info can't change under a live process.
var userAgent = "crowdsec-apache2-bouncer/" + resolveVersion(version, readBuildInfo())

// readBuildInfo returns the build info embedded in the binary, or nil when the
// binary carries none.
func readBuildInfo() *debug.BuildInfo {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return info
}

// resolveVersion takes the most specific version the build carries: the stamped
// release tag, else the VCS revision ("-dirty" when the tree held uncommitted
// changes), else "dev". It never returns "" - an empty product-version would make
// the User-Agent malformed, since RFC 9110 requires a token after the "/".
func resolveVersion(stamped string, info *debug.BuildInfo) string {
	// Tags are v-prefixed by convention; the version in the header is not.
	if tag := strings.TrimPrefix(strings.TrimSpace(stamped), "v"); tag != "" {
		return tag
	}
	var revision, modified string
	if info != nil {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value
			}
		}
	}
	if revision == "" {
		return "dev" // built outside a work tree, or with -buildvcs=false
	}
	if len(revision) > shortRevLen {
		revision = revision[:shortRevLen]
	}
	if modified == "true" {
		revision += "-dirty" // same marker as `git describe --dirty`
	}
	return revision
}
