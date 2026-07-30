# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-24

### Added

- Separate, configurable LAPI query timeouts: `REQUEST_TIMEOUT` (connect + wait for
  the response to start) and `STREAM_REQUEST_TIMEOUT` (overall deadline for the
  decision-stream pull, default 15s, so a large startup snapshot isn't cut short).
- Stream-mode CrowdSec bouncer for cPanel / Plesk Apache2 origins: polls the LAPI
  decisions stream (full snapshot on startup, then deltas every `UPDATE_FREQUENCY`s)
  and renders the active ban list to an Apache `RewriteMap`.
- Refcounted IP set so an IP shared by overlapping decisions is only dropped when the
  last contributing decision expires.
- Atomic map writes (temp file + rename) so Apache never reads a half-written map, and
  the mtime change triggers mod_rewrite's per-map reload without an Apache restart.
- Optional DBM hash map (`MAP_TYPE=dbm`) built via `httxt2dbm` for O(1) lookups; the
  previous DBM is kept if a rebuild fails.
- CIDR/range decisions expanded to individual IPs, capped by `EXPAND_MAX_HOSTS`; larger
  ranges (and any large IPv6 range) are skipped and logged rather than exploding the file.
- IPv6 single-IP support with RFC 5952 canonicalisation so keys byte-match Apache's
  `%{REMOTE_ADDR}`.
- Periodic full re-sync (`RESYNC_INTERVAL`) as a safety net against stream cursor drift,
  which also self-heals an externally deleted map file.
- TLS support: verify against the system CA store by default, with `CA_BUNDLE` and
  `INSECURE` overrides.
- Configuration via environment variables (`crowdsec-apache2-bouncer.conf`) with a `-dir`
  flag override for the blocklist directory.
- `systemd` unit with hardening (`crowdsec-apache2-bouncer.service`) and an Apache
  server-context snippet (`apache/blocklist.conf`).
- Apache examples for a local allowlist (bypass a block) and an operator-maintained
  custom blocklist, both checked alongside the CrowdSec map, plus a CIDR bypass via
  `mod_rewrite`'s `-ipmatch`.
- README covering install, cPanel/Plesk Apache integration, the real-client-IP caveat,
  RewriteMap reload/performance notes, troubleshooting, and operating steps.
- GitHub Actions release workflow: on a `v*` tag it runs the tests, builds the static
  `amd64` binary, packages a `.deb` (Debian/Ubuntu, e.g. Plesk) and an `.rpm` (RHEL/Alma,
  e.g. cPanel) with `fpm` (maintainer scripts under `packaging/`), and attaches all three
  to the GitHub Release.

[Unreleased]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/releases/tag/v0.1.0
