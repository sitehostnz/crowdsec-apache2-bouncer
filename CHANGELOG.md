# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-31

First public release ([#1]). A CrowdSec bouncer for cPanel and Plesk Apache origins:
it follows the CrowdSec decision stream and keeps the currently banned addresses in
an Apache `RewriteMap`, so banned traffic is turned away by Apache itself.

### Added

- Blocks banned addresses at Apache through a `RewriteMap` — the full ban list on
  startup, then updates every `UPDATE_FREQUENCY` seconds. ([#1])
- Optional DBM hash map (`MAP_TYPE=dbm`, what the packages ship with) for
  constant-time lookups on large lists. If a rebuild ever fails the previous map
  stays in place, so the list is never lost. ([#1])
- Updates are picked up by Apache on their own — no reload or restart needed — and
  the map is swapped in atomically, so Apache never reads a half-written file. ([#1])
- Built for six-figure ban lists: a poll only does work proportional to what
  changed, and memory use stays flat however long the daemon runs. ([#1])
- Your own allowlist and blocklist alongside CrowdSec's, created in `CUSTOM_LIST_DIR`
  beside Apache's own config and, in `dbm` mode, rebuilt whenever you edit one. The
  allowlist always wins over a ban. ([#1])
- Range and CIDR bans are expanded to individual addresses, up to
  `EXPAND_MAX_HOSTS`. Anything larger, including any sizeable IPv6 range, is skipped
  and logged rather than bloating the map. ([#1])
- IPv6 bans, written in the canonical form Apache matches against. ([#1])
- An address covered by more than one CrowdSec decision stays blocked until the last
  of those decisions expires. ([#1])
- A periodic full re-sync (`RESYNC_INTERVAL`) as a safety net, which also rebuilds
  the map if something removes it. ([#1])
- Separate timeouts for talking to the LAPI: `REQUEST_TIMEOUT` to fail fast when it
  is unreachable, and `STREAM_REQUEST_TIMEOUT` (15s by default) so a large first
  download isn't cut short. ([#1])
- HTTPS to the LAPI, verified against the system CA store, with `CA_BUNDLE` and
  `INSECURE` overrides. ([#1])
- Identifies itself to CrowdSec with its release version, so `cscli bouncers list`
  shows which build each origin is running. ([#1])
- Configuration through `/etc/crowdsec/bouncers/crowdsec-apache2-bouncer.conf`, plus
  a `-dir` flag to put the map files somewhere else. ([#1])
- A hardened `systemd` unit and a ready-to-include Apache snippet. ([#1])
- README covering installation, cPanel and Plesk integration, getting the real
  client IP behind a CDN, and performance notes. ([#1])
- `.deb` and `.rpm` packages and a static binary, built and attached to each GitHub
  release automatically. ([#1])
- A benchmark suite covering the paths that run on every update. ([#1])

[0.1.0]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/releases/tag/v0.1.0
[#1]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/pull/1
