# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `BOUNCING_ON_TYPE`, `OVERRIDE_REMEDIATION` and `FALLBACK_REMEDIATION` — the same
  names, values and order as the nginx bouncer, so a fleet running both needs one
  mental model. Each reachable remediation renders to its own map (`ban` to the
  existing `blocklist.txt`/`.dbm`, `captcha` to a `captcha.txt`/`.dbm` beside it),
  and the map set is derived from the settings, so a map exists exactly when
  something can land in it. Previously every accepted decision went into one map, so
  a captcha decision was blocked outright rather than challenged; a single address
  can now hold a ban and a captcha at once, each expiring on its own. ([#2])
- `FALLBACK_REMEDIATION` (default `ban`) catches what Apache cannot express — an
  unsupported type such as `throttle`, or a `captcha` when no challenge is
  configured. `OVERRIDE_REMEDIATION` routes every decision into one remediation
  regardless of type. The two apply in the nginx bouncer's order — override, then
  fallback — so overriding to captcha on a box with no challenge degrades to a block
  rather than enforcing nothing. ([#2])
- A decision that changes type between polls (the hub escalating a captcha to a ban
  under the same id) moves between maps instead of lingering in both. ([#2])
- A captcha challenge listener (`CAPTCHA_LISTEN`, off by default). It serves the
  challenge page, verifies the solved token against the provider server-to-server,
  and records the client in a pass map Apache checks ahead of the captcha map. The
  pass map is a `txt:` map so a solve goes live on the client's next request rather
  than waiting for a DBM rebuild. Built and tested against a self-hosted
  [Cap](https://trycap.dev) instance, whose verify API takes the reCAPTCHA field
  names (`secret` + `response`); other providers of that family are untested here
  and at least need form encoding, which is not implemented. ([#2])
- `CAPTCHA_PASS_KEY` chooses what a solved challenge is remembered against: `ip`
  (the default — covers every browser at that address, as CrowdSec's own nginx
  bouncer does) or `cookie` (per-browser, so shared NAT is handled, at the cost of
  the pass being scoped to one domain). ([#2], [#6])

### Changed

- The startup line lists every map it will write, and the per-poll totals are
  reported per map (`ban=128963 captcha=412`) rather than as one number. ([#2])
- The startup line states the resolved policy outright, e.g. `remediation policy:
  bouncing_on=all override="" fallback="ban" -> ban:ban captcha:captcha throttle:ban`.
  ([#2])

### Deprecated

- `ONLY_BAN`, replaced by `BOUNCING_ON_TYPE` and to be removed in a future release.
  It is honoured only when `BOUNCING_ON_TYPE` is unset (`true` → `ban`, `false` →
  `all`) and warns at every start. Note `ONLY_BAN=false` is no longer equivalent: it
  used to force every decision type into the ban map, where captcha decisions now
  render to their own and `FALLBACK_REMEDIATION` decides what happens when no
  challenge is configured. `ONLY_BAN=true` — the default, and what the packages ship
  — behaves exactly as before. ([#2])

### Security

- The challenge fails closed everywhere: a provider that rejects a token, errors,
  returns nonsense or cannot be reached leaves the client challenged, and a pass
  that cannot be written to disk is reported as a failure rather than a redirect.
  A captcha outage never becomes a free pass. ([#2])
- Passes are discarded when the daemon restarts. They live in memory, so a pass
  file inherited from a previous run would name clients with no expiry attached —
  nothing would ever prune them and Apache would honour them permanently. ([#2])
- The return path a client is sent back to is reduced to a same-site path, so the
  challenge cannot be used as an open redirect off a domain browsers already trust.
  Absolute URLs, protocol-relative `//host`, `/\host` and anything containing CR or
  LF fall back to the site root. ([#2])

## [0.1.0] - 2026-07-31

First public release ([#1]). A CrowdSec bouncer for cPanel and Plesk Apache origins:
it follows the CrowdSec decision stream and keeps the currently banned addresses in
an Apache `RewriteMap`, so banned traffic is turned away by Apache itself.

### Added

- Blocks banned addresses at Apache through a `RewriteMap` — the full ban list on
  startup, then updates every `UPDATE_FREQUENCY` seconds. An empty map is created
  before the first sync if none exists, since Apache refuses to start when a
  `RewriteMap` file is missing; an existing list is never overwritten. ([#1])
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
  the map if something removes it. A re-sync that would unban most of the list is
  held back until a second one agrees, so a momentary LAPI fault can't clear your
  blocklist. ([#1])
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

[Unreleased]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/releases/tag/v0.1.0
[#1]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/pull/1
[#2]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/issues/2
[#6]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/issues/6
