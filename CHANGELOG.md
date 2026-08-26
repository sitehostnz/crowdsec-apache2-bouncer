# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-08-27

### Fixed

- The full-snapshot shrink guard counts IPs rather than decisions, so a resync is no longer refused when CrowdSec re-issues the same addresses under fresh decision ids. ([#13])
- A snapshot expressing the same addresses as fewer, larger range decisions is no longer read as a mass unban. ([#13])

### Changed

- The shrink guard runs after a snapshot is applied and rolls it back when refused, since only the applied result gives a true IP count. ([#13])
- The refused-resync warning reports the IPs the snapshot would have removed and added rather than its decision count. ([#13])

## [1.0.0] - 2026-08-24

Adds captcha as a remediation. 0.1.0 sent every accepted decision to one ban map;
decisions now route per remediation, so a flagged visitor can be challenged instead
of blocked. Upgrading needs no config change — the captcha is off until you set
`CAPTCHA_LISTEN`.

### Added

- `BOUNCING_ON_TYPE`, `OVERRIDE_REMEDIATION` and `FALLBACK_REMEDIATION`, matching the nginx bouncer's names and precedence. ([#2])
- Each reachable remediation renders its own map, so one address can hold a ban and a captcha at once. ([#2])
- Captcha challenge listener (`CAPTCHA_LISTEN`, off by default) verifying ALTCHA proof of work in-process — no captcha service, no shared secret. ([#2])
- Solvers go in a `txt:` pass map Apache reads ahead of the captcha map, so a solve applies on the next request. ([#2])
- `ALTCHA_ALGORITHM`, `ALTCHA_COST` and `ALTCHA_COMPLEXITY` tune the check; an unusable combination falls back to the defaults with a warning. ([#2])
- `CAPTCHA_TEMPLATE` replaces the built-in challenge page. ([#2])
- Prometheus endpoint (`METRICS_LISTEN`, off by default) covering poll health, map sizes and captcha counters. ([#2])
- Captcha rules in `apache/blocklist.conf`, shipped commented out. ([#7])
- `-version` prints the build and exits.

> ⚠️ Challenged vhosts need HTTPS. The widget uses `crypto.subtle`, which browsers
> expose only in a secure context, so a challenged visitor on plain HTTP can never
> solve. Keep those vhosts on `FALLBACK_REMEDIATION=ban`.

### Changed

- The startup line states the resolved remediation policy and every map it will write.
- Config faults are tiered: substitute and warn, switch the captcha off, or refuse to start. Only data loss refuses.
- `postinst` pre-creates `captcha_passed.txt`, so Apache does not refuse to start on a missing `RewriteMap`.

### Deprecated

- `ONLY_BAN`, replaced by `BOUNCING_ON_TYPE`. Setting both is a startup error.

### Security

- The challenge fails closed: a token that does not verify leaves the client challenged. ([#2])
- The widget script is pinned with a Subresource Integrity digest. ([#2])
- The client address is the last `X-Forwarded-For` entry; an unparseable one is refused rather than keyed to loopback. ([#7])
- Apache exemptions are anchored to the proxied path, and the ban rule carries none — a banned client cannot reach the mint endpoint. ([#2])
- Return targets are reduced to a same-site rooted path. ([#2])
- Passes are discarded at startup and emptied at shutdown. ([#2])
- A `CAPTCHA_LISTEN` bind wider than loopback warns at startup. ([#2])
- The challenge store caps at 200,000 outstanding and refuses rather than evicting; alert on `altcha_challenges_refused_total`. Nothing bounds the request rate yet. ([#9])

## [0.1.0] - 2026-07-31

First public release ([#1]). A CrowdSec bouncer for cPanel and Plesk Apache origins:
it follows the decision stream and keeps banned addresses in an Apache `RewriteMap`,
so banned traffic is turned away by Apache itself.

### Added

- Blocks banned addresses through a `RewriteMap`, refreshed every `UPDATE_FREQUENCY`. ([#1])
- Creates an empty map before the first sync, since Apache refuses to start without one. ([#1])
- Optional DBM hash map (`MAP_TYPE=dbm`, what the packages ship) for constant-time lookups. ([#1])
- A failed DBM rebuild leaves the previous map in place, so the list is never lost. ([#1])
- Maps are swapped in atomically and picked up without an Apache reload. ([#1])
- A poll does work proportional to what changed, and memory stays flat. ([#1])
- Your own allowlist and blocklist in `CUSTOM_LIST_DIR`; the allowlist wins over a ban. ([#1])
- Refuses a resync that would unban most of the list, and re-checks on the next poll. ([#1])
- Ships a systemd unit, a conffile and `.deb`/`.rpm` packages. ([#1])

[1.0.1]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/releases/tag/v0.1.0
[#1]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/pull/1
[#2]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/issues/2
[#7]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/pull/7
[#9]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/issues/9
[#13]: https://github.com/sitehostnz/crowdsec-apache2-bouncer/pull/13
