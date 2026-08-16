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
  challenge page, verifies the solve **in-process** — there is no captcha service,
  no shared secret and nothing on the wire — and records the client in a pass map
  Apache checks ahead of the captcha map. The pass map is a `txt:` map so a solve
  goes live on the client's next request rather than waiting for a DBM rebuild.
  ([#2])

  The proof of work is [ALTCHA](https://altcha.org)'s: the daemon publishes half of
  a derived key and keeps the other half, and the browser searches counters until
  its derived key starts with the published prefix. The unpublished half is the
  proof, so verifying is a string comparison — and because redeeming a challenge
  removes it, a solution cannot be replayed.

  > ⚠️ **Requires HTTPS** on any vhost that will be challenged. The widget uses
  > `crypto.subtle`, which browsers expose only in a secure context, so on plain
  > HTTP a challenged visitor can never solve. Keep those vhosts on
  > `FALLBACK_REMEDIATION=ban`.

- `ALTCHA_ALGORITHM` (default `PBKDF2/SHA-256`), `ALTCHA_COST` (`5000`) and
  `ALTCHA_COMPLEXITY` (`5000`) tune the check. Only names the published widget can
  solve are accepted, and a combination a browser could not finish inside the
  widget's 90-second timeout is refused at startup rather than left to spin in
  somebody's browser. The defaults match the nginx bouncer's cost, so a visitor
  meets a comparable check on either. ([#2])
- `crowdsec_apache_bouncer_altcha_challenges`,
  `..._altcha_challenges_expired_total` and `..._altcha_challenges_minted_total` —
  the challenges outstanding, abandoned and derived. Minting is the only work an
  unauthenticated caller can ask for, so the last one is what a flood looks like.
  ([#2])
- `CAPTCHA_TEMPLATE` replaces the built-in challenge page with an operator one (Go
  `html/template`; the fields are listed in the README). It must reference
  `.Widget`, `.WidgetJS`, `.WidgetSRI`, `.Action`, `.Return` and `.SolveEvent` —
  `html/template` silently ignores fields a template does not use, so a page
  written against an older field set would otherwise parse cleanly, render 200 and
  be unsolvable with nothing logged. A template missing one is refused at startup
  and the listener does not come up, which leaves captcha decisions falling back to
  a refusal at the Apache layer. ([#2])
- `-version` prints the build and exits, without needing the daemon to start or
  `METRICS_LISTEN` to be set.

### Changed

- **Breaking — the Apache `ProxyPass` for the challenge listener must have no
  trailing slash on either side.** With one on the target, the widget's
  `/crowdsec-verify/altcha-challenge` maps to `//altcha-challenge`, which lands
  outside the proxy prefix and is refused by the rewrite rules — the widget never
  receives a challenge and the page hangs. Both shipped Apache references were
  corrected; **update any vhost copied from the previous ones**:

  ```apache
  ProxyPass        /crowdsec-verify http://127.0.0.1:8125
  ProxyPassReverse /crowdsec-verify http://127.0.0.1:8125
  ```

  A request that looks like the challenge endpoint but reaches the catch-all is now
  answered with a 404 and a log line naming this fix, instead of an HTML page the
  widget cannot parse. ([#2])
- **Breaking — the pass map's `RewriteMap` name is `solved`, not `cap_ok`.** It is
  internal to the Apache config; every shipped reference moved with it. ([#2])

- The startup line lists every map it will write, and the per-poll totals are
  reported per map (`ban=128963 captcha=412`) rather than as one number. ([#2])
- The startup line states the resolved policy outright, e.g. `remediation policy:
  bouncing_on=all override="" fallback="ban" -> ban:ban captcha:captcha throttle:ban`.
  ([#2])
- The challenge listener allocates less and retains less. Outstanding challenges
  are held raw and re-encoded on fetch, roughly halving the store's worst-case
  footprint (~37 MiB at its 200k cap, down from ~65 MiB measured); minting under
  the plain `SHA-256`/`384`/`512` algorithms reuses one digest instead of
  allocating ~800 KB of garbage per challenge, halving its CPU; and the widget
  markup is rendered once at startup rather than on every page. Benchmarks for the
  whole path live in `profile_test.go`, and the README's challenge-listener
  section carries the numbers. ([#2])

### Removed

- **The Cap provider, and with it `CAPTCHA_PROVIDER`, `CAPTCHA_VERIFY_URL`,
  `CAPTCHA_SECRET`, `CAPTCHA_API_ENDPOINT` and `CAPTCHA_VERIFY_TIMEOUT`.**
  Verification happens in this process now. **Setting any of them is a fatal
  startup error** naming what replaced it — deliberately, so a config half-migrated
  from Cap cannot start cleanly while doing something other than what it says.
  Blanking the line (`CAPTCHA_SECRET=`) is fine; only a real value is refused.
  ([#2])
- `captcha_verify_duration_seconds`, which measured a server-to-server round trip
  that no longer happens. ([#2])

- `CAPTCHA_PASS_KEY`, `CAPTCHA_COOKIE_NAME` and `CAPTCHA_COOKIE_SECURE`. Cookie
  keying was only half-built — the daemon set the cookie, but the Apache side to
  match on it was never finished — so `CAPTCHA_PASS_KEY=cookie` started cleanly
  and then re-challenged every visitor forever. Passes are keyed on the solver's
  address. **If you set it, remove it: an unknown setting is ignored, so nothing
  will warn you.** Cookie keying is tracked properly in [#6]. ([#2])

### Deprecated

- `ONLY_BAN`, replaced by `BOUNCING_ON_TYPE` and to be removed in a future release.
  It is honoured only when `BOUNCING_ON_TYPE` is unset (`true` → `ban`, `false` →
  `all`) and warns at every start. Note `ONLY_BAN=false` is no longer equivalent: it
  used to force every decision type into the ban map, where captcha decisions now
  render to their own and `FALLBACK_REMEDIATION` decides what happens when no
  challenge is configured. `ONLY_BAN=true` — the default, and what the packages ship
  — behaves exactly as before. ([#2])

### Security

- The Apache challenge rules exempt only the proxied `/crowdsec-verify` path from
  enforcement, not the whole `/crowdsec-*` namespace. The broader `!^/crowdsec-`
  guard let a banned or challenged client reach the vhost by prefixing any path with
  `/crowdsec-` (e.g. `/crowdsec-x`): it matched none of the block, challenge or
  refuse rules and was not proxied, so it fell through to the customer application.
  The guard now matches the `ProxyPass` scope exactly. ([#2])
- The challenge fails closed everywhere: a token that is missing, malformed, wrong,
  expired or already spent leaves the client challenged, and a pass that cannot be
  written to disk is reported as a failure rather than a redirect. A fault in the
  check never becomes a free pass. ([#2])
- The widget script is loaded with a Subresource Integrity digest
  (`CAPTCHA_WIDGET_SRI`, defaulted to the pinned build's), so a compromised CDN edge
  cannot substitute script that would run on the customer's own origin. Repointing
  `CAPTCHA_WIDGET_JS` without supplying a digest drops the attribute and warns at
  startup; a malformed digest is refused outright, because a blocked script is a
  challenge nobody can solve. ([#2])
- The client address comes from the last `X-Forwarded-For` entry — the one
  `mod_proxy` appends — and nothing else. The custom `X-CrowdSec-Real-IP` header was
  removed: it needed a `RequestHeader` line separate from the `ProxyPass` that makes
  the rest work, and a deployment that missed that line trusted a header any client
  could send, letting anyone record a pass against an address they do not control.
  ([#2])
- A `CAPTCHA_LISTEN` bind wider than loopback is warned about at startup. The
  listener reads the client's address from `X-Forwarded-For` and trusts that only
  `mod_proxy` reaches it to set that header, so an address anything else can connect
  to lets a caller name their own IP and mint a pass for it. It is a warning rather
  than a refusal because a non-loopback bind is legitimate when Apache runs on
  another host, where the private network between them is the trust boundary. ([#2])
- Passes are discarded when the daemon restarts. They live in memory, so a pass
  file inherited from a previous run would name clients with no expiry attached —
  nothing would ever prune them and Apache would honour them permanently. ([#2])
- The return path a client is sent back to is reduced to a same-site path, so the
  challenge cannot be used as an open redirect off a domain browsers already trust.
  Absolute URLs, protocol-relative `//host`, `/\host` and any C0 control byte or DEL
  fall back to the site root — the control range covers the tab, vertical tab and
  form feed a browser strips out of a URL before parsing (turning `/<tab>/host` back
  into an off-site `//host`) as well as CR/LF header smuggling. ([#2])

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
