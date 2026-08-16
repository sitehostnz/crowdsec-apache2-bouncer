# crowdsec-apache2-bouncer

A small **stream-mode** CrowdSec bouncer for cPanel / Plesk Apache2 origins. It
pulls the active ban list from the LAPI and renders it to an Apache **RewriteMap**
text file; a rewrite rule then 403s any request from a listed IP. CIDR/range
decisions are **expanded to individual IPs** (a txt RewriteMap is exact-match only).

It's a single static Go binary (stdlib only, Go 1.26) — no runtime deps — so it
runs on any cPanel/Plesk box.

## How it works

- On start: `GET /v1/decisions/stream?startup=true` → full snapshot.
- Then every `UPDATE_FREQUENCY`s: `startup=false` → deltas (`new` + `deleted`).
- Maintains a **refcounted** IP set (so an IP shared by two decisions only drops
  when the *last* one expires) and writes `OUTPUT_FILE` **atomically** (temp +
  rename) on every change. The file is `<ip> 1` per line.
- With `MAP_TYPE=dbm` (recommended) it then builds a **DBM hash map** via
  `httxt2dbm` and swaps it in — Apache `dbm:` lookups are **O(1)**, vs a `txt:`
  map which is an **O(N) linear scan per cold lookup** (and your frequent updates
  bust mod_rewrite's per-mtime cache, so cold scans recur). Use `dbm` for any
  non-trivial / fast-changing list.
- A periodic `RESYNC_INTERVAL` full re-sync guards against stream cursor drift.
- On LAPI errors it keeps the current file (never wipes your blocklist).

## Install

Prebuilt packages and a static binary are attached to every
[release](https://github.com/sitehostnz/crowdsec-apache2-bouncer/releases): a
`.deb` (Debian/Ubuntu, e.g. Plesk), an `.rpm` (RHEL/Alma, e.g. cPanel), and the
raw `amd64` binary.

### From a package (recommended)

```bash
# Debian/Ubuntu - apache2-utils provides httxt2dbm (needed for MAP_TYPE=dbm):
apt-get install -y apache2-utils
dpkg -i crowdsec-apache2-bouncer_*_amd64.deb

# RHEL/Alma - httpd-tools provides httxt2dbm. On cPanel use ea-apache24-tools
# instead: EasyApache 4 ships the Apache utilities and excludes httpd* from the
# base repos, so httpd-tools is unavailable there.
yum install -y httpd-tools        # cPanel: yum install -y ea-apache24-tools
rpm -i crowdsec-apache2-bouncer-*.x86_64.rpm
```

The package installs the binary to `/usr/local/bin`, the `systemd` unit, and a
`0600` config at `/etc/crowdsec/bouncers/crowdsec-apache2-bouncer.conf`. It does
**not** start the service (the shipped config carries a placeholder key). Add a
key, point it at your LAPI, then enable it:

```bash
# a bouncer key (run on the CrowdSec/LAPI host):
cscli bouncers add apache-$(hostname -s)        # prints the API key

$EDITOR /etc/crowdsec/bouncers/crowdsec-apache2-bouncer.conf   # set CROWDSEC_LAPI_URL + CROWDSEC_API_KEY
systemctl enable --now crowdsec-apache2-bouncer
journalctl -u crowdsec-apache2-bouncer -f        # "startup ok: N decisions -> M IPs"
```

### Build from source

Needs Go 1.26+.

```bash
# CGO_ENABLED=0 is REQUIRED for a truly static build. A default `go build` links
# the net package against the BUILD host's glibc, and the binary then fails on
# older cPanel/Plesk boxes with:  /lib64/libc.so.6: version `GLIBC_2.32' not found
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o crowdsec-apache2-bouncer .
file crowdsec-apache2-bouncer   # must say "statically linked"
install -m 0755 crowdsec-apache2-bouncer /usr/local/bin/crowdsec-apache2-bouncer

# unit + config, as the package would lay them down:
install -D -m 0600 packaging/crowdsec-apache2-bouncer.conf /etc/crowdsec/bouncers/crowdsec-apache2-bouncer.conf
install -m 0644    packaging/crowdsec-apache2-bouncer.service /etc/systemd/system/
# Your allowlist/denylist live here (CUSTOM_LIST_DIR; /etc/httpd/crowdsec on
# RHEL-family Plesk - cPanel uses /etc/apache2 even on RHEL).
# The package makes this directory; a source install has to, because the unit's
# ProtectSystem=full leaves /etc read-only to the service.
install -d -m 0755 /etc/apache2/crowdsec
cscli bouncers add apache-$(hostname -s)        # the API key (run on the LAPI host)
$EDITOR /etc/crowdsec/bouncers/crowdsec-apache2-bouncer.conf   # set CROWDSEC_LAPI_URL + CROWDSEC_API_KEY
systemctl daemon-reload && systemctl enable --now crowdsec-apache2-bouncer
journalctl -u crowdsec-apache2-bouncer -f        # "startup ok: N decisions -> M IPs"
```

## Apache integration

The principle on any panel: `mod_rewrite` rules in the **main/server** context do
**not** automatically apply inside customer `<VirtualHost>`s — vhosts have their own
rewrite context and don't inherit the engine state or the rules. So the config always
has two halves: the **map + rules once** in server context, and **two inheritance
directives in every vhost** (`RewriteEngine On` + `RewriteOptions InheritBefore`).

### cPanel — validated walkthrough

Two files, then a rebuild. Never hand-edit `httpd.conf` (cPanel regenerates it);
both locations below are cPanel-preserved across EasyApache rebuilds.

**1. Map + rules (server context)** — contents of `apache/blocklist.conf` into:

```
/etc/apache2/conf.d/includes/pre_virtualhost_global.conf
```
(equivalently WHM → Apache Configuration → **Include Editor → Pre VirtualHost
Include → All Versions**)

**2. Inheritance into every vhost** — cPanel's `userdata` mechanism has a documented
["all domains on the server, both SSL and non-SSL" level](https://docs.cpanel.net/ea4/apache/modify-apache-virtual-hosts-with-include-files/):

```
# /etc/apache2/conf.d/userdata/includename.conf
RewriteEngine On
RewriteOptions InheritBefore
```

Use **`InheritBefore`**, not `Inherit`: both pull the server-context rules into the
vhost, but `Inherit` appends them *after* the vhost's own rules, so any customer
rewrite ending with `[L]` (a cPanel-created redirect, say) pre-empts the block.
`InheritBefore` runs the blocklist first, always. (Deeper userdata paths scope the
same trick per-user or per-domain: `userdata/{std,ssl}/2_4/<user>[/<domain>]/*.conf`.)

**3. Rebuild + restart** — userdata includes are only emitted into the vhosts when
the config is regenerated:

```bash
/usr/local/cpanel/scripts/rebuildhttpdconf
/usr/local/cpanel/scripts/restartsrv_httpd
```

**4. Verify it landed** — the include must appear once per vhost:

```bash
grep -c '<VirtualHost' /etc/apache2/conf/httpd.conf
grep -c 'userdata/includename.conf' /etc/apache2/conf/httpd.conf   # counts should match
```

then ban a test IP and curl **a real customer domain, not just the hostname** —
the hostname only proves the server-context half.

### Plesk

`/etc/apache2/conf.d/zzz_crowdsec.conf` (Debian/Ubuntu) or
`/etc/httpd/conf.d/zzz_crowdsec.conf` (RHEL/Alma — also set
`CUSTOM_LIST_DIR=/etc/httpd/crowdsec`, and update `BLOCKLIST_DIR` and the unit's
`ReadWritePaths` if you relocate). Inheritance per vhost via the domain
*Additional Apache directives* or a `vhost.conf` template. Then
`plesk sbin httpdmng --reconfigure-all`.

### Custom blocked page, status code, and logging

**Blocked page** — `ErrorDocument` takes a **URL-path, not a filesystem path**, and
the banned IP must be allowed to fetch the page itself (or Apache serves the ugly
double-403 fallback). Working form, in the same global include:

```apache
RewriteCond %{REQUEST_URI} !^/crowdsec-blocked\.html$
RewriteCond ${crowdsec:%{REMOTE_ADDR}|0} =1
RewriteRule ^ - [F]

Alias /crowdsec-blocked.html /var/lib/crowdsec-apache2-bouncer/crowdsec-blocked.html
<Directory /var/lib/crowdsec-apache2-bouncer>
    Require all granted
</Directory>
ErrorDocument 403 /crowdsec-blocked.html
```

**429 instead of 403** — `[F]` is shorthand for 403; any status works via `R=`
(non-3xx codes return directly, no redirect): `RewriteRule ^ - [R=429,L]` plus
`ErrorDocument 429 …`. 429 matches the official mod_crowdsec bouncer's default and
makes blocks trivially distinguishable from application 403s in the existing logs.
Optionally add `Header always set Retry-After "600" "expr=%{REQUEST_STATUS} == 429"`
(this one needs `mod_headers`; nothing else here does).

**Dedicated block log** — tag matches with an env var and log them conditionally:

```apache
RewriteRule ^ - [F,E=CROWDSEC_BLOCK:1]
# format can live in the global include:
LogFormat "%v %h %t \"%r\" %>s \"%{User-Agent}i\"" crowdsec_block
```

⚠️ On cPanel the `CustomLog … env=CROWDSEC_BLOCK` line must live **in vhost
context** (add it to the same `userdata/includename.conf`) — a vhost that defines
any `CustomLog` (every cPanel domlog does) ignores all global ones. All vhosts
appending to one file is fine. If the page is served via `ErrorDocument`, the
robust condition is
`"expr=env('CROWDSEC_BLOCK') == '1' || env('REDIRECT_CROWDSEC_BLOCK') == '1'"`.
Give the new file a logrotate stanza (`copytruncate`).

### Allowlist and custom blocklist

The bouncer keeps two more lists for you beside the CrowdSec one: an **allowlist**
that bypasses a block, and your **own blocklist** for manual bans CrowdSec doesn't
know about. It creates both empty at `/etc/apache2/crowdsec/allowlist.txt` and
`denylist.txt` (`CUSTOM_LIST_DIR`, which follows Apache's own config directory —
`/etc/apache2` on Debian/Ubuntu *and* on cPanel, `/etc/httpd` on RHEL-family Plesk;
the package picks whichever is present at install time), and with
`MAP_TYPE=dbm` it rebuilds the matching `.dbm` within one poll of you editing either,
so there's no `httxt2dbm` step to remember. What goes *in* them is entirely yours —
the daemon only ever creates and converts them, never writes their contents.

Check them in the same include. `RewriteCond`s are AND-ed, so the block fires only
when the client is *not* allow-listed — the allowlist always wins:

```apache
RewriteMap crowdsec    dbm:/var/lib/crowdsec-apache2-bouncer/blocklist.dbm
RewriteMap local_allow dbm:/etc/apache2/crowdsec/allowlist.dbm
RewriteMap local_deny  dbm:/etc/apache2/crowdsec/denylist.dbm

# CrowdSec's list, unless allow-listed
RewriteCond ${local_allow:%{REMOTE_ADDR}|0} !=1
RewriteCond ${crowdsec:%{REMOTE_ADDR}|0}    =1
RewriteRule ^ - [F]

# your own manual bans, unless allow-listed
RewriteCond ${local_allow:%{REMOTE_ADDR}|0} !=1
RewriteCond ${local_deny:%{REMOTE_ADDR}|0}  =1
RewriteRule ^ - [F]
```

Both files are `<ip> 1` per line — the same format the bouncer writes, exact-match
(canonicalise IPv6 to RFC 5952):

```
# /etc/apache2/crowdsec/allowlist.txt
203.0.113.5 1
198.51.100.10 1
```

- **`txt:` works just as well** — point the maps straight at the `.txt` and an edit is
  live on the next request, with no rebuild in between. These lists are usually small
  enough that the `txt` scan below costs nothing; `dbm:` only starts to earn its keep
  once one runs to thousands of entries.
- **A couple of IPs, no map** — inline negatives before the block rule instead:
  `RewriteCond %{REMOTE_ADDR} !=203.0.113.5`.
- **A CIDR range** — a RewriteMap is exact-match only, so use an expression:
  `RewriteCond expr "! (%{REMOTE_ADDR} -ipmatch '203.0.113.0/24')"` before the block's
  `RewriteCond`. `-ipmatch` handles IPv4/IPv6 and CIDR.

Gotchas: add the allow guard to **every** block rule (the blocked-page variant has its
own `[F]`); adding a `RewriteMap` directive needs an Apache reload, but editing a list
afterwards doesn't (mtime re-read, same as the blocklist — with `dbm:` that happens
once the daemon has rebuilt it, so within one `UPDATE_FREQUENCY`); this is
**origin-local**, so to stop an IP being banned across *all* bouncers, allowlist it in
CrowdSec itself instead; and if you point `CUSTOM_LIST_DIR` at some other directory
under `/etc`, add it to `ReadWritePaths=` in the unit — `ProtectSystem=full` makes
`/etc` read-only to the service, so the daemon can't create the files there otherwise.

### ⚠️ Real client IP

`%{REMOTE_ADDR}` must be the **real client**. If your origin sits behind a CDN or
reverse proxy, mind where that IP comes from:

- **Direct-to-origin** traffic (attackers hitting the origin IP directly, bypassing
  the proxy): `REMOTE_ADDR` *is* the real client → blocking works. Catching what
  slips past the edge is the main reason to bounce at the origin at all.
- **Via-CDN** traffic: `REMOTE_ADDR` is the CDN edge IP, not the client — the real
  client is in `X-Forwarded-For`. Matching on the edge IP would block *all* traffic
  arriving through that CDN, so configure **`mod_remoteip`** to trust your CDN ranges
  (cPanel/Plesk both support it) — it rewrites `REMOTE_ADDR` from XFF so the map
  matches the real client.

Either way, never `mod_remoteip`-trust an upstream you don't control — otherwise a
client could spoof `X-Forwarded-For` to forge or dodge a block.

### ⚠️ RewriteMap reload & performance

Both `dbm:` and `txt:` maps are re-read when the file's **mtime changes** (Apache 2.4
docs) — the atomic swap triggers it, so **no Apache reload needed** (verify once:
bump the list, hit a banned IP, confirm the 403 without a reload).

Two findings from the end-to-end test worth knowing at deploy time:

- **Start the bouncer before (re)starting Apache.** Apache validates the RewriteMap
  file at config-parse time and refuses to start if it's missing — the daemon must
  have written the first map (even an empty one) before `httpd` comes up. Order the
  units accordingly (`Before=apache2.service` / just start the bouncer first).
- **Pin the DBM format if in doubt.** Some httpd builds (e.g. Alpine) have no
  default DBM type and fail with `RewriteMap: dbm type default is invalid`. The fix
  is to pin SDBM on both sides: `RewriteMap crowdsec dbm=sdbm:/path/blocklist.dbm`
  and run `httxt2dbm -f SDBM` (set `HTTXT2DBM` to a wrapper, or adjust the unit).
  Debian/cPanel and RHEL/Plesk builds agree on their default, so plain `dbm:` works
  there — pinning is still the safer habit.

Crucially, the lookup cost differs:
- **`dbm:` → O(1)** hash lookup, even when the per-mtime cache is cold. Scales to
  large, frequently-updated lists. **Use this** — the shipped config sets
  `MAP_TYPE=dbm`, though the built-in default with no config file is `txt`, so set
  it explicitly if you build from source or run with bare environment variables.
- **`txt:` → O(N)** linear file scan on every *cold* lookup (new IP, or right after
  the file changed). Since the daemon rewrites the file often, mod_rewrite's cache
  (keyed by mtime) is repeatedly invalidated → recurring O(N) scans. Under **prefork**
  MPM each worker process caches independently, multiplying cold scans. Only use
  `txt:` for small static lists.

## Limits

- **IPv6 single IPs** are supported — addresses are canonicalised (RFC 5952) so the
  key matches Apache's `%{REMOTE_ADDR}`. Verify once with a real IPv6 client, since a
  RewriteMap is exact-string match (both Python and Apache/`inet_ntop` use RFC 5952,
  so they should agree).
- **Ranges** (IPv4 *and* IPv6) are expanded to individual IPs when they fit under
  `EXPAND_MAX_HOSTS`, and **skipped** (logged) otherwise — the cap is on the address
  count, so it applies to both families the same way (`/16` ≈ `/112` at the default
  65536). Most IPv6 ranges (e.g. a `/64`) are far larger than any sane cap and are
  always skipped. For large-range bans use the `cs-firewall-bouncer` (ipset
  `hash:net`) instead/alongside; ipset does CIDR natively.
- **Country/AS/username** scoped decisions are skipped (can't map to IPs without geo).
- Only `type=ban` by default (`BOUNCING_ON_TYPE`) — see below.
- **`throttle`** has no `RewriteMap` expression at all and is never enforced.

## Remediations

Three settings decide what happens to a decision. They carry the **same names,
values and order as the nginx bouncer**, so a fleet running both needs one mental
model:

| | Values | Default | |
|---|---|---|---|
| `BOUNCING_ON_TYPE` | `ban` / `captcha` / `all` | `ban` | Which decisions are acted on at all |
| `OVERRIDE_REMEDIATION` | `ban` / `captcha` / empty | empty | Replaces whatever the hub asked for |
| `FALLBACK_REMEDIATION` | `ban` / `captcha` / empty | `ban` | Catches what cannot be expressed |

They apply in that order, and **override runs before fallback** — which is the
detail that matters. `OVERRIDE_REMEDIATION=captcha` on a box where no challenge is
configured degrades to `FALLBACK_REMEDIATION` and *blocks*, rather than quietly
enforcing nothing.

The fallback catches two cases: a remediation Apache can't express (`throttle` has
no `RewriteMap` form at all), and a `captcha` when `CAPTCHA_LISTEN` is unset. Set
`FALLBACK_REMEDIATION=` (empty) to drop those decisions instead.

Each reachable remediation renders to its **own** map, because the type decides what
Apache does with a hit:

| Remediation | Map |
|---|---|
| `ban` | `blocklist.txt` / `.dbm` — i.e. `OUTPUT_FILE` / `DBM_FILE` |
| `captcha` | `captcha.txt` / `.dbm`, in the same directory |

The map set is **derived** from the three settings, so a map exists exactly when
something can land in it — `OVERRIDE_REMEDIATION=captcha` builds no ban map at all.
The ban map keeps `OUTPUT_FILE`/`DBM_FILE`, so an existing Apache config still points
at the right file. A single address can hold a ban *and* a captcha at once, and a
decision the hub escalates from captcha to ban moves between maps rather than sitting
in both.

The startup line states the resulting policy outright:

```
remediation policy: bouncing_on=all override="" fallback="ban" -> ban:ban captcha:captcha throttle:ban
```

To emit captcha decisions at all you also need a
[captcha profile](https://docs.crowdsec.net/docs/local_api/profiles/captcha_profile/)
on the LAPI.

> **`ONLY_BAN` is deprecated** and will be removed. It's read only when
> `BOUNCING_ON_TYPE` is unset (`true` → `ban`, `false` → `all`) and warns at every
> start. Note `ONLY_BAN=false` is no longer equivalent: it used to force every
> decision type into the ban map, where captcha decisions now render to their own
> and `FALLBACK_REMEDIATION` decides what happens without a challenge.

### The challenge listener

Apache can't run a captcha on its own: `mod_rewrite` cannot derive a key, and has
nowhere to keep the challenge it issued. (`RewriteMap prg:` is not a way round it —
Apache runs one copy for the whole server behind the `rewrite-map` mutex, so any work
there blocks every worker.) So the daemon serves the challenge itself, on loopback,
and Apache proxies to it.

```
CAPTCHA_LISTEN=127.0.0.1:8125
CAPTCHA_PATH=/crowdsec-verify
```

A challenged client is redirected to the listener, solves the widget, and the daemon
verifies it in-process before writing them into a **pass map** Apache checks ahead of
the captcha map. The pass map is a `txt:` map on purpose:
Apache re-reads it the moment its mtime changes, so a solve takes effect on the
very next request instead of waiting for a DBM rebuild. It's the one map where the
latency is user-visible.

> ⚠️ **Bind it to loopback.** The last `X-Forwarded-For` entry — the one `mod_proxy`
> appends — is what a pass is recorded against, so a directly reachable listener
> would let anyone name their own address and exempt it.

**The widget script.** `CAPTCHA_WIDGET_JS` is a pinned jsDelivr URL and
`CAPTCHA_WIDGET_SRI` is the digest the browser checks it against — both defaulted, so
leaving them alone gets you a verified widget for free. The two answer different
threats: pinning the version stops an unreviewed release arriving on every customer
page with no deploy here, and the digest stops a compromised CDN edge substituting
script that would run on the customer's own origin with their cookies.

Point `CAPTCHA_WIDGET_JS` somewhere else and `CAPTCHA_WIDGET_SRI` **must** change
with it — a digest that doesn't match blocks the script outright, and a blocked
widget is a page that renders 200 and can never be solved:

```bash
curl -sL <url> | openssl dgst -sha384 -binary | openssl base64 -A
```

If you don't have the new digest, remove the setting entirely — *only* an empty
value drops the attribute and warns at startup. A stale value is used verbatim
against whatever URL you set.

The daemon refuses **one** case outright: a digest whose hash is the wrong length
for the algorithm named in front of it (running `openssl dgst -sha256` while
leaving a `sha384-` prefix is the easy mistake). The built-in digest paired with a
URL that isn't the built-in one only **warns** — a digest names bytes, not a URL,
so that pairing is exactly right if you're mirroring the pinned build onto your own
origin, and refusing it would take ban enforcement down along with the captcha.

**Replacing the page.** `CAPTCHA_TEMPLATE` takes a Go `html/template` and is given:

| Field | What it is |
| --- | --- |
| `{{.Widget}}` | the `<altcha-widget>` element, built here and already escaped |
| `{{.WidgetJS}}` | the widget script URL |
| `{{.WidgetSRI}}` | its digest, empty when none is configured — guard the attribute with `{{if}}` |
| `{{.Action}}` | where the solved form posts (`CAPTCHA_PATH`) |
| `{{.Return}}` | the path to send the visitor back to, already reduced to a same-site path |
| `{{.SolveEvent}}` | the event name the widget fires on success |
| `{{.Error}}` | a message to show on a failed attempt, empty on the first render |

All but `{{.Error}}` are **required** and checked at startup, because `html/template`
silently ignores fields a template doesn't reference — a page written against an
older field set parses cleanly, renders 200 and can't be solved. `{{.SolveEvent}}` is
in that list because the built-in form has no submit button: the listener it names is
what submits. The built-in page in `challenge.go` is the reference.

The daemon issues and checks its own proof-of-work — there is no captcha service, no
Valkey, no proxy to one, and no shared secret on the wire. It publishes half of a derived key and keeps the other half; the browser searches counters until its
derived key starts with the published prefix, then returns the whole thing. The half
that was never published is the proof, so verification is a string comparison — and
because redeeming removes the challenge, a solution cannot be replayed.

| | Default | |
|---|---|---|
| `ALTCHA_ALGORITHM` | `PBKDF2/SHA-256` | also `SHA-256/384/512`, `PBKDF2/SHA-384`, `PBKDF2/SHA-512`. An unknown name is refused at startup |
| `ALTCHA_COST` | `5000` | iterations per attempt |
| `ALTCHA_COMPLEXITY` | `5000` | attempts the visitor makes; they expect to try half |

The two multiply, and the daemon refuses a combination a browser cannot finish
inside the widget's 90-second timeout — it prints the estimate at startup. Prefer
raising complexity: it costs the visitor alone, where cost is also paid once per
challenge the daemon mints. Together the defaults are ~12.5M iterations, a second or
two in a browser — half what the nginx bouncer asks for, which uses the same cost
with `ALTCHA_COMPLEXITY=10000`.

> ⚠️ **Requires HTTPS.** The widget uses `crypto.subtle`, which browsers
> expose only in a secure context, so on a plain-HTTP vhost it errors and no solve
> can ever arrive — the visitor is challenged forever. There is no fallback provider, so if any vhost is HTTP-only, either serve it over TLS or keep those
> decisions on `ban` with `FALLBACK_REMEDIATION=ban`.

**What it costs the daemon.** Benchmarked with the challenge-listener suite in
`profile_test.go` (`go test -run '^$' -bench . -benchmem`), on a Ryzen 5 7535U at
the shipped defaults — treat the numbers as shape rather than gospel:

| Operation | When it happens | Cost |
| --- | --- | --- |
| Mint a challenge (`PBKDF2/SHA-256`, cost 5000) | once per challenged address per 20 min | ~0.7 ms, ~1 KB allocated |
| Re-issue the outstanding challenge | every re-fetch by the same address | ~1 µs |
| Render the challenge page | every challenged `GET` | ~7 µs |
| Verify a solve | per solve `POST` | ~1.4 µs |
| Record a pass | per successful solve | ~27 µs holding 1 pass, ~250 µs holding 10,000 — the whole map is rewritten |
| Challenge store at its 200k cap | worst-case flood | ~195 B per challenge, ~37 MiB total |

The shape to remember: **minting is the only expensive step, and deliberately so** —
it is one pass of the same KDF the visitor's browser must run thousands of times,
so it *is* the proof-of-work dial rather than overhead. Everything around it costs
microseconds. Three things keep a flood from weaponising it: a challenged address
gets the same challenge back until it solves or expires, so reloads never re-mint;
concurrent mints are capped at half the CPUs, so the poll loop maintaining the ban
maps always has a core; and the store refuses new challenges at 200k outstanding, so
the most an address-hopping flood can pin is ~37 MiB — the refusal is logged, and
`altcha_challenges_minted_total` on `/metrics` is the rate an abuser would be
driving up.

**What a pass is keyed on.** The solver's address, matching CrowdSec's own nginx
bouncer, so the Apache side is a plain map lookup identical to the ban list. One
solver therefore lets through every browser at that address — everyone behind the
same NAT included.

Cookie keying would be the more correct answer under NAT, and was removed: the
daemon minted the token but nothing else was finished, so setting it produced a
daemon that recorded cookies while Apache matched addresses, re-challenging every
visitor forever. Better absent than half-present.

**Failure behaviour is fail-closed throughout.** A token that is missing, malformed,
wrong, expired or already spent leaves the client challenged — a fault in the check
must never become a free pass for the traffic the hub flagged. A
pass that can't be written to disk is likewise reported as a failure rather than a
redirect, so the client isn't bounced into a loop. And passes are discarded when
the daemon restarts: they live in memory, so a file inherited from a previous run
would name clients with no expiry and stay valid forever.

### Apache configuration

The package ships these rules in `apache/blocklist.conf`, which is the copy to
edit — it carries the full commentary and is what the walkthrough above installs.
Reproduced here so the shape is visible without a checkout:

```apache
RewriteMap crowdsec dbm:/var/lib/crowdsec-apache2-bouncer/blocklist.dbm
RewriteMap captcha  dbm:/var/lib/crowdsec-apache2-bouncer/captcha.dbm
RewriteMap solved   txt:/var/lib/crowdsec-apache2-bouncer/captcha_passed.txt

# A ban outranks a captcha, so the block rule stays FIRST.
RewriteCond %{ENV:REDIRECT_STATUS} ^$
RewriteCond %{REQUEST_URI} !^/crowdsec-verify
RewriteCond ${crowdsec:%{REMOTE_ADDR}|0} =1
RewriteRule ^ - [F]

# Challenge HTML navigations, while the daemon is up to answer them.
RewriteCond %{ENV:REDIRECT_STATUS} ^$
RewriteCond %{REQUEST_URI} !^/crowdsec-verify
RewriteCond ${solved:%{REMOTE_ADDR}|0}  !=1
RewriteCond ${captcha:%{REMOTE_ADDR}|0}  =1
RewriteCond %{HTTP_ACCEPT} text/html
RewriteCond /run/crowdsec-apache2-bouncer/challenge.up -f
RewriteRule ^ /crowdsec-verify?r=%{REQUEST_URI} [R=302,L]

# Anything else from a challenged client - and everything, once the daemon is
# down - is refused rather than redirected.
RewriteCond %{ENV:REDIRECT_STATUS} ^$
RewriteCond %{REQUEST_URI} !^/crowdsec-verify
RewriteCond ${solved:%{REMOTE_ADDR}|0}  !=1
RewriteCond ${captcha:%{REMOTE_ADDR}|0}  =1
RewriteRule ^ - [F]

# No trailing slash on either side. With one on the target, a subpath such as
# /crowdsec-verify/altcha-challenge maps to //altcha-challenge, which lands
# outside the proxy prefix and is then refused by the rules above - the widget
# never receives a challenge and the page hangs with nothing logged.
ProxyPass        /crowdsec-verify http://127.0.0.1:8125
ProxyPassReverse /crowdsec-verify http://127.0.0.1:8125
```

Those two proxy lines are the whole of it. The daemon takes the client address off
the `X-Forwarded-For` that `mod_proxy` appends itself, reading only the **last**
entry — the one Apache wrote. Anything the client put in that header sits in front of
it and is ignored. There is no header to set.

> ⚠️ **`ProxyAddHeaders` must stay `On`** (its default), and nothing may strip
> `X-Forwarded-For` on this location. With either changed, Apache appends nothing but
> still forwards what the client sent, so the daemon reads a header the *client*
> wrote — and anyone can record a pass against an address they don't control. The
> daemon can't detect it: through the proxy the peer is loopback either way.

Three things there are not obvious, and each is a failure that has been hit rather
than a precaution:

1. **`%{ENV:REDIRECT_STATUS} ^$` — act only on the original request.**
   `ErrorDocument` performs an internal redirect, which re-runs these rules against
   the error page's own URI. Without the guard, a challenged client hitting any
   error page is challenged again, which errors again: an infinite redirect loop,
   not a block.
2. **The readiness file** — only send someone to the challenge while the daemon is
   listening. Otherwise the redirect lands on a proxy with nothing behind it, Apache
   answers 503, `ErrorDocument` turns that into an internal redirect, and (1)
   becomes a loop. When it is down we refuse instead, which is what
   `FALLBACK_REMEDIATION=ban` means at the Apache layer.
3. **Nothing uses `[L]` to let a request *through*.** With `InheritBefore` these
   rules are prepended to the vhost's own, so an `[L]` here would also stop the
   customer's rewrites — breaking WordPress permalinks and the like, for exactly the
   visitors who have just solved a challenge. Each rule that *stops* a request
   therefore carries its full set of guards, and `!^/crowdsec-verify` is what keeps
   the challenge itself from being challenged. It exempts exactly what `ProxyPass`
   forwards to the listener and no more — a broader `!^/crowdsec-` would let a
   banned client reach the vhost on any other `/crowdsec-*` path.

Add the allowlist guard (`RewriteCond ${local_allow:%{REMOTE_ADDR}|0} !=1`) to the
block *and* challenge rules if you use the local lists — the same rule as
everywhere else here: every rule that stops a request needs the guard.

These directives are subject to the same per-vhost inheritance as the rest, so they
need `RewriteEngine On` + `RewriteOptions InheritBefore` in each vhost. `mod_proxy`
must be loaded.

## Verify / operate

```bash
wc -l /var/lib/crowdsec-apache2-bouncer/blocklist.txt          # grows after startup
systemctl status crowdsec-apache2-bouncer
# end-to-end: ban yourself, confirm the block on a CUSTOMER domain, then remove
cscli decisions add --ip <your-test-ip> -d 5m && sleep "${UPDATE_FREQUENCY:-60}"
grep <your-test-ip> /var/lib/crowdsec-apache2-bouncer/blocklist.txt
curl -sk -o /dev/null -w '%{http_code}\n' https://<customer-domain>/   # from that IP: 403/429
cscli decisions delete --ip <your-test-ip>
```

## Security

- API key lives only in the `0600` EnvironmentFile, never in the script.
- The blocklist file is `0644` (Apache must read it); it contains only IPs.
- Runs as root by default. To run as a dedicated user, give it write on
  `BLOCKLIST_DIR` (default `/var/lib/crowdsec-apache2-bouncer`) and adjust the unit's
  `User=`/`ReadWritePaths=`.

## License

[Apache License 2.0](LICENSE).
