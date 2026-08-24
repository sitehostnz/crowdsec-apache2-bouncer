package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// maxDurationSecs caps the seconds-valued env vars so a wildly large value can't
// overflow time.Duration (int64 ns). 10 years is far beyond any real setting.
const maxDurationSecs = 315360000

// Bounds for RESYNC_INTERVAL. A full snapshot is the expensive LAPI query, and the
// stream deltas already keep the list current between re-syncs - so hourly is as
// often as it is worth paying for, and a day is as long as cursor drift should go
// unnoticed. 0 opts out of the safety net entirely.
const (
	minResyncSecs = 3600  // 1 hour
	maxResyncSecs = 86400 // 24 hours
)

// config holds the runtime configuration, populated from the environment and the
// -dir flag by loadConfig.
type config struct {
	lapiURL              string
	apiKey               string
	outputFile           string
	updateFrequency      time.Duration
	expandMaxHosts       uint64
	resyncInterval       time.Duration
	requestTimeout       time.Duration
	streamRequestTimeout time.Duration
	mapType              string // "txt" | "dbm"
	httxt2dbm            string
	dbmFile              string
	insecure             bool
	caBundle             string
	// customListDir holds the operator-maintained allowlist/denylist the daemon
	// creates and keeps DBMs for; empty switches that off.
	customListDir string
	// The remediation policy, named to match the nginx bouncer. See
	// resolveRemediation for how the three combine.
	bouncingOnType      string // "ban" | "captcha" | "all" - which decisions are acted on
	overrideRemediation string // replaces the hub's choice; empty honours it
	fallbackRemediation string // catches what cannot be expressed; empty drops it
	// remediations is the derived set of maps to render, from mapsNeeded.
	remediations []string

	// The challenge listener. captchaListen empty switches the whole thing off,
	// which is the default: a bouncer that only bans needs none of it.
	captchaListen     string
	captchaPath       string // the path Apache proxies to the listener
	captchaWidgetJS   string // the widget script
	captchaWidgetSRI  string // its SRI digest; empty renders no integrity attribute
	captchaTokenField string // the form field the solved token arrives in
	captchaTemplate   string // optional challenge page override
	captchaPassFile   string // the map of solved challenges
	captchaReadyFile  string // exists only while the challenge is actually listening
	captchaPassTTL    time.Duration
	altchaComplexity  int64
	altchaAlgorithm   string
	altchaCost        int

	// Prometheus scrape endpoint. Empty (the default) switches it off. Kept on its
	// own listener: the challenge one is proxied to the public internet.
	metricsListen string
	metricsPath   string
}

// loadCaptcha fills in the challenge listener's settings and checks the ones that
// cannot be defaulted. Everything here is inert until CAPTCHA_LISTEN is set.
func (c *config) loadCaptcha(dir string) error {
	c.captchaListen = envStr("CAPTCHA_LISTEN", "")
	c.captchaPath = envStr("CAPTCHA_PATH", "/crowdsec-verify")
	c.captchaWidgetJS = envStr("CAPTCHA_WIDGET_JS", altchaDefaultWidgetJS)
	c.captchaWidgetSRI = strings.TrimSpace(envStr("CAPTCHA_WIDGET_SRI", ""))
	// The built-in digest belongs to the built-in URL and to nothing else, so it is
	// only assumed while the script is still the one it was computed from. An
	// operator who repoints CAPTCHA_WIDGET_JS without supplying a hash gets no
	// integrity attribute rather than one that cannot match: a mismatch blocks the
	// script outright, and a blocked widget is a challenge nobody can ever solve.
	if c.captchaWidgetSRI == "" && c.captchaWidgetJS == altchaDefaultWidgetJS {
		c.captchaWidgetSRI = altchaDefaultWidgetSRI
	}
	c.captchaTokenField = envStr("CAPTCHA_TOKEN_FIELD", "altcha")
	c.captchaTemplate = envStr("CAPTCHA_TEMPLATE", "")
	c.captchaPassFile = envStr("CAPTCHA_PASS_FILE", filepath.Join(dir, "captcha_passed.txt"))
	// Under /run so it cannot outlive a reboot, and inside the unit's
	// RuntimeDirectory= so systemd removes it even when the daemon is killed
	// outright. Empty switches the signal off.
	c.captchaReadyFile = envOptional("CAPTCHA_READY_FILE", "/run/crowdsec-apache2-bouncer/challenge.up")
	c.captchaPassTTL = time.Duration(clampEnvInt("CAPTCHA_PASS_TTL", 3600, 60, maxDurationSecs)) * time.Second
	// The client scans upward from zero until the derived key matches, so it tries
	// half of this on average - and, because the counter we pick is uniform over the
	// range, close to all of it in the worst case. The budget checks below are sized
	// on the average, so the ceiling is what bounds the unlucky tail: at 1,000,000 a
	// visitor whose counter lands near the top pays roughly twice the estimate and
	// still finishes inside the widget's timeout. It is not a solvability check -
	// that is altchaMaxWebCryptoCalls and altchaMaxIterations, and both stay
	// reachable above this ceiling once ALTCHA_COST is raised.
	c.altchaComplexity = int64(clampEnvInt("ALTCHA_COMPLEXITY", altchaDefaultComplexity, 1_000, 1_000_000))
	// Only names the published widget can solve are accepted; an unknown one falls
	// back to the defaults below, because the widget rejects it in the browser with
	// nothing logged on our side - the client just never completes.
	// Iterations per candidate. The client runs this many for EVERY counter it
	// tries, so the work it owes is roughly (ALTCHA_COMPLEXITY / 2) * ALTCHA_COST -
	// the two multiply, and either one alone can make the check unbearable on a
	// cheap phone. Prefer raising complexity: it costs the client only, whereas cost
	// is also paid once per challenge WE mint, on an endpoint anyone can reach.
	// Verifying is unaffected either way - that is a string comparison now.
	c.altchaCost = clampEnvInt("ALTCHA_COST", altchaDefaultCost, 1, 100_000)
	c.altchaAlgorithm = strings.TrimSpace(envStr("ALTCHA_ALGORITHM", altchaDefaultAlgorithm))

	if c.captchaListen == "" {
		return nil
	}
	// The listener grants a pass to whatever address clientIP reads out of
	// X-Forwarded-For, and trusts that only Apache's mod_proxy ever reaches it to
	// write that header (see clientIP in challenge.go). A bind wider than loopback
	// breaks that assumption: anyone who can open a socket to the listener can send
	// their own X-Forwarded-For and mint a pass for any IP, exempting it from the
	// captcha on every challenged vhost.
	//
	// A WARNING and not a fatal, for the same reason the SRI-mismatch case below is:
	// a non-loopback bind is not always wrong. Apache running on a separate host has
	// to reach the daemon over a routable address, and there the private network
	// between them is the trust boundary. Refusing it would kill a good deployment -
	// and a failed captcha config takes ban enforcement down with it, not just the
	// captcha.
	if !loopbackListen(c.captchaListen) {
		log.Printf("WARNING: CAPTCHA_LISTEN=%s is not bound to loopback. The challenge listener trusts X-Forwarded-For to name the "+
			"client it grants a pass to, so anyone who can reach this address can forge a pass for any IP and skip the captcha on every "+
			"challenged vhost. Bind it to 127.0.0.1 and let Apache's ProxyPass reach it there; widen it only when Apache is on another "+
			"host, and then only across a network you trust to reach nothing else.", c.captchaListen)
	}
	// Settings that only ever meant something to the removed cap provider. Refused
	// rather than ignored: an unknown setting is silently dropped, and a config
	// half-migrated from cap would otherwise start cleanly while doing something
	// other than what it says. This is the trap CAPTCHA_PASS_KEY set when cookie
	// keying went - do not repeat it.
	for _, gone := range []struct{ name, was string }{
		{"CAPTCHA_PROVIDER", "the cap provider was removed; altcha is the only one"},
		{"CAPTCHA_VERIFY_URL", "there is no provider to call"},
		{"CAPTCHA_SECRET", "no secret crosses the wire"},
		{"CAPTCHA_API_ENDPOINT", "the widget talks to this daemon"},
		{"CAPTCHA_VERIFY_TIMEOUT", "verification is local and immediate"},
	} {
		// Non-empty, not merely present. Blanking a line is how a setting is usually
		// disabled in an env file - and it is what an operator does when told to
		// "remove" one - but systemd's EnvironmentFile still sets it. Treating that
		// as present made `CAPTCHA_SECRET=` a fatal error, and the fatal takes ban
		// enforcement down with the captcha it was complaining about.
		if os.Getenv(gone.name) != "" {
			return fmt.Errorf("%s is no longer used: %s. Remove it from the environment file", gone.name, gone.was)
		}
	}
	{
		// A bad ALTCHA dial falls back to the shipped default, loudly, instead of
		// refusing to start. Refusal was the original choice - the browser-side
		// failure is a page that spins until the widget's 90s timeout with nothing
		// logged here, the failure hardest to diagnose from the outside - but dying
		// over a captcha dial takes ban enforcement down with it, which is the one
		// trade this file never makes. The defaults keep the challenge solvable at a
		// cost the operator did not choose, and the WARNING says exactly what moved;
		// serve's startup line then prints the dials actually in force.
		//
		// Lower-cased first, so an operator writing "pbkdf2/sha-256" is spelling it
		// the way a config file usually looks rather than making a mistake.
		c.altchaAlgorithm = canonicalAltchaAlgorithm(c.altchaAlgorithm)
		if _, ok := altchaAlgorithms[c.altchaAlgorithm]; !ok {
			// All three dials, not just the name. ALTCHA_COST means something
			// different per family, so carrying the operator's cost across a family
			// switch silently changes the work: a typo'd plain-SHA name with the
			// cost=1 that family wants lands on PBKDF2, where every candidate costs
			// three WebCrypto calls instead of one - triple the browser work they
			// asked for, and low enough to slip under the budget check below, which
			// would then never fire. Substituting a name is a partial reset, and the
			// comment below says why those are unsafe.
			log.Printf("WARNING: ALTCHA_ALGORITHM=%q is not one the widget can solve (want one of %s); using the defaults %s cost=%d complexity=%d",
				c.altchaAlgorithm, strings.Join(altchaAlgorithmNames(), ", "),
				altchaDefaultAlgorithm, altchaDefaultCost, altchaDefaultComplexity)
			c.altchaAlgorithm = altchaDefaultAlgorithm
			c.altchaCost = altchaDefaultCost
			c.altchaComplexity = altchaDefaultComplexity
		}
		// The two dials are judged together, per family, against the widget's
		// timeout. ALTCHA_COST means something different per family: the plain SHA
		// family spends one awaited WebCrypto call per iteration, where PBKDF2 keeps
		// its iterations inside one call - which is also why the call count alone
		// misses PBKDF2 entirely (ALTCHA_COST=100000 reported 15,000 calls while
		// asking for 500,000,000 iterations, raising every mint WE perform from
		// 730us to 16ms), so the total work is bounded too.
		//
		// A violation resets ALL THREE dials, not just the offender: the defaults
		// are only known-solvable as a set - the default cost and complexity under
		// plain SHA-256 still exceed the call budget - and a partial reset could
		// land on another unsolvable combination.
		calls := altchaWebCryptoCalls(c.altchaAlgorithm, c.altchaCost, c.altchaComplexity)
		iterations := c.altchaComplexity / 2 * int64(c.altchaCost)
		if calls > altchaMaxWebCryptoCalls || iterations > altchaMaxIterations {
			log.Printf("WARNING: ALTCHA_ALGORITHM=%s with ALTCHA_COST=%d and ALTCHA_COMPLEXITY=%d asks the browser for ~%d WebCrypto calls and ~%d KDF iterations per solve, "+
				"more than it can finish inside the widget's 90s timeout (bounds: ~%d calls, ~%d iterations); using the defaults %s cost=%d complexity=%d",
				c.altchaAlgorithm, c.altchaCost, c.altchaComplexity, calls, iterations,
				altchaMaxWebCryptoCalls, altchaMaxIterations,
				altchaDefaultAlgorithm, altchaDefaultCost, altchaDefaultComplexity)
			c.altchaAlgorithm = altchaDefaultAlgorithm
			c.altchaCost = altchaDefaultCost
			c.altchaComplexity = altchaDefaultComplexity
		}
		// The pass-file collision check lives in loadConfig rather than here: it has
		// to compare against every map the daemon renders, and which maps those are
		// is not known until mapsNeeded runs - which needs the captcha settings this
		// function is still reading.
		// A malformed digest is worse than none at all: the browser refuses the
		// script, the element never upgrades, and the page sits on "Verifying your
		// connection" with nothing wrong in the markup and nothing logged here - the
		// same silent hang the MIME fault produced.
		//
		// There is no safe value to substitute - a digest names the bytes of whatever
		// CAPTCHA_WIDGET_JS points at, so inventing or dropping one would silently
		// un-verify the operator's script. But that rules out a DEFAULT, not a
		// degrade: the listener simply does not start, exactly as it already does for
		// an unusable CAPTCHA_TEMPLATE. Captcha decisions then take
		// FALLBACK_REMEDIATION (a block, by default) and the ban map keeps updating,
		// which is the fail-closed end of this trade rather than a dead daemon.
		if c.captchaWidgetSRI != "" && !validSRI(c.captchaWidgetSRI) {
			// Spell out what happens to the DECISIONS, not just to the listener.
			// fallbackRemediation is always set, so this always names a real outcome.
			outcome := fmt.Sprintf("fall back to %q", c.fallbackRemediation)
			log.Printf("WARNING: CAPTCHA_WIDGET_SRI=%q is not a subresource integrity digest. Want a lowercase sha256-, sha384- or sha512- "+
				"followed by that hash's base64, at its full length (%d, %d or %d bytes) - a hash of the wrong size for the name in front of it "+
				"is refused by every browser, which blocks the widget. The challenge listener will NOT start; captcha decisions %s. "+
				"Regenerate it with: curl -sL %s | openssl dgst -sha384 -binary | openssl base64 -A",
				c.captchaWidgetSRI, sriHashSizes["sha256"], sriHashSizes["sha384"], sriHashSizes["sha512"],
				outcome, c.captchaWidgetJS)
			c.captchaListen = ""
			return nil
		}
		// The built-in digest against a different URL is usually the shipped config
		// file's trap - the two settings sit next to each other, both commented, so
		// uncommenting both to change the URL leaves the digest behind.
		//
		// A WARNING and not a fatal, because it is not always wrong: a digest names
		// BYTES, not a URL, so an operator serving a byte-identical mirror of the
		// pinned build from their own origin - which is the strongest answer to the
		// CDN threat this setting exists for - has this exact pairing and is correct.
		// Refusing it would kill the daemon over a good configuration, and a failed
		// config takes ban enforcement down with the captcha, not just the captcha.
		// The browser is the real check here and it reports in the first tab; all
		// this can usefully do is say which of the two cases the operator is in.
		if c.captchaWidgetJS != altchaDefaultWidgetJS && c.captchaWidgetSRI == altchaDefaultWidgetSRI {
			log.Printf("WARNING: CAPTCHA_WIDGET_SRI is still the built-in widget's digest while CAPTCHA_WIDGET_JS points at %s. "+
				"That is correct only if you are serving a byte-identical copy of the pinned build. If you are not, the browser will refuse "+
				"the script and no visitor will be able to solve - replace it with: curl -sL %s | openssl dgst -sha384 -binary | openssl base64 -A",
				c.captchaWidgetJS, c.captchaWidgetJS)
		}
		// Only reachable by repointing CAPTCHA_WIDGET_JS, and worth a line: the page
		// keeps working either way, so an unverified widget is a downgrade that
		// announces itself nowhere.
		if c.captchaWidgetSRI == "" {
			log.Printf("WARNING: CAPTCHA_WIDGET_JS=%s is loaded with no CAPTCHA_WIDGET_SRI, so the browser cannot check it is the script you meant. "+
				"Whatever serves that URL runs with the customer's cookies on every vhost you challenge - set CAPTCHA_WIDGET_SRI to its digest: "+
				"curl -sL %s | openssl dgst -sha384 -binary | openssl base64 -A",
				c.captchaWidgetJS, c.captchaWidgetJS)
		}
	}
	return nil
}

// loopbackListen reports whether addr binds only the loopback interface, which is
// the only safe place for the challenge listener: clientIP trusts the last
// X-Forwarded-For entry, so whoever can reach the listener directly can name any
// address and mint a pass for it.
//
// An empty or unspecified host ("", "0.0.0.0", "::") binds every interface and is
// the dangerous case. A hostname that is not "localhost" and does not parse as an
// IP cannot be classified here without resolving it, so it is treated as
// non-loopback - the check errs towards firing the warning rather than staying
// silent on an address it is unsure about.
func loopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // no port to split off; classify the whole string
	}
	if host == "" {
		return false // ":8125" binds every interface
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false // a hostname we can't resolve here; don't assume it is loopback
	}
	return ip.IsLoopback()
}

// sriHashSizes are the digest lengths, in bytes, of the three hashes browsers
// accept for subresource integrity.
var sriHashSizes = map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}

// validSRI reports whether s has the shape of a subresource integrity digest:
// one of the three hashes browsers accept, then its base64, of the length that
// hash actually produces. Whether the digest MATCHES the script is the browser's
// job - it is the only party in a position to say - but everything short of that
// is worth catching here, because the browser's answer to a bad one is to refuse
// the script silently.
//
// The length check is the point of this. A digest of the wrong size for the
// algorithm it names parses perfectly well and is rejected by every browser, and
// the way an operator produces one is not exotic: the documented recipe is
// `openssl dgst -sha384`, so running it with -sha256 and leaving the sha384-
// prefix in place is a two-character mistake that would otherwise start cleanly
// and take the captcha down for every challenged visitor.
//
// Deliberately narrower than the spec, which also allows a space-separated LIST
// of digests and a ?options suffix. Neither is refused silently - loadCaptcha
// makes it a startup error naming what is accepted - and a single digest is what
// the recipe in the docs produces.
func validSRI(s string) bool {
	// The integrity attribute takes a WHITESPACE-SEPARATED LIST, and each entry may
	// carry a "?options" suffix. Both are spec-legal and a browser accepts them, so
	// refusing them here would switch the listener off over a correct value - the
	// operator mirroring a build and pinning two hashes during a rollover is the
	// obvious case. Every entry has to be valid: the browser picks the strongest it
	// recognises, so one malformed member is still a broken attribute.
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if i := strings.IndexByte(f, '?'); i >= 0 {
			f = f[:i] // the spec parks unrecognised options here; they do not affect the digest
		}
		alg, digest, ok := strings.Cut(f, "-")
		if !ok || digest == "" {
			return false
		}
		size, known := sriHashSizes[alg]
		if !known {
			return false
		}
		// Standard encoding with padding, which is what the spec requires and what
		// every tool that prints one emits.
		sum, err := base64.StdEncoding.DecodeString(digest)
		if err != nil || len(sum) != size {
			return false
		}
	}
	return true
}

// The remediations this bouncer can express in Apache, and the wildcard
// BOUNCING_ON_TYPE accepts. CrowdSec also defines "throttle", which has no
// RewriteMap expression at all - it is bounced on only to be degraded to
// FALLBACK_REMEDIATION, never enforced as itself.
const (
	remediationBan     = "ban"
	remediationCaptcha = "captcha"
	bouncingAll        = "all"
)

// knownRemediations are the decision types this bouncer can render a map for.
var knownRemediations = []string{remediationBan, remediationCaptcha}

// captchaUsable reports whether a captcha could actually be served. A captcha map
// with no listener is inert - the file fills up correctly and Apache does nothing
// with it - which is exactly the case FALLBACK_REMEDIATION exists to catch.
func (c *config) captchaUsable() bool { return c.captchaListen != "" }

// resolveRemediation decides which map a decision of this type renders into, or
// "" when it is not enforced at all.
//
// The order mirrors the nginx bouncer's exactly, because an operator running both
// should be able to reason about one set of rules:
//
//  1. BOUNCING_ON_TYPE filters: a decision of a type we are not bouncing on is
//     dropped before anything else looks at it.
//  2. OVERRIDE_REMEDIATION replaces whatever the hub asked for.
//  3. FALLBACK_REMEDIATION catches what is left: a remediation this bouncer cannot
//     express, or a captcha with no challenge to serve.
//
// Override deliberately runs BEFORE fallback, so overriding to captcha while no
// challenge is configured still degrades to the fallback rather than quietly
// enforcing nothing.
func (c *config) resolveRemediation(decisionType string) string {
	t := strings.ToLower(strings.TrimSpace(decisionType))
	if c.bouncingOnType != bouncingAll && t != c.bouncingOnType {
		return ""
	}
	r := t
	if c.overrideRemediation != "" {
		r = c.overrideRemediation
	}
	expressible := r == remediationBan || (r == remediationCaptcha && c.captchaUsable())
	if !expressible {
		// Always set - loadRemediationPolicy turns an empty value into ban - so
		// anything this bouncer cannot express becomes a block rather than nothing.
		return c.fallbackRemediation
	}
	return r
}

// mapsNeeded derives the maps to render by asking resolveRemediation what each
// kind of decision the LAPI can send would become. Deriving it means the maps and
// the routing can never disagree - a map is written exactly when something could
// land in it.
func (c *config) mapsNeeded() []string {
	var out []string
	// "throttle" stands in for any remediation this bouncer cannot express.
	for _, decisionType := range []string{remediationBan, remediationCaptcha, "throttle"} {
		if r := c.resolveRemediation(decisionType); r != "" && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	// Stable order regardless of how the settings were reached, so the startup
	// line and the map list read the same way every time.
	slices.Sort(out)
	return out
}

// loadRemediationPolicy reads the three settings that decide what this bouncer
// does with a decision. They are named and ordered to match the nginx bouncer, so
// one fleet does not need two mental models.
func (c *config) loadRemediationPolicy() error {
	c.bouncingOnType = strings.ToLower(strings.TrimSpace(envStr("BOUNCING_ON_TYPE", "")))
	if c.bouncingOnType == "" {
		c.bouncingOnType = legacyBouncingOnType()
	}
	if c.bouncingOnType != bouncingAll && !slices.Contains(knownRemediations, c.bouncingOnType) {
		return fmt.Errorf("BOUNCING_ON_TYPE: want %s or %s, got %q",
			strings.Join(knownRemediations, "/"), bouncingAll, c.bouncingOnType)
	}
	var err error
	// FALLBACK_REMEDIATION has no "off". It used to: an empty value dropped a
	// remediation this bouncer cannot express, rather than degrading it. That was the
	// one setting able to leave a decision the hub made enforced by NOTHING - a
	// captcha with no listener, or a throttle - which is the wrong default for a
	// security component and is not what an operator blanking a line expects. Empty
	// now means ban, like unset.
	if c.fallbackRemediation, err = optionalRemediation("FALLBACK_REMEDIATION", remediationBan); err != nil {
		return err
	}
	if c.fallbackRemediation == "" {
		// Only reachable when it was SET to empty - unset takes the default above -
		// so this is somebody's deliberate choice being overridden, and it has to say
		// so rather than change behaviour silently.
		log.Printf("FALLBACK_REMEDIATION is empty, which no longer means \"ignore\": using %s, so a decision this bouncer cannot express is blocked rather than dropped",
			remediationBan)
		c.fallbackRemediation = remediationBan
	}
	if c.overrideRemediation, err = optionalRemediation("OVERRIDE_REMEDIATION", ""); err != nil {
		return err
	}
	return nil
}

// optionalRemediation reads a setting that names one remediation, or is empty to
// switch the behaviour off. envOptional is used so an explicit "VAR=" means off
// rather than falling back to the default.
func optionalRemediation(name, def string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(envOptional(name, def)))
	if v == "" || slices.Contains(knownRemediations, v) {
		return v, nil
	}
	return "", fmt.Errorf("%s: want %s or empty, got %q", name, strings.Join(knownRemediations, "/"), v)
}

// legacyBouncingOnType maps the deprecated ONLY_BAN onto BOUNCING_ON_TYPE, so an
// existing config keeps working while being told, every start, to move.
//
// ONLY_BAN is a boolean over what turned out to be a three-way choice, and it
// shares no vocabulary with the nginx bouncer an operator is likely running
// beside this one. BOUNCING_ON_TYPE replaces it exactly.
func legacyBouncingOnType() string {
	v, set := os.LookupEnv("ONLY_BAN")
	if !set || strings.TrimSpace(v) == "" {
		return remediationBan
	}
	if envBool("ONLY_BAN", true) {
		log.Printf("DEPRECATED: ONLY_BAN is replaced by BOUNCING_ON_TYPE and will be removed in a future release; "+
			"reading it as BOUNCING_ON_TYPE=%s. Set BOUNCING_ON_TYPE=%s and drop ONLY_BAN.",
			remediationBan, remediationBan)
		return remediationBan
	}
	log.Printf("DEPRECATED: ONLY_BAN is replaced by BOUNCING_ON_TYPE and will be removed in a future release; "+
		"reading ONLY_BAN=false as BOUNCING_ON_TYPE=%s. Note this is no longer the same thing: it used to put "+
		"every decision type into the ban map, whereas captcha decisions now render to their own and "+
		"FALLBACK_REMEDIATION decides what happens when no challenge is configured. Set BOUNCING_ON_TYPE=%s "+
		"explicitly, and FALLBACK_REMEDIATION=%s to keep blocking what cannot be challenged.",
		bouncingAll, bouncingAll, remediationBan)
	return bouncingAll
}

// mapPaths returns the txt/dbm pair a remediation renders to. The ban map keeps
// OUTPUT_FILE/DBM_FILE, so an existing install's Apache config still points at
// the right file; every other type is named after itself in the same directory.
func (c *config) mapPaths(name string) (txt, dbm string) {
	if name == "ban" {
		return c.outputFile, c.dbmFile
	}
	txt = filepath.Join(filepath.Dir(c.outputFile), name+".txt")
	return txt, defaultDBMPath(txt)
}

// samePath reports whether two settings name the same file. Absolute first, so
// the answer cannot depend on the daemon's working directory - Abs also Cleans,
// which collapses the spellings an operator actually types (dir//file, dir/./file,
// file/, dir/../dir/file). A symlink still compares as a different path: this
// guards a config slip, not an adversary.
func samePath(a, b string) bool { return absPath(a) == absPath(b) }

// describePath names a path the way the operator will find it in their config.
// samePath deliberately matches spellings that are not textually equal, so a
// message quoting only the resolved path can name a string that appears nowhere in
// their file - a relative CAPTCHA_PASS_FILE reported as /var/lib/.../blocklist.txt,
// which sends them looking for a line they never wrote.
func describePath(p string) string {
	if abs := absPath(p); abs != filepath.Clean(p) {
		return fmt.Sprintf("%q, which resolves to %q", p, abs)
	}
	return fmt.Sprintf("%q", p)
}

func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p) // only fails when the working directory is gone
	}
	return abs
}

// envStr returns environment variable name, or def when it is unset or empty.
func envStr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// envInt returns environment variable name parsed as an int, falling back to def
// when it is unset, empty or unparseable.
func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

// clampEnvInt reads name as an int and holds it to [lo, hi], saying so when the
// clamp moved it.
//
// The saying-so is the point. These settings are clamped where they are read, so
// the value the operator wrote is discarded on the spot - and every later message
// then quotes the value in FORCE, naming a number that appears nowhere in their
// file. That is the same trap describePath exists to avoid for paths, and
// resyncEvery already avoids for RESYNC_INTERVAL by naming both numbers. Three
// numeric settings want it, so it lives here rather than being spelled out three
// times.
//
// Note this cannot see a malformed value: envInt returns def for "abc" without
// saying anything, so got == def and no clamp is reported. That gap is envInt's,
// not this function's.
func clampEnvInt(name string, def, lo, hi int) int {
	got := envInt(name, def)
	clamped := min(hi, max(lo, got))
	if clamped != got {
		log.Printf("WARNING: %s (%d) out of range; using %d (accepted: %d-%d)", name, got, clamped, lo, hi)
	}
	return clamped
}

// envBool returns environment variable name as a bool (1/true/yes/on are true;
// anything else is false), or def when it is unset.
func envBool(name string, def bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// envOptional returns environment variable name, or def when it is *unset*.
// Unlike envStr, an explicitly empty value comes back empty rather than falling
// back to def - which lets an operator write "VAR=" to turn a feature off.
func envOptional(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return strings.TrimSpace(v)
	}
	return def
}

// loadMetrics reads the scrape listener settings.
//
// METRICS_PATH is the daemon's only operator-controlled http.ServeMux pattern, and
// ServeMux PANICS on a pattern it cannot parse rather than returning an error. That
// makes an unvalidated value here not a broken scrape endpoint but a dead daemon:
// serveMetrics runs as a bare goroutine, an unrecovered panic in one takes the
// process with it, and under the shipped Restart=always/RestartSec=5 that is a
// crash loop which never reaches a poll - so the maps freeze at whatever they last
// held while Apache goes on serving them. A typo in an optional observability
// setting must not cost ban enforcement, which is the rule the whole captcha tier
// system exists to keep, so everything here substitutes and warns.
//
// Two shapes actually reach it. METRICS_PATH=metrics is the likely slip and the one
// worth honouring rather than discarding; anything carrying pattern syntax (a space
// makes ServeMux read the value as "METHOD /path", braces make it a wildcard) is
// refused outright, because guessing at those risks serving the exposition somewhere
// the operator did not ask for.
func (c *config) loadMetrics() {
	c.metricsListen = envStr("METRICS_LISTEN", "")
	p := strings.TrimSpace(envStr("METRICS_PATH", metricsDefaultPath))
	switch {
	case p == "":
		log.Printf("WARNING: METRICS_PATH is blank; using %s", metricsDefaultPath)
		p = metricsDefaultPath
	case strings.ContainsAny(p, " \t{}"):
		log.Printf("WARNING: METRICS_PATH (%q) carries http.ServeMux pattern syntax, which it refuses; using %s",
			p, metricsDefaultPath)
		p = metricsDefaultPath
	case !strings.HasPrefix(p, "/"):
		log.Printf("WARNING: METRICS_PATH (%q) has no leading slash, which http.ServeMux refuses; using %q",
			p, "/"+p)
		p = "/" + p
	}
	// Registering is not the same as being reachable, and this is the gap between
	// them. ServeMux canonicalises the request path before it matches, so a pattern
	// that is not already clean registers without complaint and then can never be
	// hit: "//metrics" is accepted, every request for it is redirected to "/metrics",
	// and nothing is registered there. The endpoint the startup line prints has to be
	// the endpoint a scrape can reach.
	//
	// A trailing slash is preserved rather than cleaned away, because in a pattern it
	// is meaningful - it makes the pattern a subtree - and dropping it would turn an
	// operator's "/metrics/" into an exact match that their own scrape URL misses.
	cleaned := path.Clean(p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		cleaned += "/"
	}
	if cleaned != p {
		log.Printf("WARNING: METRICS_PATH (%q) is not a canonical path, so http.ServeMux would redirect every request away from it; using %q",
			p, cleaned)
		p = cleaned
	}
	c.metricsPath = p
}

// loadConfig assembles a config from the -dir flag and environment variables,
// applying defaults. It errors if CROWDSEC_API_KEY is unset, or if MAP_TYPE=dbm
// but httxt2dbm can't be found.
func loadConfig() (*config, error) {
	// Blocklist directory: -dir flag > BLOCKLIST_DIR env > default. The txt map,
	// the DBM, and every temp file live here (same-dir keeps renames atomic).
	// Explicit OUTPUT_FILE / DBM_FILE env vars trump the directory entirely.
	dir := *flagDir
	if dir == "" {
		dir = envStr("BLOCKLIST_DIR", "/var/lib/crowdsec-apache2-bouncer")
	}
	cfg := &config{
		lapiURL:         strings.TrimRight(envStr("CROWDSEC_LAPI_URL", "http://127.0.0.1:8080"), "/"),
		apiKey:          envStr("CROWDSEC_API_KEY", ""),
		outputFile:      envStr("OUTPUT_FILE", filepath.Join(dir, "blocklist.txt")),
		updateFrequency: time.Duration(min(maxDurationSecs, max(1, envInt("UPDATE_FREQUENCY", 60)))) * time.Second,
		expandMaxHosts:  uint64(min(1<<20, max(1, envInt("EXPAND_MAX_HOSTS", 65536)))),
		resyncInterval:  resyncEvery(envInt("RESYNC_INTERVAL", 21600)),
		requestTimeout:  time.Duration(min(maxDurationSecs, max(1, envInt("REQUEST_TIMEOUT", 10)))) * time.Second,
		// STREAM_REQUEST_TIMEOUT: the whole-query deadline for the decision stream
		// (the startup snapshot can be large), separate from the connect timeout.
		streamRequestTimeout: time.Duration(min(maxDurationSecs, max(1, envInt("STREAM_REQUEST_TIMEOUT", 15)))) * time.Second,
		mapType:              strings.ToLower(envStr("MAP_TYPE", "txt")),
		httxt2dbm:            envStr("HTTXT2DBM", "httxt2dbm"),
		insecure:             envBool("INSECURE", false),
		caBundle:             envStr("CA_BUNDLE", ""),
		// The daemon creates allowlist.txt/denylist.txt here and, in dbm mode,
		// rebuilds their DBMs when they change. Set CUSTOM_LIST_DIR= (empty) to
		// leave them alone entirely, or point it elsewhere on RHEL-family layouts
		// where Apache config lives under /etc/httpd.
		customListDir: envOptional("CUSTOM_LIST_DIR", "/etc/apache2/crowdsec"),
	}
	if cfg.apiKey == "" {
		return nil, fmt.Errorf("CROWDSEC_API_KEY is required (cscli bouncers add <name>)")
	}
	cfg.dbmFile = envStr("DBM_FILE", defaultDBMPath(cfg.outputFile))
	// The DBM is built *from* the txt map, so a DBM that lands on the txt path makes
	// the converter destroy its own input and the two forms flap on every poll -
	// which surfaces as blocking that works intermittently for no visible reason.
	//
	// Compared by samePath against every name the DBM can occupy, not by == against
	// the base, because both of those miss real collisions. == misses the spellings
	// samePath collapses - the ones an operator actually types, per its own comment -
	// and the base alone misses three of the four backend names: with
	// DBM_FILE=/x/map and OUTPUT_FILE=/x/map.pag, an SDBM build renames its output
	// straight onto the txt map. Same comparison the pass/readiness guard below uses,
	// for the same reason.
	for _, written := range dbmFilesFor(cfg.dbmFile) {
		if !samePath(written, cfg.outputFile) {
			continue
		}
		if written != cfg.dbmFile {
			return nil, fmt.Errorf("DBM_FILE %s is built as %q, the same file as OUTPUT_FILE %s; the DBM is built from the txt map, so they must differ",
				describePath(cfg.dbmFile), written, describePath(cfg.outputFile))
		}
		return nil, fmt.Errorf("DBM_FILE and OUTPUT_FILE are both %s; the DBM is built from the txt map, so they must differ",
			describePath(cfg.outputFile))
	}
	if cfg.mapType == "dbm" {
		if _, err := exec.LookPath(cfg.httxt2dbm); err != nil {
			return nil, fmt.Errorf("MAP_TYPE=dbm but %q not found (install apache2-utils / httpd-tools, or set HTTXT2DBM)", cfg.httxt2dbm)
		}
	}
	// After outputFile/dbmFile are settled: mapPaths derives every other map from
	// them, so the ban map has to be final before the rest are named.
	if err := cfg.loadRemediationPolicy(); err != nil {
		return nil, err
	}
	// The captcha settings have to be read before the maps are derived:
	// resolveRemediation asks whether a challenge can actually be served, and
	// degrades captcha to the fallback when it cannot.
	if err := cfg.loadCaptcha(dir); err != nil {
		return nil, err
	}
	// FALLBACK_REMEDIATION=captcha with no listener is the one combination the
	// fallback cannot catch, because the fallback IS the captcha: resolveRemediation
	// hands back a remediation nothing can serve, mapsNeeded renders the captcha map
	// for it, and every decision routed there - including the throttles the fallback
	// exists to absorb - ends up enforced by nothing. Demoted here rather than in
	// loadRemediationPolicy because CAPTCHA_LISTEN is not known until loadCaptcha has
	// run, and it has to be settled before the maps are derived from it.
	if cfg.fallbackRemediation == remediationCaptcha && !cfg.captchaUsable() {
		log.Printf("WARNING: FALLBACK_REMEDIATION=%s but no challenge listener can run (CAPTCHA_LISTEN is unset, or was switched off by an earlier captcha setting), which would leave every decision it catches enforced by nothing: using %s instead",
			remediationCaptcha, remediationBan)
		cfg.fallbackRemediation = remediationBan
	}
	cfg.loadMetrics()
	// Never empty: BOUNCING_ON_TYPE always names at least one remediation this
	// bouncer can express, and that one always resolves to itself.
	cfg.remediations = cfg.mapsNeeded()
	// A challenge listener with nothing routed to it is a no-op, not a reason to
	// refuse to start. Failing here would freeze ban enforcement over a captcha
	// misconfiguration - the exact trade loadCaptcha warns against everywhere else -
	// and it is the state an operator lands in by uncommenting CAPTCHA_LISTEN alone,
	// the single most obvious step. Warn and switch the listener off instead, so bans
	// keep updating.
	//
	// The boundary is deliberate, and it has three tiers rather than two:
	//
	//  1. SUBSTITUTE - a bad ALTCHA dial falls back to the shipped defaults
	//     (loadCaptcha above), and a FALLBACK_REMEDIATION that cannot be served
	//     falls back to ban (just above). The check still runs, at a cost nobody
	//     chose, and the decision is still enforced.
	//  2. SWITCH THE LISTENER OFF - no routing reaches the captcha map (this
	//     check), or a malformed CAPTCHA_WIDGET_SRI. There is nothing safe to
	//     substitute, so the challenge is not served. Both clear CAPTCHA_LISTEN
	//     before the maps are derived, so captcha decisions take
	//     FALLBACK_REMEDIATION and the captcha map is never rendered at all.
	//     An unusable CAPTCHA_TEMPLATE is NOT in this tier: it fails in
	//     startChallenge, after routing is already fixed, so the captcha map is
	//     rendered and the listener is simply not there to serve it. That is a
	//     runtime gap the log line at the failure has to name, not a tier.
	//  3. REFUSE TO START - only where continuing would destroy data or lie about
	//     what the daemon is doing: a pass or readiness file aimed at a map the
	//     daemon empties, and the removed Cap provider settings, which would
	//     otherwise let a half-migrated config start cleanly while verifying
	//     nothing.
	//
	// Tiers 1 and 2 both keep the ban map updating, which is the property that
	// decides the tier: a captcha misconfiguration never takes ban enforcement
	// down. Tier 3 is not "invalid values" - a mistyped algorithm is invalid and
	// degrades; it is destruction and misrepresentation.
	if cfg.captchaUsable() && !slices.Contains(cfg.remediations, remediationCaptcha) {
		log.Printf("WARNING: CAPTCHA_LISTEN=%s is set but no captcha decisions are routed to it "+
			"(BOUNCING_ON_TYPE=%s, OVERRIDE_REMEDIATION=%q), so the challenge listener will not start. "+
			"Set BOUNCING_ON_TYPE=all (or =captcha), and clear any OVERRIDE_REMEDIATION that routes captcha elsewhere, to enable it.",
			cfg.captchaListen, cfg.bouncingOnType, cfg.overrideRemediation)
		cfg.captchaListen = ""
	}
	// The pass map must not share a path with anything else this daemon writes:
	// startChallenge resets it at boot, so a collision truncates whatever file it
	// lands on. Only meaningful while the listener actually runs, so gate on that -
	// which also skips it when the warning above switched the listener off.
	// Both of these files DESTROY what they point at: startChallenge rewrites the
	// pass map on every start, and the readiness file is truncated to zero bytes when
	// the listener comes up (markReady) and deleted when it goes down (clearReady).
	// Pointed at the ban map, either one empties it.
	//
	// They are scoped differently on purpose. The pass map is pre-created whatever
	// the captcha is doing - it has to be, or Apache refuses to start on a missing
	// RewriteMap the moment an operator uncomments the captcha block - so it is
	// checked unconditionally. The readiness file is only ever written while the
	// listener runs, so checking it otherwise would refuse to start over a stale
	// setting nothing is going to touch.
	//
	// Checked against every map the daemon can WRITE, not just the ones this policy
	// renders. retireUnusedMaps still empties a map that used to be produced, so a
	// path aimed at a now-retired map - the ban map under BOUNCING_ON_TYPE=captcha,
	// say - would otherwise pass this guard. knownRemediations is that full set.
	// Comparison is by samePath, so any spelling of the same file matches.
	type ownedFile struct{ setting, path string }
	owned := []ownedFile{{"CAPTCHA_PASS_FILE", cfg.captchaPassFile}}
	if cfg.captchaUsable() {
		owned = append(owned, ownedFile{"CAPTCHA_READY_FILE", cfg.captchaReadyFile})
	}
	for _, own := range owned {
		if own.path == "" {
			continue // CAPTCHA_READY_FILE= switches the readiness signal off
		}
		for _, name := range knownRemediations {
			for _, rendered := range mapFilesFor(cfg.mapPaths(name)) {
				if !samePath(own.path, rendered) {
					continue
				}
				if name == remediationBan {
					return nil, fmt.Errorf("%s is %s - the same file as the ban map; the daemon empties that file, which would unban everyone", own.setting, describePath(own.path))
				}
				return nil, fmt.Errorf("%s is %s - the same file as the %s map; the daemon empties that file, so the map would be lost until the next poll rebuilds it", own.setting, describePath(own.path), name)
			}
		}
		// Custom lists are worse off than the maps: they are operator-maintained,
		// so nothing would ever rebuild one that has been truncated.
		for _, list := range newCustomLists(cfg.customListDir) {
			for _, kept := range mapFilesFor(list.txt, list.dbm) {
				if samePath(own.path, kept) {
					return nil, fmt.Errorf("%s is %s - the same file as the custom %s; the daemon empties that file, and nothing rebuilds a truncated custom list", own.setting, describePath(own.path), list.name)
				}
			}
		}
	}
	// And not each other: the readiness file is deleted when the listener stops,
	// which would take every recorded pass with it.
	if cfg.captchaUsable() && cfg.captchaReadyFile != "" && samePath(cfg.captchaReadyFile, cfg.captchaPassFile) {
		return nil, fmt.Errorf("CAPTCHA_READY_FILE is %s and CAPTCHA_PASS_FILE is %s - the same file; the readiness file is deleted when the listener stops, taking every pass with it", describePath(cfg.captchaReadyFile), describePath(cfg.captchaPassFile))
	}
	// REQUEST_TIMEOUT is a per-phase bound nested inside the overall
	// STREAM_REQUEST_TIMEOUT deadline, so a larger value would be masked by the
	// stream deadline and never fire. Cap it so it always stays effective.
	if cfg.requestTimeout > cfg.streamRequestTimeout {
		log.Printf("REQUEST_TIMEOUT (%s) > STREAM_REQUEST_TIMEOUT (%s); capping REQUEST_TIMEOUT to the stream timeout",
			cfg.requestTimeout, cfg.streamRequestTimeout)
		cfg.requestTimeout = cfg.streamRequestTimeout
	}
	return cfg, nil
}

// resyncEvery turns a RESYNC_INTERVAL seconds value into an interval: 0 or less
// disables the periodic full re-sync, and anything else is held to [1h, 24h]. An
// out-of-range value is honoured at the nearest bound rather than rejected, so a
// bad setting can't stop the daemon starting - but it says so, because otherwise
// the interval in the logs wouldn't be the one that was configured.
func resyncEvery(secs int) time.Duration {
	if secs <= 0 {
		return 0 // disabled
	}
	clamped := min(maxResyncSecs, max(minResyncSecs, secs))
	if clamped != secs {
		log.Printf("RESYNC_INTERVAL (%ds) out of range; using %ds (0 disables, otherwise %d-%ds)",
			secs, clamped, minResyncSecs, maxResyncSecs)
	}
	return time.Duration(clamped) * time.Second
}

// defaultDBMPath derives the DBM path from the txt output path, swapping a
// trailing .txt for .dbm.
func defaultDBMPath(outputFile string) string {
	return strings.TrimSuffix(outputFile, ".txt") + ".dbm"
}
