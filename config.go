package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
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
	captchaListen        string
	captchaPath          string // the path Apache proxies to the listener
	captchaVerifyURL     string // the provider's siteverify
	captchaSecret        string
	captchaAPIEndpoint   string // what the widget talks to
	captchaWidgetJS      string // the widget script
	captchaTokenField    string // the form field the solved token arrives in
	captchaTemplate      string // optional challenge page override
	captchaPassFile      string // the map of solved challenges
	captchaReadyFile     string // exists only while the challenge is actually listening
	captchaPassTTL       time.Duration
	captchaPassKey       string // "ip" | "cookie"
	captchaCookieName    string
	captchaCookieSecure  bool
	captchaVerifyTimeout time.Duration

	// Prometheus scrape endpoint. Empty (the default) switches it off. Kept on its
	// own listener: the challenge one is proxied to the public internet.
	metricsListen string
	metricsPath   string
}

// How a solved challenge is remembered. See newPass for the trade-off.
const (
	passKeyIP     = "ip"
	passKeyCookie = "cookie"
)

// loadCaptcha fills in the challenge listener's settings and checks the ones that
// cannot be defaulted. Everything here is inert until CAPTCHA_LISTEN is set.
func (c *config) loadCaptcha(dir string) error {
	c.captchaListen = envStr("CAPTCHA_LISTEN", "")
	c.captchaPath = envStr("CAPTCHA_PATH", "/crowdsec-verify")
	c.captchaVerifyURL = envStr("CAPTCHA_VERIFY_URL", "")
	c.captchaSecret = envStr("CAPTCHA_SECRET", "")
	c.captchaAPIEndpoint = envStr("CAPTCHA_API_ENDPOINT", "")
	c.captchaWidgetJS = envStr("CAPTCHA_WIDGET_JS", "https://cdn.jsdelivr.net/npm/cap-widget")
	c.captchaTokenField = envStr("CAPTCHA_TOKEN_FIELD", "cap-token")
	c.captchaTemplate = envStr("CAPTCHA_TEMPLATE", "")
	c.captchaPassFile = envStr("CAPTCHA_PASS_FILE", filepath.Join(dir, "captcha_passed.txt"))
	// Under /run so it cannot outlive a reboot, and inside the unit's
	// RuntimeDirectory= so systemd removes it even when the daemon is killed
	// outright. Empty switches the signal off.
	c.captchaReadyFile = envOptional("CAPTCHA_READY_FILE", "/run/crowdsec-apache2-bouncer/challenge.up")
	c.captchaPassTTL = time.Duration(min(maxDurationSecs, max(60, envInt("CAPTCHA_PASS_TTL", 3600)))) * time.Second
	c.captchaPassKey = strings.ToLower(strings.TrimSpace(envStr("CAPTCHA_PASS_KEY", passKeyIP)))
	c.captchaCookieName = envStr("CAPTCHA_COOKIE_NAME", "cs_captcha")
	c.captchaCookieSecure = envBool("CAPTCHA_COOKIE_SECURE", true)
	c.captchaVerifyTimeout = time.Duration(min(maxDurationSecs, max(1, envInt("CAPTCHA_VERIFY_TIMEOUT", 5)))) * time.Second

	if c.captchaListen == "" {
		return nil
	}
	if c.captchaPassKey != passKeyIP && c.captchaPassKey != passKeyCookie {
		return fmt.Errorf("CAPTCHA_PASS_KEY: want %q or %q, got %q", passKeyIP, passKeyCookie, c.captchaPassKey)
	}
	// A listener with nowhere to verify against would fail every solve closed, so
	// it is better to refuse at startup than to challenge people into a wall.
	for _, required := range []struct{ name, value string }{
		{"CAPTCHA_VERIFY_URL", c.captchaVerifyURL},
		{"CAPTCHA_SECRET", c.captchaSecret},
		{"CAPTCHA_API_ENDPOINT", c.captchaAPIEndpoint},
	} {
		if required.value == "" {
			return fmt.Errorf("CAPTCHA_LISTEN is set, so %s is required", required.name)
		}
	}
	if c.captchaPassFile == c.outputFile {
		return fmt.Errorf("CAPTCHA_PASS_FILE and OUTPUT_FILE are both %q; a pass map that overwrites the ban list would unban everyone", c.outputFile)
	}
	return nil
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
	if !expressible && c.fallbackRemediation != "" {
		return c.fallbackRemediation
	}
	if r == remediationBan || r == remediationCaptcha {
		// A captcha with no listener and no fallback lands here: rendered to its
		// map and enforced by nothing. warnAboutEnforcement says so at startup.
		return r
	}
	return "" // unexpressible, and no fallback to catch it
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
	// An empty FALLBACK_REMEDIATION is meaningful: it turns the degrade off, so an
	// unexpressible remediation is dropped instead of becoming something else.
	if c.fallbackRemediation, err = optionalRemediation("FALLBACK_REMEDIATION", remediationBan); err != nil {
		return err
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
	// The DBM is built *from* the txt map, so pointing both at one path makes the
	// converter destroy its own input and the two forms flap on every poll - which
	// surfaces as blocking that works intermittently for no visible reason.
	if cfg.dbmFile == cfg.outputFile {
		return nil, fmt.Errorf("DBM_FILE and OUTPUT_FILE are both %q; the DBM is built from the txt map, so they must differ", cfg.outputFile)
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
	cfg.metricsListen = envStr("METRICS_LISTEN", "")
	cfg.metricsPath = envStr("METRICS_PATH", "/metrics")
	// Never empty: BOUNCING_ON_TYPE always names at least one remediation this
	// bouncer can express, and that one always resolves to itself.
	cfg.remediations = cfg.mapsNeeded()
	if cfg.captchaUsable() && !slices.Contains(cfg.remediations, remediationCaptcha) {
		return nil, fmt.Errorf("CAPTCHA_LISTEN is set but nothing can reach the captcha map: "+
			"BOUNCING_ON_TYPE=%s, OVERRIDE_REMEDIATION=%q", cfg.bouncingOnType, cfg.overrideRemediation)
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
