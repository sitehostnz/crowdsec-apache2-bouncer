package main

import (
	"fmt"
	"log"
	"strings"
)

// reload re-reads the config file on SIGHUP and applies the settings that can
// change while the daemon runs, in place. It returns whether UPDATE_FREQUENCY
// moved, so the caller can reset the poll ticker.
//
// It runs on the poll goroutine (see run), which is what makes the in-place
// writes below safe without a lock: UPDATE_FREQUENCY, RESYNC_INTERVAL,
// EXPAND_MAX_HOSTS and STREAM_REQUEST_TIMEOUT are read only by that same
// goroutine. The two reloadable settings other goroutines read - the ALTCHA
// dials, which the request goroutines mint with, and the pass TTL, which the
// listener writes - are applied through their own synchronised setters
// (challengeServer.dials, passStore.setTTL) rather than by touching cfg.
//
// Everything else is treated as restart-required: the LAPI client, the listen
// addresses and the challenge page are built once at start, and the map set and
// its paths are wired into Apache's own config. A change to one of those is
// logged, loudly and by name, rather than half-applied - the silent partial
// reload is the failure this is meant to avoid.
func (b *bouncer) reload() (freqChanged bool) {
	path := b.cfg.configFile
	if path == "" {
		log.Printf("reload: no config file to re-read (set -config or CONFIG_FILE); nothing to do")
		return false
	}
	// The env fallback in loadConfigFromFile means an unreadable or half-written
	// file still yields a config - but a genuine read error (gone, no permission)
	// comes back here, and the running config is kept rather than replaced blind.
	fresh, err := loadConfigFromFile(path)
	if err != nil {
		log.Printf("reload: cannot read %s: %v; keeping the running configuration", path, err)
		return false
	}

	var applied, deferred []string

	// --- applied live: read only by this goroutine, so a plain write is safe ---
	if fresh.updateFrequency != b.cfg.updateFrequency {
		applied = append(applied, fmt.Sprintf("UPDATE_FREQUENCY %s->%s", b.cfg.updateFrequency, fresh.updateFrequency))
		b.cfg.updateFrequency = fresh.updateFrequency
		freqChanged = true
	}
	if fresh.resyncInterval != b.cfg.resyncInterval {
		applied = append(applied, fmt.Sprintf("RESYNC_INTERVAL %s->%s", b.cfg.resyncInterval, fresh.resyncInterval))
		b.cfg.resyncInterval = fresh.resyncInterval
	}
	if fresh.expandMaxHosts != b.cfg.expandMaxHosts {
		applied = append(applied, fmt.Sprintf("EXPAND_MAX_HOSTS %d->%d", b.cfg.expandMaxHosts, fresh.expandMaxHosts))
		b.cfg.expandMaxHosts = fresh.expandMaxHosts
	}
	if fresh.streamRequestTimeout != b.cfg.streamRequestTimeout {
		applied = append(applied, fmt.Sprintf("STREAM_REQUEST_TIMEOUT %s->%s", b.cfg.streamRequestTimeout, fresh.streamRequestTimeout))
		b.cfg.streamRequestTimeout = fresh.streamRequestTimeout
	}

	// --- applied live through synchronised setters (other goroutines read these) ---
	if b.challenge != nil {
		if cur := b.challenge.dials.Load(); fresh.altchaAlgorithm != cur.algorithm ||
			fresh.altchaCost != cur.cost || fresh.altchaComplexity != cur.complexity {
			applied = append(applied, fmt.Sprintf("ALTCHA %s/cost=%d/complexity=%d -> %s/cost=%d/complexity=%d",
				cur.algorithm, cur.cost, cur.complexity, fresh.altchaAlgorithm, fresh.altchaCost, fresh.altchaComplexity))
			b.challenge.dials.Store(&altchaDials{algorithm: fresh.altchaAlgorithm, cost: fresh.altchaCost, complexity: fresh.altchaComplexity})
		}
	}
	if b.passes != nil {
		if cur := b.passes.ttlOf(); fresh.captchaPassTTL != cur {
			applied = append(applied, fmt.Sprintf("CAPTCHA_PASS_TTL %s->%s", cur, fresh.captchaPassTTL))
			b.passes.setTTL(fresh.captchaPassTTL)
		}
	}

	// --- restart-required: detected and named, never half-applied ---
	// Compared against the running config (b.cfg), which for these fields still
	// holds the start-time value because nothing above writes them - so this keeps
	// reporting the change until a restart actually applies it.
	restartOnly := []struct{ name, was, now string }{
		{"CROWDSEC_LAPI_URL", b.cfg.lapiURL, fresh.lapiURL},
		{"OUTPUT_FILE", b.cfg.outputFile, fresh.outputFile},
		{"DBM_FILE", b.cfg.dbmFile, fresh.dbmFile},
		{"MAP_TYPE", b.cfg.mapType, fresh.mapType},
		{"HTTXT2DBM", b.cfg.httxt2dbm, fresh.httxt2dbm},
		{"CUSTOM_LIST_DIR", b.cfg.customListDir, fresh.customListDir},
		{"CA_BUNDLE", b.cfg.caBundle, fresh.caBundle},
		{"BOUNCING_ON_TYPE", b.cfg.bouncingOnType, fresh.bouncingOnType},
		{"OVERRIDE_REMEDIATION", b.cfg.overrideRemediation, fresh.overrideRemediation},
		{"FALLBACK_REMEDIATION", b.cfg.fallbackRemediation, fresh.fallbackRemediation},
		{"CAPTCHA_LISTEN", b.cfg.captchaListen, fresh.captchaListen},
		{"CAPTCHA_PATH", b.cfg.captchaPath, fresh.captchaPath},
		{"CAPTCHA_WIDGET_JS", b.cfg.captchaWidgetJS, fresh.captchaWidgetJS},
		{"CAPTCHA_WIDGET_SRI", b.cfg.captchaWidgetSRI, fresh.captchaWidgetSRI},
		{"CAPTCHA_TOKEN_FIELD", b.cfg.captchaTokenField, fresh.captchaTokenField},
		{"CAPTCHA_TEMPLATE", b.cfg.captchaTemplate, fresh.captchaTemplate},
		{"CAPTCHA_PASS_FILE", b.cfg.captchaPassFile, fresh.captchaPassFile},
		{"CAPTCHA_READY_FILE", b.cfg.captchaReadyFile, fresh.captchaReadyFile},
		{"METRICS_LISTEN", b.cfg.metricsListen, fresh.metricsListen},
		{"METRICS_PATH", b.cfg.metricsPath, fresh.metricsPath},
	}
	for _, s := range restartOnly {
		if s.was != s.now {
			deferred = append(deferred, fmt.Sprintf("%s (%q->%q)", s.name, s.was, s.now))
		}
	}
	if fresh.requestTimeout != b.cfg.requestTimeout {
		deferred = append(deferred, fmt.Sprintf("REQUEST_TIMEOUT (%s->%s)", b.cfg.requestTimeout, fresh.requestTimeout))
	}
	if fresh.insecure != b.cfg.insecure {
		deferred = append(deferred, fmt.Sprintf("INSECURE (%t->%t)", b.cfg.insecure, fresh.insecure))
	}
	// Named but never valued: the key is a secret, and a log line is the wrong place
	// for it.
	if fresh.apiKey != b.cfg.apiKey {
		deferred = append(deferred, "CROWDSEC_API_KEY (changed)")
	}

	if len(applied) == 0 && len(deferred) == 0 {
		log.Printf("reload: %s re-read, configuration unchanged", path)
		return freqChanged
	}
	if len(applied) > 0 {
		log.Printf("reload: applied live: %s", strings.Join(applied, ", "))
	}
	if len(deferred) > 0 {
		log.Printf("reload: these need a restart to take effect and were NOT applied: %s", strings.Join(deferred, ", "))
	}
	return freqChanged
}
