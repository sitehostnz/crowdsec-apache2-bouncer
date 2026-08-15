package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// metrics is what the daemon knows about itself, in Prometheus exposition
// format. It is deliberately hand-rolled: this bouncer has no dependencies, and
// the exposition format is a dozen lines of text.
//
// The counters are atomic because the challenge listener increments some of them
// while the poll loop increments others. The gauges are read live from the
// bouncer at scrape time rather than mirrored here, so they can never drift from
// what is actually on disk - under b.state, because a scrape is a third
// goroutine reading a list the poll loop is free to be rewriting.
type metrics struct {
	pollsOK       atomic.Int64
	pollsFailed   atomic.Int64
	resyncsOK     atomic.Int64
	resyncRefused atomic.Int64
	mapWrites     atomic.Int64
	mapWriteFail  atomic.Int64
	dbmRebuilds   atomic.Int64
	dbmFailures   atomic.Int64

	challengesServed atomic.Int64
	solvesOK         atomic.Int64
	solvesRejected   atomic.Int64
	solvesErrored    atomic.Int64
	passesExpired    atomic.Int64
	challengesLapsed atomic.Int64
	challengesMinted atomic.Int64

	// lastPollUnix is the wall-clock time of the last SUCCESSFUL poll. It is the
	// single most useful number here: a daemon can be up, polling and logging
	// happily while the list it serves is hours stale, and nothing else in this
	// set would show it.
	lastPollUnix atomic.Int64
	lastPollSecs atomic.Uint64 // float64 bits: duration of the last cycle

	startedAt time.Time
}

func newMetrics() *metrics { return &metrics{startedAt: time.Now()} }

// observeDuration stores a float64 in an atomic without a mutex.
func observeDuration(dst *atomic.Uint64, d time.Duration) {
	dst.Store(math.Float64bits(d.Seconds()))
}

func loadDuration(src *atomic.Uint64) float64 { return math.Float64frombits(src.Load()) }

// serveMetrics runs the scrape listener until ctx is cancelled. It is a separate
// listener from the challenge on purpose: that one is proxied to the public
// internet, and this exposes how the enforcement is doing.
func (b *bouncer) serveMetrics(ctx context.Context) {
	if b.cfg.metricsListen == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc(b.cfg.metricsPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(b.renderMetrics()))
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", b.cfg.metricsListen)
	if err != nil {
		log.Printf("metrics listener not started: %v", err)
		return
	}
	go func() {
		<-ctx.Done()
		// Detached on purpose: ctx is already cancelled by the time we get here.
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second) //nolint:contextcheck // see above
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("metrics on %s%s", b.cfg.metricsListen, b.cfg.metricsPath)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("metrics listener stopped: %v", err)
	}
}

// sample is one line of exposition.
type sample struct {
	name   string
	help   string
	typ    string // "counter" | "gauge"
	labels map[string]string
	value  float64
}

const metricPrefix = "crowdsec_apache_bouncer_"

// mapGauge is one remediation's pair of size gauges, copied out of the list.
type mapGauge struct {
	name      string
	ips       int
	decisions int
}

// gauges takes every number renderMetrics needs from the list in a single read
// under b.state. Copied out rather than read where they are used, so all of them
// describe one moment and the lock is not held across building the document -
// the scrape blocks only for as long as it takes to count some maps, and the
// poll loop is never waiting on a slow HTTP write.
//
// The passStore and altchaStore counts are deliberately not in here: they carry
// their own locks and are not part of the list.
func (b *bouncer) gauges() (skippedRanges int, maps []mapGauge) {
	b.state.RLock()
	defer b.state.RUnlock()
	maps = make([]mapGauge, 0, len(b.remediations))
	for _, r := range b.remediations {
		maps = append(maps, mapGauge{name: r.name, ips: len(r.refcount), decisions: len(r.decisionIPs)})
	}
	return b.skippedRanges, maps
}

// renderMetrics builds the whole exposition document. Gauges are read from live
// state at scrape time.
func (b *bouncer) renderMetrics() string {
	m := b.metrics
	skipped, mapGauges := b.gauges()
	out := []sample{
		{name: "build_info", typ: "gauge", value: 1,
			help:   "Always 1, labelled with the running version.",
			labels: map[string]string{"version": strings.TrimPrefix(userAgent, "crowdsec-apache2-bouncer/")}},
		{name: "uptime_seconds", typ: "gauge", value: time.Since(m.startedAt).Seconds(),
			help: "Seconds since the daemon started."},

		{name: "last_successful_poll_timestamp_seconds", typ: "gauge", value: float64(m.lastPollUnix.Load()),
			help: "Unix time of the last poll that succeeded. Alert on this: the list can be badly stale while everything else looks healthy."},
		{name: "poll_duration_seconds", typ: "gauge", value: loadDuration(&m.lastPollSecs),
			help: "How long the last poll cycle took, list maintenance included."},

		{name: "polls_total", typ: "counter", value: float64(m.pollsOK.Load()),
			help: "Polls of the LAPI decision stream.", labels: map[string]string{"result": "ok"}},
		{name: "polls_total", typ: "counter", value: float64(m.pollsFailed.Load()),
			labels: map[string]string{"result": "failed"}},
		{name: "resyncs_total", typ: "counter", value: float64(m.resyncsOK.Load()),
			help: "Periodic full snapshots. A refused one means the snapshot would have unbanned most of the list.", labels: map[string]string{"result": "ok"}},
		{name: "resyncs_total", typ: "counter", value: float64(m.resyncRefused.Load()),
			labels: map[string]string{"result": "refused"}},

		{name: "map_writes_total", typ: "counter", value: float64(m.mapWrites.Load()),
			help: "Renders of a map to disk.", labels: map[string]string{"result": "ok"}},
		{name: "map_writes_total", typ: "counter", value: float64(m.mapWriteFail.Load()),
			labels: map[string]string{"result": "failed"}},
		{name: "dbm_rebuilds_total", typ: "counter", value: float64(m.dbmRebuilds.Load()),
			help: "httxt2dbm conversions. Failures leave Apache reading the previous map.", labels: map[string]string{"result": "ok"}},
		{name: "dbm_rebuilds_total", typ: "counter", value: float64(m.dbmFailures.Load()),
			labels: map[string]string{"result": "failed"}},

		{name: "ranges_skipped", typ: "gauge", value: float64(skipped),
			help: "Range decisions in the last apply too large to expand under EXPAND_MAX_HOSTS."},
	}

	// Per-remediation gauges, read live so they cannot drift from the maps.
	for _, g := range mapGauges {
		out = append(out,
			sample{name: "map_ips", typ: "gauge", value: float64(g.ips),
				help:   "Addresses currently rendered into each map.",
				labels: map[string]string{"remediation": g.name}},
			sample{name: "map_decisions", typ: "gauge", value: float64(g.decisions),
				help:   "Decisions currently held per remediation. Not the same as addresses: one range is many.",
				labels: map[string]string{"remediation": g.name}},
		)
	}

	if b.cfg.captchaListen != "" {
		held := 0
		if b.passes != nil {
			held = b.passes.held()
		}
		outstanding := 0
		if b.altcha != nil {
			outstanding = b.altcha.held()
		}
		out = append(out,
			sample{name: "challenges_served_total", typ: "counter", value: float64(m.challengesServed.Load()),
				help: "Challenge pages served on a fresh request. A page re-rendered after a failed solve is not counted here - see challenge_solves_total."},
			sample{name: "challenge_solves_total", typ: "counter", value: float64(m.solvesOK.Load()),
				help:   "Solve attempts by outcome. 'rejected' means nothing usable was submitted - no token, or a body too large or malformed to parse; 'errored' means the solution was wrong, expired or already spent, or the pass could not be written to disk. Verification is local, so none of these is a network fault.",
				labels: map[string]string{"result": "ok"}},
			sample{name: "challenge_solves_total", typ: "counter", value: float64(m.solvesRejected.Load()),
				labels: map[string]string{"result": "rejected"}},
			sample{name: "challenge_solves_total", typ: "counter", value: float64(m.solvesErrored.Load()),
				labels: map[string]string{"result": "errored"}},
		)
		out = append(out,
			sample{name: "captcha_passes", typ: "gauge", value: float64(held),
				help: "Solved challenges currently honoured."},
			sample{name: "captcha_passes_expired_total", typ: "counter", value: float64(m.passesExpired.Load()),
				help: "Passes dropped because their TTL lapsed."},
			// The daemon's only state that grows with traffic rather than with
			// decisions, one entry per challenged address - worth watching, because
			// a number that climbs and never falls means pruning is not keeping up
			// or a lot of visitors are abandoning the check.
			sample{name: "altcha_challenges", typ: "gauge", value: float64(outstanding),
				help: "Challenges issued and not yet solved, expired or spent."},
			sample{name: "altcha_challenges_expired_total", typ: "counter", value: float64(m.challengesLapsed.Load()),
				help: "Challenges dropped unsolved because their TTL lapsed."},
			// Each mint is a KDF pass on an endpoint that cannot be authenticated,
			// so this is the work rate an abuser would be trying to drive up. Without
			// it a flood is invisible: challenges_served counts page renders, and an
			// attacker driving mints never asks for the page.
			sample{name: "altcha_challenges_minted_total", typ: "counter", value: float64(m.challengesMinted.Load()),
				help: "Challenges derived. A cached re-issue to the same address does not count."},
		)
	}
	return render(out)
}

// render emits the exposition text, with each metric's HELP/TYPE printed once
// before its first sample, as the format requires.
func render(samples []sample) string {
	var sb strings.Builder
	seen := map[string]bool{}
	for _, s := range samples {
		full := metricPrefix + s.name
		if !seen[full] {
			seen[full] = true
			if s.help != "" {
				fmt.Fprintf(&sb, "# HELP %s %s\n", full, s.help)
			}
			fmt.Fprintf(&sb, "# TYPE %s %s\n", full, s.typ)
		}
		sb.WriteString(full)
		if len(s.labels) > 0 {
			keys := make([]string, 0, len(s.labels))
			for k := range s.labels {
				keys = append(keys, k)
			}
			sort.Strings(keys) // stable output, so a diff of two scrapes is readable
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s=%q", k, s.labels[k]))
			}
			sb.WriteString("{" + strings.Join(parts, ",") + "}")
		}
		fmt.Fprintf(&sb, " %g\n", s.value)
	}
	return sb.String()
}
