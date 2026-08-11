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
	"sync"
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
// what is actually on disk.
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

	// lastPollUnix is the wall-clock time of the last SUCCESSFUL poll. It is the
	// single most useful number here: a daemon can be up, polling and logging
	// happily while the list it serves is hours stale, and nothing else in this
	// set would show it.
	lastPollUnix   atomic.Int64
	lastPollSecs   atomic.Uint64 // float64 bits: duration of the last cycle
	lastVerifySecs atomic.Uint64 // float64 bits: duration of the last siteverify

	startedAt time.Time
	once      sync.Once
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
	ln, err := net.Listen("tcp", b.cfg.metricsListen)
	if err != nil {
		log.Printf("metrics listener not started: %v", err)
		return
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

// renderMetrics builds the whole exposition document. Gauges are read from live
// state at scrape time.
func (b *bouncer) renderMetrics() string {
	m := b.metrics
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

		{name: "ranges_skipped", typ: "gauge", value: float64(b.skippedRanges),
			help: "Range decisions in the last apply too large to expand under EXPAND_MAX_HOSTS."},
	}

	// Per-remediation gauges, read live so they cannot drift from the maps.
	for _, r := range b.remediations {
		out = append(out,
			sample{name: "map_ips", typ: "gauge", value: float64(len(r.refcount)),
				help:   "Addresses currently rendered into each map.",
				labels: map[string]string{"remediation": r.name}},
			sample{name: "map_decisions", typ: "gauge", value: float64(len(r.decisionIPs)),
				help:   "Decisions currently held per remediation. Not the same as addresses: one range is many.",
				labels: map[string]string{"remediation": r.name}},
		)
	}

	if b.cfg.captchaListen != "" {
		held := 0
		if b.passes != nil {
			held = b.passes.held()
		}
		out = append(out,
			sample{name: "challenges_served_total", typ: "counter", value: float64(m.challengesServed.Load()),
				help: "Challenge pages rendered."},
			sample{name: "challenge_solves_total", typ: "counter", value: float64(m.solvesOK.Load()),
				help:   "Solve attempts by outcome. 'errored' means the provider could not be reached or answered badly - watch this one, it is what a misconfigured secret looks like.",
				labels: map[string]string{"result": "ok"}},
			sample{name: "challenge_solves_total", typ: "counter", value: float64(m.solvesRejected.Load()),
				labels: map[string]string{"result": "rejected"}},
			sample{name: "challenge_solves_total", typ: "counter", value: float64(m.solvesErrored.Load()),
				labels: map[string]string{"result": "errored"}},
			sample{name: "captcha_verify_duration_seconds", typ: "gauge", value: loadDuration(&m.lastVerifySecs),
				help: "Round trip of the last server-to-server verification."},
			sample{name: "captcha_passes", typ: "gauge", value: float64(held),
				help: "Solved challenges currently honoured."},
			sample{name: "captcha_passes_expired_total", typ: "counter", value: float64(m.passesExpired.Load()),
				help: "Passes dropped because their TTL lapsed."},
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
