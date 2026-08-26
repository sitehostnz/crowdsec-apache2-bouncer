package main

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The exposition format is picky in ways a scraper will reject silently: HELP and
// TYPE must appear once per metric NAME, before its first sample, even when
// several samples share that name under different labels.
func TestMetricsExpositionFormat(t *testing.T) {
	b := testBouncer(t, func(c *config) {
		c.bouncingOnType = bouncingAll
		c.captchaListen = "127.0.0.1:0"
	})
	b.metrics.pollsOK.Add(3)
	b.metrics.pollsFailed.Add(1)
	b.metrics.lastPollUnix.Store(1700000000)
	observeDuration(&b.metrics.lastPollSecs, 250*time.Millisecond)
	b.applyFull([]decision{
		dec("1", "Ip", "203.0.113.9", "ban"),
		dec("2", "Ip", "198.51.100.4", "captcha"),
	})

	out := b.renderMetrics()

	for _, want := range []string{
		`crowdsec_apache_bouncer_polls_total{result="ok"} 3`,
		`crowdsec_apache_bouncer_polls_total{result="failed"} 1`,
		`crowdsec_apache_bouncer_last_successful_poll_timestamp_seconds 1.7e+09`,
		`crowdsec_apache_bouncer_poll_duration_seconds 0.25`,
		`crowdsec_apache_bouncer_map_ips{remediation="ban"} 1`,
		`crowdsec_apache_bouncer_map_ips{remediation="captcha"} 1`,
		`# TYPE crowdsec_apache_bouncer_polls_total counter`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing from exposition:\n  %s", want)
		}
	}

	// One TYPE line per metric name, however many samples carry it.
	if n := strings.Count(out, "# TYPE crowdsec_apache_bouncer_polls_total"); n != 1 {
		t.Errorf("TYPE for polls_total appears %d times, want exactly 1", n)
	}
	// Every TYPE must precede its samples.
	for _, name := range []string{"polls_total", "map_ips"} {
		full := metricPrefix + name
		if strings.Index(out, "# TYPE "+full) > strings.Index(out, "\n"+full) {
			t.Errorf("%s: TYPE line comes after the first sample", full)
		}
	}
}

// Captcha metrics only appear when a challenge is configured - exporting solve
// counters that can never move would just be noise on a ban-only box.
func TestMetricsOmitsCaptchaWhenDisabled(t *testing.T) {
	b := testBouncer(t, nil) // ban only, no listener
	out := b.renderMetrics()
	if strings.Contains(out, "challenge_solves_total") {
		t.Error("captcha metrics exported although no challenge is configured")
	}
	if !strings.Contains(out, "map_ips") {
		t.Error("core metrics missing")
	}
}

// A scrape arrives on the metrics listener's goroutine whenever Prometheus feels
// like it, including halfway through an apply. Nothing here asserts a value: the
// assertion is the race detector, which reported renderMetrics against applyDelta
// and remediation.ref before b.state existed. Worth pinning, because the failure
// it grows into is not a torn gauge but a fatal concurrent map iteration the
// moment anyone ranges over refcount to export per-IP data - which takes the
// whole daemon down, enforcement included.
func TestMetricsScrapeDuringApplyIsRaceFree(t *testing.T) {
	b := testBouncer(t, func(c *config) { c.bouncingOnType = bouncingAll })

	const rounds = 200
	var wg sync.WaitGroup
	wg.Add(3)

	// The poll loop, delta path: churn the list so refcount and decisionIPs are
	// being written throughout, and skippedRanges reset on every pass.
	go func() {
		defer wg.Done()
		for i := range rounds {
			d := dec(strconv.Itoa(i), "Ip", "203.0.113.9", "ban")
			b.applyDelta([]decision{d}, nil)
			b.applyDelta(nil, []decision{d})
		}
	}()

	// The resync path, which is the one the mutex comment is actually about:
	// applyFull empties every map before refilling it, so a scrape landing in that
	// window sees a list that is momentarily near-empty. Covered separately because
	// a future edit could drop the lock from applyFull alone and leave the delta
	// path guarded - and the suite would stay green.
	// Alternates a snapshot above minSnapshotIPs with a short one, so half the rounds
	// are refused and the rollback - which writes the same maps the apply does - runs
	// under the detector too. Below the floor the guard short-circuits and it never did.
	go func() {
		defer wg.Done()
		big := append(ipDecisions(minSnapshotIPs+10, 0),
			dec("full-b", "Range", "10.0.0.0/30", "captcha"))
		for i := range rounds {
			if i%2 == 0 {
				b.applyFull(big)
			} else {
				b.applyFull([]decision{dec("full-a", "Ip", "198.51.100."+strconv.Itoa(i%256), "ban")})
			}
		}
	}()

	go func() {
		defer wg.Done()
		for range rounds * 2 {
			_ = b.renderMetrics()
		}
	}()

	wg.Wait()
}

// Gauges are read live rather than mirrored, so they cannot drift from the maps.
func TestMetricsGaugesTrackLiveState(t *testing.T) {
	b := testBouncer(t, nil)
	if !strings.Contains(b.renderMetrics(), `map_ips{remediation="ban"} 0`) {
		t.Fatal("expected an empty ban map to report 0")
	}
	b.applyFull([]decision{dec("1", "Range", "10.0.0.0/30", "ban")})
	if !strings.Contains(b.renderMetrics(), `map_ips{remediation="ban"} 4`) {
		t.Fatal("gauge did not follow the map after a range expanded to 4 addresses")
	}
}

// The counter is only useful if it reaches the scrape, and the sample line sits
// among four near-identical ones reading four different fields - so this pins that
// it reads the right one. Without the assertion a sample wired to challengesMinted
// would pass every other test in the suite.
func TestMetricsCarriesTheChallengeRefusalCounter(t *testing.T) {
	b := testBouncer(t, func(c *config) {
		c.captchaListen = "127.0.0.1:0" // captchaUsable gates the whole altcha block
	})
	b.metrics.challengesRefused.Store(7)

	out := b.renderMetrics()
	for _, want := range []string{
		"# TYPE crowdsec_apache_bouncer_altcha_challenges_refused_total counter",
		"crowdsec_apache_bouncer_altcha_challenges_refused_total 7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition is missing %q", want)
		}
	}
}
