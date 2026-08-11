package main

import (
	"strings"
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
