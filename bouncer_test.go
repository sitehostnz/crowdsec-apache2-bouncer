package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testBouncer(t *testing.T, mutate func(*config)) *bouncer {
	t.Helper()
	cfg := &config{
		lapiURL:              "http://127.0.0.1:8080",
		apiKey:               "test",
		outputFile:           filepath.Join(t.TempDir(), "blocklist.txt"),
		updateFrequency:      time.Second,
		expandMaxHosts:       65536,
		bouncingOnType:       remediationBan,
		fallbackRemediation:  remediationBan,
		requestTimeout:       2 * time.Second,
		streamRequestTimeout: 5 * time.Second,
		mapType:              "txt",
	}
	cfg.dbmFile = defaultDBMPath(cfg.outputFile)
	// Beside the ban map, the way loadConfig derives it. Left empty, startChallenge
	// still builds the pass store, writeLocked does CreateTemp(".") in the package
	// directory and then fails to rename to "" - so every test that drives run wrote
	// into the repo working directory and logged a pass-map failure that had nothing
	// to do with what it was testing.
	cfg.captchaPassFile = filepath.Join(filepath.Dir(cfg.outputFile), "captcha_passed.txt")
	cfg.captchaPassTTL = time.Hour
	if mutate != nil {
		mutate(cfg)
	}
	// Derived the way loadConfig derives it, so a test can never configure a
	// policy that routes decisions to a map the bouncer never built.
	cfg.remediations = cfg.mapsNeeded()
	b, err := newBouncer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dec(id, scope, value, typ string) decision {
	return decision{ID: json.Number(id), Scope: scope, Value: value, Type: typ}
}

// banSet is the ban remediation's IP set - the one nearly every test works with.
func banSet(b *bouncer) *remediation { return b.setFor("ban") }

// assertSortedInStep checks the invariant the incrementally maintained sortedIPs
// rests on: it must hold exactly the refcount keyset, in order. Everything the
// daemon writes to disk comes off this slice, so if it drifts from refcount the
// map silently stops matching the decisions. Every remediation is checked, not
// just the ban one, because each maintains its own slice independently.
func assertSortedInStep(t *testing.T, b *bouncer) {
	t.Helper()
	for _, r := range b.remediations {
		if len(r.sortedIPs) != len(r.refcount) {
			t.Fatalf("%s: sortedIPs has %d entries, refcount has %d", r.name, len(r.sortedIPs), len(r.refcount))
		}
		if !slices.IsSorted(r.sortedIPs) {
			t.Fatalf("%s: sortedIPs is not in order: %v", r.name, r.sortedIPs)
		}
		for _, ip := range r.sortedIPs {
			if _, ok := r.refcount[ip]; !ok {
				t.Fatalf("%s: sortedIPs holds %q, which is not in refcount", r.name, ip)
			}
		}
	}
}

// ---- expand: canonicalisation + CIDR ----------------------------------------

func TestExpand(t *testing.T) {
	b := testBouncer(t, nil)
	cases := []struct {
		name  string
		d     decision
		want  []string
		empty bool
	}{
		{"plain v4", dec("1", "Ip", "203.0.113.9", "ban"), []string{"203.0.113.9"}, false},
		{"v4-mapped unwrapped", dec("2", "Ip", "::ffff:118.148.160.59", "ban"), []string{"118.148.160.59"}, false},
		{"v6 canonical", dec("3", "Ip", "2001:db8::1", "ban"), []string{"2001:db8::1"}, false},
		{"v6 expanded form -> canonical", dec("4", "Ip", "2001:0DB8:0000:0000:0000:0000:0000:0001", "ban"), []string{"2001:db8::1"}, false},
		{"v4 /30 expands", dec("5", "Range", "10.0.0.0/30", "ban"),
			[]string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}, false},
		{"host bits masked", dec("6", "Range", "10.0.0.3/30", "ban"),
			[]string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}, false},
		{"tiny v6 range expands", dec("7", "Range", "2001:db8:abcd::/126", "ban"),
			[]string{"2001:db8:abcd::", "2001:db8:abcd::1", "2001:db8:abcd::2", "2001:db8:abcd::3"}, false},
		{"v4 /8 skipped (over cap)", dec("8", "Range", "11.0.0.0/8", "ban"), nil, true},
		{"v6 /64 skipped", dec("9", "Range", "2001:db8::/64", "ban"), nil, true},
		{"invalid range skipped", dec("10", "Range", "not-a-range", "ban"), nil, true},
		{"country scope skipped", dec("11", "Country", "CN", "ban"), nil, true},
		{"invalid ip skipped", dec("12", "Ip", "not-an-ip", "ban"), nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := b.expand(c.d)
			if c.empty {
				if len(got) != 0 {
					t.Fatalf("want empty, got %v", got)
				}
				return
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %d ips %v, want %d", len(got), got, len(c.want))
			}
			for _, ip := range c.want {
				if !slices.Contains(got, ip) {
					t.Fatalf("missing %q in %v", ip, got)
				}
			}
		})
	}
}

func TestIncludedFiltersType(t *testing.T) {
	b := testBouncer(t, nil)
	if b.included(dec("1", "Ip", "9.9.9.9", "captcha")) {
		t.Error("captcha should be excluded when only ban has a map")
	}
	if !b.included(dec("1", "Ip", "9.9.9.9", "BAN")) {
		t.Error("type match should be case-insensitive")
	}
	if b.included(dec("1", "Country", "NZ", "ban")) {
		t.Error("a country-scoped decision cannot become map keys")
	}
	b2 := testBouncer(t, func(c *config) { c.bouncingOnType = bouncingAll; c.captchaListen = "127.0.0.1:0" })
	if !b2.included(dec("1", "Ip", "9.9.9.9", "captcha")) {
		t.Error("captcha should be included once it has a map of its own")
	}
	// throttle has no RewriteMap expression, so with a fallback set it degrades to
	// that rather than being dropped - the nginx bouncer's behaviour.
	if !b2.included(dec("1", "Ip", "9.9.9.9", "throttle")) {
		t.Error("throttle should degrade to FALLBACK_REMEDIATION, not be ignored")
	}
	b3 := testBouncer(t, func(c *config) { c.bouncingOnType = bouncingAll; c.fallbackRemediation = "" })
	if b3.included(dec("1", "Ip", "9.9.9.9", "throttle")) {
		t.Error("with no fallback, an unexpressible remediation must be dropped")
	}
}

// ---- per-remediation routing --------------------------------------------------

// TestRemediationsAreSeparateSets is the property the whole split exists for: a
// captcha decision must never reach the ban map, or Apache would 403 a client
// the hub only wanted challenged.
func TestRemediationsAreSeparateSets(t *testing.T) {
	b := testBouncer(t, func(c *config) { c.bouncingOnType = bouncingAll; c.captchaListen = "127.0.0.1:0" })
	b.applyFull([]decision{
		dec("1", "Ip", "203.0.113.9", "ban"),
		dec("2", "Ip", "198.51.100.4", "captcha"),
	})
	ban, captcha := b.setFor("ban"), b.setFor("captcha")
	if _, ok := ban.refcount["198.51.100.4"]; ok {
		t.Fatal("a captcha decision leaked into the ban map - it would be blocked, not challenged")
	}
	if _, ok := captcha.refcount["198.51.100.4"]; !ok {
		t.Fatal("captcha decision missing from the captcha map")
	}
	if _, ok := ban.refcount["203.0.113.9"]; !ok {
		t.Fatal("ban decision missing from the ban map")
	}
	assertSortedInStep(t, b)

	// The same IP can hold both at once, and each expires on its own schedule.
	b.applyDelta([]decision{dec("3", "Ip", "203.0.113.9", "captcha")}, nil)
	if _, ok := captcha.refcount["203.0.113.9"]; !ok {
		t.Fatal("an IP must be able to hold a ban and a captcha at the same time")
	}
	b.applyDelta(nil, []decision{dec("1", "Ip", "203.0.113.9", "ban")})
	if _, ok := ban.refcount["203.0.113.9"]; ok {
		t.Fatal("ban expired but survived in the ban map")
	}
	if _, ok := captcha.refcount["203.0.113.9"]; !ok {
		t.Fatal("expiring the ban must not take the independent captcha with it")
	}
	assertSortedInStep(t, b)
}

// TestDecisionChangingTypeMovesMaps covers the case a per-id map alone would get
// wrong: the hub escalates a captcha to a ban under the SAME decision id, so the
// IP has to leave the captcha map as it enters the ban one. Left in both, it
// would be challenged and blocked at once.
func TestDecisionChangingTypeMovesMaps(t *testing.T) {
	b := testBouncer(t, func(c *config) { c.bouncingOnType = bouncingAll; c.captchaListen = "127.0.0.1:0" })
	b.applyFull([]decision{dec("1", "Ip", "203.0.113.9", "captcha")})
	ban, captcha := b.setFor("ban"), b.setFor("captcha")
	if _, ok := captcha.refcount["203.0.113.9"]; !ok {
		t.Fatal("captcha decision missing before the escalation")
	}

	b.applyDelta([]decision{dec("1", "Ip", "203.0.113.9", "ban")}, nil)
	if _, ok := captcha.refcount["203.0.113.9"]; ok {
		t.Fatal("escalated decision left behind in the captcha map")
	}
	if _, ok := ban.refcount["203.0.113.9"]; !ok {
		t.Fatal("escalated decision never arrived in the ban map")
	}
	assertSortedInStep(t, b)

	// ...and deleting it by id clears it wherever it ended up.
	b.applyDelta(nil, []decision{dec("1", "Ip", "203.0.113.9", "ban")})
	if len(ban.refcount)+len(captcha.refcount) != 0 {
		t.Fatalf("deletion left entries behind: ban=%v captcha=%v", ban.refcount, captcha.refcount)
	}
}

// TestOverrideRemediation covers the "challenge everything" policy: with
// OVERRIDE_REMEDIATION=captcha a ban decision has to render into the captcha map, so
// Apache challenges it instead of blocking it.
func TestOverrideRemediation(t *testing.T) {
	t.Run("captcha absorbs bans", func(t *testing.T) {
		b := testBouncer(t, func(c *config) {
			c.bouncingOnType = bouncingAll
			c.overrideRemediation = remediationCaptcha
			c.captchaListen = "127.0.0.1:0"
		})
		b.applyFull([]decision{
			dec("1", "Ip", "203.0.113.9", "ban"),
			dec("2", "Ip", "198.51.100.4", "captcha"),
			dec("3", "Ip", "198.51.100.5", "throttle"),
		})
		ban, captcha := b.setFor("ban"), b.setFor("captcha")
		if ban != captcha {
			t.Fatal("with OVERRIDE_REMEDIATION every type must resolve to the one set")
		}
		if len(captcha.refcount) != 3 {
			t.Fatalf("captcha map = %v, want every bounced decision", captcha.refcount)
		}
		// No ban map is even built: nothing can resolve to it, so writing an empty
		// file Apache would consult on every request would be pure waste.
		if b.byType[remediationBan] != nil {
			t.Fatal("a ban map was built although nothing can route to it")
		}
		// An override replaces whatever the hub asked for, including a remediation
		// this bouncer could not otherwise express - the nginx bouncer applies the
		// override to every bounced decision, and BOUNCING_ON_TYPE=all bounces on
		// throttle too.
		if _, ok := captcha.refcount["198.51.100.5"]; !ok {
			t.Fatal("throttle should have been absorbed by the override")
		}
		assertSortedInStep(t, b)
	})

	t.Run("ban absorbs captchas", func(t *testing.T) {
		b := testBouncer(t, func(c *config) {
			c.bouncingOnType = bouncingAll
			c.overrideRemediation = remediationBan
		})
		b.applyFull([]decision{dec("1", "Ip", "198.51.100.4", "captcha")})
		if _, ok := b.byType["ban"].refcount["198.51.100.4"]; !ok {
			t.Fatal("OVERRIDE_REMEDIATION=ban must block a captcha decision outright")
		}
	})

	t.Run("a single forced map needs no ban map at all", func(t *testing.T) {
		b := testBouncer(t, func(c *config) {
			c.bouncingOnType = bouncingAll
			c.overrideRemediation = remediationCaptcha
			c.captchaListen = "127.0.0.1:0"
		})
		b.applyFull([]decision{dec("1", "Ip", "203.0.113.9", "ban")})
		if _, ok := b.setFor("ban").refcount["203.0.113.9"]; !ok {
			t.Fatal("a ban decision must still be enforced when it is forced to the only map there is")
		}
	})
}

// TestEachRemediationGetsItsOwnFiles checks the maps land on disk separately and
// that the ban map keeps OUTPUT_FILE, so an existing install's Apache config
// still points at the right file after the upgrade.
func TestEachRemediationGetsItsOwnFiles(t *testing.T) {
	b := testBouncer(t, func(c *config) { c.bouncingOnType = bouncingAll; c.captchaListen = "127.0.0.1:0" })
	b.applyFull([]decision{
		dec("1", "Ip", "203.0.113.9", "ban"),
		dec("2", "Ip", "198.51.100.4", "captcha"),
	})
	if err := b.write(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(b.cfg.outputFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "203.0.113.9 1\n" {
		t.Fatalf("ban map = %q, want only the banned IP", got)
	}
	captchaTxt := filepath.Join(filepath.Dir(b.cfg.outputFile), "captcha.txt")
	if got, err = os.ReadFile(captchaTxt); err != nil {
		t.Fatal(err)
	}
	if string(got) != "198.51.100.4 1\n" {
		t.Fatalf("captcha map = %q, want only the challenged IP", got)
	}
	for _, pattern := range []string{".blocklist.*", ".captcha.*"} {
		if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(b.cfg.outputFile), pattern)); len(leftovers) != 0 {
			t.Fatalf("temp files left behind: %v", leftovers)
		}
	}
}

// ---- refcount + deltas -------------------------------------------------------

func TestRefcountOverlapAndDelta(t *testing.T) {
	b := testBouncer(t, nil)
	added, removed := b.applyFull([]decision{
		dec("1", "Ip", "203.0.113.9", "ban"),
		dec("2", "Range", "10.0.0.0/30", "ban"),
	})
	if added != 5 || removed != 0 {
		t.Fatalf("full sync counts = +%d/-%d, want +5/-0", added, removed)
	}
	if len(banSet(b).refcount) != 5 {
		t.Fatalf("want 5 ips after full sync, got %d: %v", len(banSet(b).refcount), banSet(b).refcount)
	}
	assertSortedInStep(t, b)

	// second decision bans the same IP -> refcount 2, but NO new IP appears
	added, removed = b.applyDelta([]decision{dec("7", "Ip", "203.0.113.9", "ban")}, nil)
	if added != 0 || removed != 0 {
		t.Fatalf("overlap add counts = +%d/-%d, want +0/-0 (presence unchanged)", added, removed)
	}
	if banSet(b).refcount["203.0.113.9"] != 2 {
		t.Fatalf("refcount = %d, want 2", banSet(b).refcount["203.0.113.9"])
	}
	assertSortedInStep(t, b)

	// delete decision 1 -> IP must SURVIVE (still held by 7); delete 2 -> the
	// range's 4 IPs disappear -> exactly 4 removed
	added, removed = b.applyDelta(nil, []decision{
		dec("1", "Ip", "203.0.113.9", "ban"),
		dec("2", "Range", "10.0.0.0/30", "ban"),
	})
	if added != 0 || removed != 4 {
		t.Fatalf("delete counts = +%d/-%d, want +0/-4", added, removed)
	}
	if _, ok := banSet(b).refcount["203.0.113.9"]; !ok {
		t.Fatal("203.0.113.9 dropped while still held by decision 7")
	}
	if _, ok := banSet(b).refcount["10.0.0.1"]; ok {
		t.Fatal("range ip survived its decision's deletion")
	}
	assertSortedInStep(t, b)

	// deleting an unknown decision is a no-op
	if added, removed = b.applyDelta(nil, []decision{dec("999", "Ip", "8.8.8.8", "ban")}); added != 0 || removed != 0 {
		t.Fatalf("unknown deletion counts = +%d/-%d, want +0/-0", added, removed)
	}
	// re-adding the same decision unchanged is a no-op
	b.applyDelta([]decision{dec("7", "Ip", "203.0.113.9", "ban")}, nil)
	if banSet(b).refcount["203.0.113.9"] != 1 {
		t.Fatalf("duplicate add double-counted: refcount = %d", banSet(b).refcount["203.0.113.9"])
	}

	// decision UPDATED in place (same id, new value): old IP out, new IP in
	added, removed = b.applyDelta([]decision{dec("7", "Ip", "198.51.100.7", "ban")}, nil)
	if added != 1 || removed != 1 {
		t.Fatalf("update-in-place counts = +%d/-%d, want +1/-1", added, removed)
	}
	if _, ok := banSet(b).refcount["203.0.113.9"]; ok {
		t.Fatal("old value survived an in-place decision update")
	}
	if _, ok := banSet(b).refcount["198.51.100.7"]; !ok {
		t.Fatal("new value missing after in-place decision update")
	}
	assertSortedInStep(t, b)
}

func TestApplyFullReportsResyncDiff(t *testing.T) {
	b := testBouncer(t, nil)
	b.applyFull([]decision{
		dec("1", "Ip", "203.0.113.9", "ban"),
		dec("2", "Ip", "198.51.100.1", "ban"),
	})
	// resync: one kept, one gone, one new -> +1/-1
	added, removed := b.applyFull([]decision{
		dec("1", "Ip", "203.0.113.9", "ban"),
		dec("3", "Ip", "192.0.2.3", "ban"),
	})
	if added != 1 || removed != 1 {
		t.Fatalf("resync diff = +%d/-%d, want +1/-1", added, removed)
	}
	assertSortedInStep(t, b)
}

// TestApplyDeltaChurnWithinOneTick covers what the incremental counting has to
// get right and a naive transition counter would not: an IP that leaves one
// decision and arrives under another in the SAME delta never actually left the
// blocklist, so it must net to zero.
func TestApplyDeltaChurnWithinOneTick(t *testing.T) {
	b := testBouncer(t, nil)
	b.applyFull([]decision{dec("1", "Ip", "203.0.113.9", "ban")})

	added, removed := b.applyDelta(
		[]decision{dec("2", "Ip", "203.0.113.9", "ban")},
		[]decision{dec("1", "Ip", "203.0.113.9", "ban")},
	)
	if added != 0 || removed != 0 {
		t.Fatalf("churn within one tick = +%d/-%d, want +0/-0 (presence unchanged)", added, removed)
	}
	if _, ok := banSet(b).refcount["203.0.113.9"]; !ok {
		t.Fatal("203.0.113.9 dropped though decision 2 now holds it")
	}
	assertSortedInStep(t, b)
}

// TestApplyDeltaBulkCrossesResortThreshold exercises settle's rebuild branch: a
// bulk blocklist import is far more than resortThreshold changes, so sortedIPs
// is regenerated with one sort instead of spliced change by change.
func TestApplyDeltaBulkCrossesResortThreshold(t *testing.T) {
	b := testBouncer(t, nil)
	bulk := make([]decision, 0, resortThreshold*2)
	for i := range cap(bulk) {
		bulk = append(bulk, dec(strconv.Itoa(1000+i), "Ip", fmt.Sprintf("10.%d.%d.1", i/256, i%256), "ban"))
	}

	added, removed := b.applyDelta(bulk, nil)
	if added != len(bulk) || removed != 0 {
		t.Fatalf("bulk import = +%d/-%d, want +%d/-0", added, removed, len(bulk))
	}
	assertSortedInStep(t, b)

	added, removed = b.applyDelta(nil, bulk)
	if added != 0 || removed != len(bulk) {
		t.Fatalf("bulk removal = +%d/-%d, want +0/-%d", added, removed, len(bulk))
	}
	assertSortedInStep(t, b)
	if len(banSet(b).sortedIPs) != 0 {
		t.Fatalf("sortedIPs still holds %d entries after removing every decision", len(banSet(b).sortedIPs))
	}
}

// ---- txt output ----------------------------------------------------------------

func TestWriteTxt(t *testing.T) {
	b := testBouncer(t, nil)
	b.applyFull([]decision{
		dec("1", "Ip", "203.0.113.9", "ban"),
		dec("2", "Ip", "::ffff:10.1.1.1", "ban"),
	})
	if err := b.write(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(b.cfg.outputFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "10.1.1.1 1\n203.0.113.9 1\n"
	if string(got) != want {
		t.Fatalf("file = %q, want %q", got, want)
	}
	// no temp files left behind
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(b.cfg.outputFile), ".blocklist.*"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

// ---- DBM build/swap (stub httxt2dbm) --------------------------------------------

func writeStub(t *testing.T, dir, script string) string {
	t.Helper()
	path := filepath.Join(dir, "httxt2dbm")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBuildDBM(t *testing.T) {
	t.Run("single-file backend", func(t *testing.T) {
		dir := t.TempDir()
		stub := writeStub(t, dir, "#!/bin/sh\nwhile [ $# -gt 0 ]; do case $1 in -i) IN=$2; shift 2;; -o) OUT=$2; shift 2;; *) shift;; esac; done\ncp \"$IN\" \"$OUT\"\n")
		b := testBouncer(t, func(c *config) {
			c.mapType = "dbm"
			c.httxt2dbm = stub
			c.outputFile = filepath.Join(dir, "blocklist.txt")
			c.dbmFile = defaultDBMPath(c.outputFile)
		})
		b.applyFull([]decision{dec("1", "Ip", "203.0.113.9", "ban")})
		if err := b.write(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(b.cfg.dbmFile); err != nil {
			t.Fatalf("dbm not created: %v", err)
		}
	})

	t.Run("two-file backend (SDBM)", func(t *testing.T) {
		dir := t.TempDir()
		stub := writeStub(t, dir, "#!/bin/sh\nwhile [ $# -gt 0 ]; do case $1 in -i) IN=$2; shift 2;; -o) OUT=$2; shift 2;; *) shift;; esac; done\ncp \"$IN\" \"$OUT.pag\"; cp \"$IN\" \"$OUT.dir\"\n")
		b := testBouncer(t, func(c *config) {
			c.mapType = "dbm"
			c.httxt2dbm = stub
			c.outputFile = filepath.Join(dir, "blocklist.txt")
			c.dbmFile = defaultDBMPath(c.outputFile)
		})
		b.applyFull([]decision{dec("1", "Ip", "203.0.113.9", "ban")})
		if err := b.write(); err != nil {
			t.Fatal(err)
		}
		for _, suffix := range []string{".pag", ".dir"} {
			if _, err := os.Stat(b.cfg.dbmFile + suffix); err != nil {
				t.Fatalf("dbm%s not created: %v", suffix, err)
			}
		}
		if leftovers, _ := filepath.Glob(b.cfg.dbmFile + ".new*"); len(leftovers) != 0 {
			t.Fatalf("temp dbm files left behind: %v", leftovers)
		}
	})

	t.Run("empty converter output keeps previous dbm", func(t *testing.T) {
		dir := t.TempDir()
		stub := writeStub(t, dir, "#!/bin/sh\nexit 0\n") // succeeds but writes nothing
		b := testBouncer(t, func(c *config) {
			c.mapType = "dbm"
			c.httxt2dbm = stub
			c.outputFile = filepath.Join(dir, "blocklist.txt")
			c.dbmFile = defaultDBMPath(c.outputFile)
		})
		if err := os.WriteFile(b.cfg.dbmFile, []byte("previous"), 0o644); err != nil {
			t.Fatal(err)
		}
		b.applyFull([]decision{dec("1", "Ip", "203.0.113.9", "ban")})
		if err := b.write(); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(b.cfg.dbmFile); string(got) != "previous" {
			t.Fatalf("previous DBM clobbered on empty converter output: %q", got)
		}
	})

	t.Run("stale temp files from a crashed run are cleaned", func(t *testing.T) {
		dir := t.TempDir()
		stub := writeStub(t, dir, "#!/bin/sh\nwhile [ $# -gt 0 ]; do case $1 in -i) IN=$2; shift 2;; -o) OUT=$2; shift 2;; *) shift;; esac; done\ncp \"$IN\" \"$OUT\"\n")
		b := testBouncer(t, func(c *config) {
			c.mapType = "dbm"
			c.httxt2dbm = stub
			c.outputFile = filepath.Join(dir, "blocklist.txt")
			c.dbmFile = defaultDBMPath(c.outputFile)
		})
		// leftovers from a hypothetical earlier crash
		for _, stale := range []string{".new", ".new.pag"} {
			if err := os.WriteFile(b.cfg.dbmFile+stale, []byte("stale"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		b.applyFull([]decision{dec("1", "Ip", "203.0.113.9", "ban")})
		if err := b.write(); err != nil {
			t.Fatal(err)
		}
		leftovers, _ := filepath.Glob(b.cfg.dbmFile + ".new*")
		if len(leftovers) != 0 {
			t.Fatalf("stale temp files not cleaned: %v", leftovers)
		}
	})

	t.Run("failing httxt2dbm keeps previous dbm", func(t *testing.T) {
		dir := t.TempDir()
		stub := writeStub(t, dir, "#!/bin/sh\nexit 1\n")
		b := testBouncer(t, func(c *config) {
			c.mapType = "dbm"
			c.httxt2dbm = stub
			c.outputFile = filepath.Join(dir, "blocklist.txt")
			c.dbmFile = defaultDBMPath(c.outputFile)
		})
		if err := os.WriteFile(b.cfg.dbmFile, []byte("previous"), 0o644); err != nil {
			t.Fatal(err)
		}
		b.applyFull([]decision{dec("1", "Ip", "203.0.113.9", "ban")})
		if err := b.write(); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(b.cfg.dbmFile)
		if string(got) != "previous" {
			t.Fatalf("previous DBM clobbered on converter failure: %q", got)
		}
	})
}

// ---- stream fetch ---------------------------------------------------------------

func TestFetch(t *testing.T) {
	var gotKey, gotStartup string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Api-Key")
		gotStartup = r.URL.Query().Get("startup")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"new":[{"id":42,"scope":"Ip","value":"1.2.3.4","type":"ban"}],"deleted":null}`))
	}))
	defer srv.Close()

	b := testBouncer(t, func(c *config) { c.lapiURL = srv.URL })
	sr, err := b.fetch(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if gotKey != "test" || gotStartup != "true" {
		t.Fatalf("request: key=%q startup=%q", gotKey, gotStartup)
	}
	if len(sr.New) != 1 || sr.New[0].ID.String() != "42" || sr.New[0].Value != "1.2.3.4" {
		t.Fatalf("parsed: %+v", sr.New)
	}
	if len(sr.Deleted) != 0 {
		t.Fatalf("deleted should be empty, got %v", sr.Deleted)
	}

	t.Run("non-200 is an error", func(t *testing.T) {
		srv403 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"message":"access forbidden"}`, http.StatusForbidden)
		}))
		defer srv403.Close()
		b := testBouncer(t, func(c *config) { c.lapiURL = srv403.URL })
		if _, err := b.fetch(context.Background(), false); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("want 403 error, got %v", err)
		}
	})
}

// ---- end-to-end: snapshot then delta through to the file --------------------------

func TestEndToEndFileMaintenance(t *testing.T) {
	b := testBouncer(t, nil)

	// snapshot
	b.applyFull([]decision{
		dec("1", "Ip", "203.0.113.9", "ban"),
		dec("2", "Range", "192.0.2.0/31", "ban"),
	})
	if err := b.write(); err != nil {
		t.Fatal(err)
	}

	// delta: one expires, one arrives
	b.applyDelta(
		[]decision{dec("3", "Ip", "2001:db8::7", "ban")},
		[]decision{dec("1", "Ip", "203.0.113.9", "ban")},
	)
	if err := b.write(); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(b.cfg.outputFile)
	want := "192.0.2.0 1\n192.0.2.1 1\n2001:db8::7 1\n"
	if string(got) != want {
		t.Fatalf("file = %q, want %q", got, want)
	}
}

// ---- full-snapshot shrink guard ------------------------------------------------

// A full snapshot replaces the list wholesale, so a truncated-but-valid 200 would
// unban everything it omits. A large drop has to be confirmed by a second snapshot.
func TestAcceptSnapshot(t *testing.T) {
	held := func(n int) *bouncer {
		b := testBouncer(t, nil)
		for i := range n {
			banSet(b).decisionIPs[strconv.Itoa(i)] = []string{"203.0.113.1"}
		}
		return b
	}

	t.Run("a small list is never second-guessed", func(t *testing.T) {
		b := held(minSnapshotDecisions - 1)
		if !b.acceptSnapshot(0) {
			t.Fatal("below the floor a snapshot must be taken at face value")
		}
	})

	t.Run("a modest shrink is accepted outright", func(t *testing.T) {
		b := held(1000)
		if !b.acceptSnapshot(600) {
			t.Fatal("600 of 1000 is above the limit and should apply immediately")
		}
	})

	t.Run("growth is always accepted", func(t *testing.T) {
		b := held(1000)
		if !b.acceptSnapshot(5000) {
			t.Fatal("a larger snapshot must apply")
		}
	})

	t.Run("an empty snapshot is refused once then confirmed", func(t *testing.T) {
		b := held(1000)
		if b.acceptSnapshot(0) {
			t.Fatal("a snapshot wiping the whole list must not apply on first sight")
		}
		if !b.acceptSnapshot(0) {
			t.Fatal("a second agreeing snapshot means the flush is real - it must apply")
		}
	})

	t.Run("a recovered snapshot clears the pending state", func(t *testing.T) {
		b := held(1000)
		if b.acceptSnapshot(0) {
			t.Fatal("first short snapshot should be refused")
		}
		if !b.acceptSnapshot(1000) { // LAPI recovered
			t.Fatal("a full snapshot must apply")
		}
		// ...so the next short one starts the count again rather than landing.
		if b.acceptSnapshot(0) {
			t.Fatal("pending state should have been reset by the good snapshot")
		}
	})
}
