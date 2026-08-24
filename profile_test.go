package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Benchmarks are sized to a large list rather than a toy one, because the costs
// that matter here only appear at scale: ~120k IPs held between polls, each poll
// changing a handful of decisions, plus the occasional bulk blocklist import
// landing on top of it in one go.
const (
	steadyIPs = 120_000
	bulkIPs   = 80_000
)

// ---- benchmark fixtures ------------------------------------------------------

// benchBouncer mirrors testBouncer for benchmarks (b.TempDir, no *testing.T).
func benchBouncer(b *testing.B) *bouncer {
	b.Helper()
	cfg := &config{
		lapiURL:              "http://127.0.0.1:8080",
		apiKey:               "bench",
		outputFile:           filepath.Join(b.TempDir(), "blocklist.txt"),
		updateFrequency:      30 * time.Second,
		expandMaxHosts:       65536,
		remediations:         []string{"ban"},
		requestTimeout:       2 * time.Second,
		streamRequestTimeout: 5 * time.Second,
		mapType:              "txt",
	}
	cfg.dbmFile = defaultDBMPath(cfg.outputFile)
	bo, err := newBouncer(cfg)
	if err != nil {
		b.Fatal(err)
	}
	return bo
}

// ipAt returns a deterministic, distinct IPv4 for index i (up to ~16M).
func ipAt(i int) string {
	return netip.AddrFrom4([4]byte{byte(10 + i>>24), byte(i >> 16), byte(i >> 8), byte(i)}).String()
}

// ipDecisions builds n single-IP ban decisions starting at index offset, as a
// LAPI snapshot or a bulk blocklist import would.
func ipDecisions(n, offset int) []decision {
	ds := make([]decision, n)
	for i := range ds {
		ds[i] = decision{
			ID:    json.Number(strconv.Itoa(offset + i)),
			Scope: "ip",
			Value: ipAt(offset + i),
			Type:  "ban",
		}
	}
	return ds
}

// rangeDecisions builds n /24 range ban decisions (256 IPs each).
func rangeDecisions(n, idOffset int) []decision {
	ds := make([]decision, n)
	for i := range ds {
		ds[i] = decision{
			ID:    json.Number(strconv.Itoa(idOffset + i)),
			Scope: "range",
			Value: netip.AddrFrom4([4]byte{172, byte(i >> 8), byte(i), 0}).String() + "/24",
			Type:  "ban",
		}
	}
	return ds
}

// ---- expand: per-decision cost ----------------------------------------------

func BenchmarkExpandIP(b *testing.B) {
	bo := benchBouncer(b)
	d := decision{ID: "1", Scope: "ip", Value: "192.0.2.10", Type: "ban"}
	b.ReportAllocs()
	for b.Loop() {
		bo.expand(d)
	}
}

func BenchmarkExpandRange(b *testing.B) {
	for _, tc := range []struct {
		name  string
		cidr  string
		hosts int
	}{
		{"/28_16ips", "192.0.2.0/28", 16},
		{"/24_256ips", "192.0.2.0/24", 256},
		{"/20_4096ips", "192.0.0.0/20", 4096},
		{"/16_65536ips", "192.0.0.0/16", 65536},
	} {
		b.Run(tc.name, func(b *testing.B) {
			bo := benchBouncer(b)
			d := decision{ID: "1", Scope: "range", Value: tc.cidr, Type: "ban"}
			b.ReportAllocs()
			for b.Loop() {
				bo.expand(d)
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*tc.hosts), "ns/ip")
		})
	}
}

// ---- applyFull: startup, and the periodic resync -----------------------------

func BenchmarkApplyFull(b *testing.B) {
	for _, n := range []int{steadyIPs, steadyIPs + bulkIPs} {
		b.Run(strconv.Itoa(n/1000)+"k_ip_decisions", func(b *testing.B) {
			bo := benchBouncer(b)
			ds := ipDecisions(n, 0)
			b.ReportAllocs()
			for b.Loop() {
				bo.applyFull(ds)
			}
		})
	}
	// same IP count, but sourced from /24 ranges instead of single IPs
	b.Run("120k_ips_as_469_slash24", func(b *testing.B) {
		bo := benchBouncer(b)
		ds := rangeDecisions(469, 1_000_000)
		b.ReportAllocs()
		for b.Loop() {
			bo.applyFull(ds)
		}
	})
}

// ---- applyDelta: the routine poll path ---------------------------------------

// BenchmarkApplyDeltaSmall is the dominant case by frequency: a large list where
// only a handful of decisions change on any given poll, all day long.
func BenchmarkApplyDeltaSmall(b *testing.B) {
	for _, churn := range []int{1, 10, 100} {
		b.Run(strconv.Itoa(churn)+"_changed_of_120k", func(b *testing.B) {
			bo := benchBouncer(b)
			bo.applyFull(ipDecisions(steadyIPs, 0))
			churned := ipDecisions(churn, 9_000_000)
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if i%2 == 0 {
					bo.applyDelta(churned, nil)
				} else {
					bo.applyDelta(nil, churned)
				}
				i++
			}
		})
	}
}

// BenchmarkApplyDeltaBulk is a bulk blocklist import: 80k new decisions arriving
// in a single delta on top of an already-large list.
func BenchmarkApplyDeltaBulk(b *testing.B) {
	bo := benchBouncer(b)
	base := ipDecisions(steadyIPs, 0)
	bulk := ipDecisions(bulkIPs, 5_000_000)
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		bo.applyFull(base)
		b.StartTimer()
		bo.applyDelta(bulk, nil)
	}
}

// ---- writeTxt: rendered on every change --------------------------------------

func BenchmarkWriteTxt(b *testing.B) {
	for _, n := range []int{steadyIPs, steadyIPs + bulkIPs} {
		b.Run(strconv.Itoa(n/1000)+"k_ips", func(b *testing.B) {
			bo := benchBouncer(b)
			bo.applyFull(ipDecisions(n, 0))
			b.ReportAllocs()
			for b.Loop() {
				if err := bo.writeTxt(banSet(bo)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---- the whole poll cycle: delta + rewrite -----------------------------------

// BenchmarkPollCycle is one complete tick at scale: apply a small delta to a
// large list, then re-render the map file (the DBM build is excluded - that's an
// httxt2dbm subprocess).
func BenchmarkPollCycle(b *testing.B) {
	bo := benchBouncer(b)
	bo.applyFull(ipDecisions(steadyIPs, 0))
	churned := ipDecisions(10, 9_000_000)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		var added, removed int
		if i%2 == 0 {
			added, removed = bo.applyDelta(churned, nil)
		} else {
			added, removed = bo.applyDelta(nil, churned)
		}
		if added > 0 || removed > 0 {
			if err := bo.writeTxt(banSet(bo)); err != nil {
				b.Fatal(err)
			}
		}
		i++
	}
}

// ---- stream decode: the LAPI response parse ----------------------------------

func BenchmarkDecodeStream(b *testing.B) {
	for _, n := range []int{steadyIPs, steadyIPs + bulkIPs} {
		b.Run(strconv.Itoa(n/1000)+"k_decisions", func(b *testing.B) {
			body, err := json.Marshal(streamResponse{New: ipDecisions(n, 0)})
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				var sr streamResponse
				if err := json.NewDecoder(io.LimitReader(bytes.NewReader(body), maxStreamBytes)).Decode(&sr); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---- challenge listener: per-request costs -------------------------------------

// The poll-path benchmarks above are paced by UPDATE_FREQUENCY; these are paced by
// whoever Apache sends over, which is why they exist. A challenged client - or a
// flood pretending to be many of them - drives each of these directly.

// benchChallenge builds a challenge server at the shipped ALTCHA defaults, so the
// numbers describe the configuration people actually run.
func benchChallenge(b *testing.B) *challengeServer {
	b.Helper()
	cfg := &config{
		captchaListen:     "127.0.0.1:0",
		captchaPath:       "/crowdsec-verify",
		captchaWidgetJS:   altchaDefaultWidgetJS,
		captchaWidgetSRI:  altchaDefaultWidgetSRI,
		captchaTokenField: "altcha",
		captchaPassFile:   filepath.Join(b.TempDir(), "captcha_passed.txt"),
		captchaPassTTL:    time.Hour,
		altchaAlgorithm:   altchaDefaultAlgorithm,
		altchaCost:        altchaDefaultCost,
		altchaComplexity:  altchaDefaultComplexity,
	}
	srv, err := newChallengeServer(cfg, newPassStore(cfg.captchaPassFile, cfg.captchaPassTTL), newMetrics())
	if err != nil {
		b.Fatal(err)
	}
	return srv
}

// discardResponseWriter swallows the response, so the handler benchmarks measure
// the daemon's work rather than httptest's response recording.
type discardResponseWriter struct{ h http.Header }

func (d *discardResponseWriter) Header() http.Header {
	if d.h == nil {
		d.h = http.Header{}
	}
	return d.h
}
func (d *discardResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (d *discardResponseWriter) WriteHeader(int)             {}

// BenchmarkAltchaMint is the KDF pass behind issuing one challenge - the work an
// unauthenticated GET can demand of the daemon, and the reason issuance is cached
// per address and bounded by mintTokens. One sub-benchmark per algorithm family:
// the two spend their cost completely differently (see altchaAlgorithms).
func BenchmarkAltchaMint(b *testing.B) {
	now := time.Now()
	for _, alg := range []string{"PBKDF2/SHA-256", "SHA-256"} {
		b.Run(strings.ReplaceAll(alg, "/", "_"), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := newAltchaChallenge(alg, altchaDefaultCost, altchaDefaultComplexity, now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkChallengeFetch is GET /altcha-challenge through the real handler.
// cold_per_ip is a flood's shape - every request a fresh address, every response a
// mint; warm_reissue is a reload - the same address asks again and gets the
// challenge it already holds.
func BenchmarkChallengeFetch(b *testing.B) {
	newReq := func(ip string) *http.Request {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, altchaChallengePath, nil)
		req.Header.Set("X-Forwarded-For", ip)
		return req
	}
	b.Run("cold_per_ip", func(b *testing.B) {
		srv := benchChallenge(b)
		w := &discardResponseWriter{}
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			srv.altchaChallenge(w, newReq(ipAt(i)))
			i++
		}
	})
	b.Run("warm_reissue", func(b *testing.B) {
		srv := benchChallenge(b)
		w := &discardResponseWriter{}
		req := newReq("203.0.113.9")
		srv.altchaChallenge(w, req) // mint once; every iteration below re-issues it
		b.ReportAllocs()
		for b.Loop() {
			srv.altchaChallenge(w, req)
		}
	})
}

// BenchmarkChallengePage renders the challenge page - the response every
// challenged GET gets until its owner solves, and what a failed solve re-renders
// with an error.
func BenchmarkChallengePage(b *testing.B) {
	srv := benchChallenge(b)
	w := &discardResponseWriter{}
	b.ReportAllocs()
	for b.Loop() {
		srv.render(w, http.StatusOK, "/checkout", "")
	}
}

// BenchmarkSolveVerify is the verification half of a solve: decode the submitted
// payload and check it against the outstanding challenge. The pass-map write that
// follows a success is measured separately in BenchmarkPassPublish. Cost 1,
// because verification is a comparison - its cost does not depend on the work
// dial, and grinding a cost-5000 solve here would benchmark the test suite.
func BenchmarkSolveVerify(b *testing.B) {
	srv := benchChallenge(b)
	now := time.Now()
	const ip = "203.0.113.9"
	ch, err := srv.altcha.challengeFor(ip, altchaDefaultAlgorithm, 1, 2000, now)
	if err != nil {
		b.Fatal(err)
	}
	key, ok := solveAltcha(ch, 2000)
	if !ok {
		b.Fatal("could not solve the benchmark's own challenge")
	}
	payload := encodeAltchaPayload(key)
	b.ReportAllocs()
	for b.Loop() {
		got, err := parseAltchaPayload(payload)
		if err != nil {
			b.Fatal(err)
		}
		e, err := srv.altcha.redeem(ip, got, now)
		if err != nil {
			b.Fatal(err)
		}
		srv.altcha.restore(ip, e, now) // put it back so the next iteration can spend it again
	}
}

// BenchmarkPassPublish is what recording one verified solve costs: the whole pass
// map is rendered and atomically replaced, so the cost scales with the passes
// currently held, not with the one being added.
func BenchmarkPassPublish(b *testing.B) {
	for _, held := range []int{1, 1_000, 10_000} {
		b.Run(strconv.Itoa(held)+"_held", func(b *testing.B) {
			p := newPassStore(filepath.Join(b.TempDir(), "captcha_passed.txt"), time.Hour)
			now := time.Now()
			for i := 0; i < held; i++ {
				p.passes[ipAt(i)] = now.Add(time.Hour) // prefill without a write per entry
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := p.add("203.0.113.9", now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// altchaSink keeps the filled store reachable, for the same reason sink does.
var altchaSink *altchaStore

// BenchmarkAltchaHeapAtCap fills the challenge store to altchaMaxLive - the flood
// ceiling - and reports the live heap that pins: the worst case a challenge flood
// adds on top of the list itself, and the number altchaMaxLive's own comment
// promises. Cost 1 - entry size does not depend on the work dial.
func BenchmarkAltchaHeapAtCap(b *testing.B) {
	now := time.Now()
	for b.Loop() {
		altchaSink = nil
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		s := newAltchaStore()
		for i := 0; i < altchaMaxLive; i++ {
			if _, err := s.challengeFor(ipAt(i), altchaDefaultAlgorithm, 1, 2000, now); err != nil {
				b.Fatal(err)
			}
		}
		altchaSink = s
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/float64(altchaMaxLive), "B/challenge")
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), "MiB_at_cap")
	}
}

// ---- resident footprint ------------------------------------------------------

// sink keeps the measured bouncer reachable so -memprofile's inuse_space sample
// shows the retained structure rather than a post-GC empty heap.
var sink *bouncer

// BenchmarkHeapPerIP reports the live heap held by the list itself - what drives
// the daemon's memory use. The two "as_slash24" cases carry the same number of IPs
// from far fewer decisions, which isolates the per-decision overhead from the
// per-IP overhead.
func BenchmarkHeapPerIP(b *testing.B) {
	for _, tc := range []struct {
		name string
		ips  int
		ds   []decision
	}{
		{"120k_ips_120k_decisions", steadyIPs, ipDecisions(steadyIPs, 0)},
		{"200k_ips_200k_decisions", steadyIPs + bulkIPs, ipDecisions(steadyIPs+bulkIPs, 0)},
		{"120k_ips_469_decisions", 469 * 256, rangeDecisions(469, 1_000_000)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			for b.Loop() {
				sink = nil
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				bo := benchBouncer(b)
				bo.applyFull(tc.ds)
				sink = bo
				runtime.GC()
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/float64(tc.ips), "B/ip")
				b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), "MiB_live")
			}
		})
	}
}
