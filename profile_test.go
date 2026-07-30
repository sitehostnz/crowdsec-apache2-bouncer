package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
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
		onlyBan:              true,
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
				if err := bo.writeTxt(); err != nil {
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
			if err := bo.writeTxt(); err != nil {
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
