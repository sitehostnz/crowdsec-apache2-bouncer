package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		onlyBan:              true,
		requestTimeout:       2 * time.Second,
		streamRequestTimeout: 5 * time.Second,
		mapType:              "txt",
	}
	cfg.dbmFile = defaultDBMPath(cfg.outputFile)
	if mutate != nil {
		mutate(cfg)
	}
	b, err := newBouncer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dec(id, scope, value, typ string) decision {
	return decision{ID: json.Number(id), Scope: scope, Value: value, Type: typ}
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
				if _, ok := got[ip]; !ok {
					t.Fatalf("missing %q in %v", ip, got)
				}
			}
		})
	}
}

func TestIncludedFiltersType(t *testing.T) {
	b := testBouncer(t, nil)
	if b.included(dec("1", "Ip", "9.9.9.9", "captcha")) {
		t.Error("captcha should be excluded with ONLY_BAN")
	}
	if !b.included(dec("1", "Ip", "9.9.9.9", "BAN")) {
		t.Error("type match should be case-insensitive")
	}
	b2 := testBouncer(t, func(c *config) { c.onlyBan = false })
	if !b2.included(dec("1", "Ip", "9.9.9.9", "captcha")) {
		t.Error("captcha should be included with ONLY_BAN=false")
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
	if len(b.refcount) != 5 {
		t.Fatalf("want 5 ips after full sync, got %d: %v", len(b.refcount), b.refcount)
	}

	// second decision bans the same IP -> refcount 2, but NO new IP appears
	added, removed = b.applyDelta([]decision{dec("7", "Ip", "203.0.113.9", "ban")}, nil)
	if added != 0 || removed != 0 {
		t.Fatalf("overlap add counts = +%d/-%d, want +0/-0 (presence unchanged)", added, removed)
	}
	if b.refcount["203.0.113.9"] != 2 {
		t.Fatalf("refcount = %d, want 2", b.refcount["203.0.113.9"])
	}

	// delete decision 1 -> IP must SURVIVE (still held by 7); delete 2 -> the
	// range's 4 IPs disappear -> exactly 4 removed
	added, removed = b.applyDelta(nil, []decision{
		dec("1", "Ip", "203.0.113.9", "ban"),
		dec("2", "Range", "10.0.0.0/30", "ban"),
	})
	if added != 0 || removed != 4 {
		t.Fatalf("delete counts = +%d/-%d, want +0/-4", added, removed)
	}
	if _, ok := b.refcount["203.0.113.9"]; !ok {
		t.Fatal("203.0.113.9 dropped while still held by decision 7")
	}
	if _, ok := b.refcount["10.0.0.1"]; ok {
		t.Fatal("range ip survived its decision's deletion")
	}

	// deleting an unknown decision is a no-op
	if added, removed = b.applyDelta(nil, []decision{dec("999", "Ip", "8.8.8.8", "ban")}); added != 0 || removed != 0 {
		t.Fatalf("unknown deletion counts = +%d/-%d, want +0/-0", added, removed)
	}
	// re-adding the same decision unchanged is a no-op
	b.applyDelta([]decision{dec("7", "Ip", "203.0.113.9", "ban")}, nil)
	if b.refcount["203.0.113.9"] != 1 {
		t.Fatalf("duplicate add double-counted: refcount = %d", b.refcount["203.0.113.9"])
	}

	// decision UPDATED in place (same id, new value): old IP out, new IP in
	added, removed = b.applyDelta([]decision{dec("7", "Ip", "198.51.100.7", "ban")}, nil)
	if added != 1 || removed != 1 {
		t.Fatalf("update-in-place counts = +%d/-%d, want +1/-1", added, removed)
	}
	if _, ok := b.refcount["203.0.113.9"]; ok {
		t.Fatal("old value survived an in-place decision update")
	}
	if _, ok := b.refcount["198.51.100.7"]; !ok {
		t.Fatal("new value missing after in-place decision update")
	}
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
