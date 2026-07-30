package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- fetch edge cases --------------------------------------------------------

func TestFetchEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // 200 with empty body = "no changes"
	}))
	defer srv.Close()

	b := testBouncer(t, func(c *config) { c.lapiURL = srv.URL })
	sr, err := b.fetch(context.Background(), false)
	if err != nil {
		t.Fatalf("empty body should not error: %v", err)
	}
	if len(sr.New) != 0 || len(sr.Deleted) != 0 {
		t.Fatalf("want empty response, got %+v", sr)
	}
}

func TestFetchGarbageBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>not json</html>"))
	}))
	defer srv.Close()

	b := testBouncer(t, func(c *config) { c.lapiURL = srv.URL })
	if _, err := b.fetch(context.Background(), false); err == nil {
		t.Fatal("garbage body should error")
	}
}

func TestFetchTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	b := testBouncer(t, func(c *config) {
		c.lapiURL = srv.URL
		c.streamRequestTimeout = 100 * time.Millisecond
	})
	if _, err := b.fetch(context.Background(), false); err == nil {
		t.Fatal("want timeout error")
	}
}

func TestFetchSendsIdentityHeaders(t *testing.T) {
	var ua, accept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua, accept = r.Header.Get("User-Agent"), r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	b := testBouncer(t, func(c *config) { c.lapiURL = srv.URL })
	if _, err := b.fetch(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ua, "crowdsec-apache2-bouncer/") || accept != "application/json" {
		t.Fatalf("headers: UA=%q Accept=%q", ua, accept)
	}
}

// ---- TLS matrix ---------------------------------------------------------------

func TestFetchTLS(t *testing.T) {
	newTLS := func() *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"new":[],"deleted":[]}`))
		}))
	}

	t.Run("untrusted cert fails closed", func(t *testing.T) {
		srv := newTLS()
		defer srv.Close()
		b := testBouncer(t, func(c *config) { c.lapiURL = srv.URL })
		if _, err := b.fetch(context.Background(), false); err == nil {
			t.Fatal("self-signed server must fail without trust config")
		}
	})

	t.Run("CA_BUNDLE trusts the server", func(t *testing.T) {
		srv := newTLS()
		defer srv.Close()
		bundle := filepath.Join(t.TempDir(), "ca.pem")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		if err := os.WriteFile(bundle, pemBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		b := testBouncer(t, func(c *config) {
			c.lapiURL = srv.URL
			c.caBundle = bundle
		})
		if _, err := b.fetch(context.Background(), false); err != nil {
			t.Fatalf("CA_BUNDLE trust failed: %v", err)
		}
	})

	t.Run("INSECURE skips verification", func(t *testing.T) {
		srv := newTLS()
		defer srv.Close()
		b := testBouncer(t, func(c *config) {
			c.lapiURL = srv.URL
			c.insecure = true
		})
		if _, err := b.fetch(context.Background(), false); err != nil {
			t.Fatalf("INSECURE=true should connect: %v", err)
		}
	})
}

// ---- write error path ------------------------------------------------------------

func TestWriteTxtErrorPath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := testBouncer(t, func(c *config) {
		c.outputFile = filepath.Join(blocker, "sub", "blocklist.txt") // parent is a FILE
	})
	b.applyFull([]decision{dec("1", "Ip", "203.0.113.9", "ban")})
	if err := b.write(); err == nil {
		t.Fatal("write into a file-as-directory path must error")
	}
}

// ---- the run() daemon loop --------------------------------------------------------

// scriptedLAPI serves a scripted sequence of responses and records each request's
// startup= parameter, concurrency-safe.
type scriptedLAPI struct {
	mu       sync.Mutex
	n        int
	startups []string
	script   func(call int, w http.ResponseWriter)
}

func (s *scriptedLAPI) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.n++
		call := s.n
		s.startups = append(s.startups, r.URL.Query().Get("startup"))
		s.mu.Unlock()
		s.script(call, w)
	}
}

func (s *scriptedLAPI) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func (s *scriptedLAPI) startup(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.startups) {
		return "<none>"
	}
	return s.startups[i]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRunLifecycle(t *testing.T) {
	lapi := &scriptedLAPI{script: func(call int, w http.ResponseWriter) {
		switch call {
		case 1: // startup attempt 1: LAPI down -> must retry, not crash
			http.Error(w, "starting up", http.StatusServiceUnavailable)
		case 2: // startup retry: full snapshot
			_, _ = fmt.Fprint(w, `{"new":[{"id":1,"scope":"Ip","value":"203.0.113.9","type":"ban"}],"deleted":[]}`)
		case 3: // first delta: A expires, B arrives
			_, _ = fmt.Fprint(w, `{"new":[{"id":2,"scope":"Ip","value":"198.51.100.7","type":"ban"}],"deleted":[{"id":1,"scope":"Ip","value":"203.0.113.9","type":"ban"}]}`)
		default: // then the LAPI goes away -> the list must be KEPT
			http.Error(w, "down", http.StatusBadGateway)
		}
	}}
	srv := httptest.NewServer(lapi.handler())
	defer srv.Close()

	b := testBouncer(t, func(c *config) {
		c.lapiURL = srv.URL
		c.updateFrequency = 25 * time.Millisecond
		c.resyncInterval = 0 // deltas only
	})
	readFile := func() string {
		got, _ := os.ReadFile(b.cfg.outputFile)
		return string(got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.run(ctx); close(done) }()

	// startup survived the 503 and wrote the snapshot
	waitFor(t, "snapshot file", func() bool { return readFile() == "203.0.113.9 1\n" })
	if lapi.startup(1) != "true" {
		t.Errorf("snapshot request startup=%s, want true", lapi.startup(1))
	}

	// delta applied: A out, B in
	waitFor(t, "delta file", func() bool { return readFile() == "198.51.100.7 1\n" })
	if lapi.startup(2) != "false" {
		t.Errorf("delta request startup=%s, want false", lapi.startup(2))
	}

	// LAPI now failing: several polls later the list is untouched (fail-safe)
	calls := lapi.calls()
	waitFor(t, "post-failure polls", func() bool { return lapi.calls() >= calls+3 })
	if got := readFile(); got != "198.51.100.7 1\n" {
		t.Fatalf("list changed while LAPI down: %q", got)
	}

	// clean shutdown
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("run() did not stop on context cancel")
	}
}

func TestRunResync(t *testing.T) {
	lapi := &scriptedLAPI{script: func(_ int, w http.ResponseWriter) {
		_, _ = fmt.Fprint(w, `{"new":[{"id":1,"scope":"Ip","value":"203.0.113.9","type":"ban"}],"deleted":[]}`)
	}}
	srv := httptest.NewServer(lapi.handler())
	defer srv.Close()

	b := testBouncer(t, func(c *config) {
		c.lapiURL = srv.URL
		c.updateFrequency = 25 * time.Millisecond
		c.resyncInterval = time.Millisecond // every poll is due for a full resync
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.run(ctx); close(done) }()

	waitFor(t, "three requests", func() bool { return lapi.calls() >= 3 })
	cancel()
	<-done

	// request 0 is the startup snapshot; 1+ are polls, which must all be resyncs
	for i := 1; i <= 2; i++ {
		if lapi.startup(i) != "true" {
			t.Errorf("poll %d startup=%s, want true (resync)", i, lapi.startup(i))
		}
	}
}
