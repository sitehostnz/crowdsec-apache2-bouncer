package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testChallenge builds a challenge server with a stub provider, returning the
// server, the pass store and a counter of how many times the provider was asked.
func testChallenge(t *testing.T, verdict func() (int, string), mutate func(*config)) (*challengeServer, *passStore, *int) {
	t.Helper()
	calls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["secret"] != "s3cret" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-secret"]}`))
			return
		}
		code, payload := verdict()
		w.WriteHeader(code)
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(provider.Close)

	dir := t.TempDir()
	cfg := &config{
		captchaListen:        "127.0.0.1:0",
		captchaPath:          "/crowdsec-verify",
		captchaVerifyURL:     provider.URL,
		captchaSecret:        "s3cret",
		captchaAPIEndpoint:   "https://cap.example/site/",
		captchaWidgetJS:      "https://cap.example/widget.js",
		captchaTokenField:    "cap-token",
		captchaPassFile:      filepath.Join(dir, "captcha_passed.txt"),
		captchaPassTTL:       time.Hour,
		captchaPassKey:       passKeyIP,
		captchaCookieName:    "cs_captcha",
		captchaCookieSecure:  true,
		captchaVerifyTimeout: 2 * time.Second,
	}
	if mutate != nil {
		mutate(cfg)
	}
	store := newPassStore(cfg.captchaPassFile, cfg.captchaPassTTL)
	srv, err := newChallengeServer(cfg, store, newMetrics())
	if err != nil {
		t.Fatal(err)
	}
	return srv, store, &calls
}

func solveRequest(token, back, ip string) *http.Request {
	form := url.Values{"cap-token": {token}, "r": {back}}
	req := httptest.NewRequest(http.MethodPost, "/crowdsec-verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(realIPHeader, ip)
	return req
}

func ok() (int, string) { return http.StatusOK, `{"success":true}` }

func TestChallengeSolveRecordsAPass(t *testing.T) {
	srv, store, calls := testChallenge(t, ok, nil)
	w := httptest.NewRecorder()
	srv.handle(w, solveRequest("tok", "/wp-admin", "203.0.113.9"))

	if w.Code != http.StatusFound {
		t.Fatalf("want a redirect after a good solve, got %d: %s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/wp-admin" {
		t.Fatalf("returned to %q, want the original path", loc)
	}
	if *calls != 1 {
		t.Fatalf("provider asked %d times, want exactly 1", *calls)
	}
	// In ip mode the pass is keyed on the address Apache reported, and it must be
	// on disk in the "<ip> 1" form Apache reads.
	got, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "203.0.113.9 1\n" {
		t.Fatalf("pass map = %q", got)
	}
}

// A provider that says no, or cannot be reached at all, must leave the client
// challenged. Waving them through on error turns a captcha outage into a free
// pass for exactly the traffic the hub flagged.
func TestChallengeFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		verdict func() (int, string)
	}{
		{"provider rejects the token", func() (int, string) {
			return http.StatusOK, `{"success":false,"error-codes":["invalid-input-response"]}`
		}},
		{"provider errors", func() (int, string) { return http.StatusInternalServerError, `nope` }},
		{"provider returns garbage", func() (int, string) { return http.StatusOK, `<html>not json</html>` }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, store, _ := testChallenge(t, c.verdict, nil)
			w := httptest.NewRecorder()
			srv.handle(w, solveRequest("tok", "/", "203.0.113.9"))

			if w.Code == http.StatusFound {
				t.Fatal("client was let through despite the provider not confirming the token")
			}
			if store.held() != 0 {
				t.Fatal("a pass was recorded without a confirmed solve")
			}
		})
	}

	t.Run("provider unreachable", func(t *testing.T) {
		srv, store, _ := testChallenge(t, ok, func(c *config) {
			c.captchaVerifyURL = "http://127.0.0.1:1" // nothing listens here
		})
		w := httptest.NewRecorder()
		srv.handle(w, solveRequest("tok", "/", "203.0.113.9"))
		if w.Code == http.StatusFound || store.held() != 0 {
			t.Fatal("an unreachable provider must not grant a pass")
		}
	})

	t.Run("no token submitted", func(t *testing.T) {
		srv, store, calls := testChallenge(t, ok, nil)
		w := httptest.NewRecorder()
		srv.handle(w, solveRequest("", "/", "203.0.113.9"))
		if w.Code == http.StatusFound || store.held() != 0 {
			t.Fatal("an empty token must not grant a pass")
		}
		if *calls != 0 {
			t.Fatal("an empty token should never reach the provider")
		}
	})
}

// Cap takes the reCAPTCHA field names. Getting this wrong means verification can
// never succeed however correct the secret is, and the failure is opaque: Cap
// answers 400 when it cannot split the value, or 500 when the field is absent
// entirely and its handler dereferences undefined.
func TestChallengeVerifySendsRecaptchaFields(t *testing.T) {
	var got map[string]string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer provider.Close()

	srv, _, _ := testChallenge(t, ok, func(c *config) { c.captchaVerifyURL = provider.URL })
	srv.handle(httptest.NewRecorder(), solveRequest("sitekey:id:solution", "/", "203.0.113.9"))

	if got["response"] != "sitekey:id:solution" {
		t.Fatalf("provider received %v, want the token under \"response\"", got)
	}
	if len(got) != 2 || got["secret"] != "s3cret" {
		t.Fatalf("body was %v, want exactly secret + response", got)
	}
}

// The readiness file is what lets Apache tell "the challenge is down" from "the
// challenge said no". It must appear only after a successful bind: a daemon that
// started but could not listen would otherwise have Apache redirect clients into
// a proxy with nothing behind it, and ErrorDocument turns that 503 into a
// redirect loop.
func TestChallengeReadinessFile(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "run", "challenge.up")

	t.Run("appears while listening, gone afterwards", func(t *testing.T) {
		srv, _, _ := testChallenge(t, ok, func(c *config) {
			c.captchaListen = "127.0.0.1:0"
			c.captchaReadyFile = ready
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { srv.serve(ctx); close(done) }()

		waitFor(t, "the readiness file to appear", func() bool {
			_, err := os.Stat(ready)
			return err == nil
		})
		cancel()
		<-done
		if _, err := os.Stat(ready); !os.IsNotExist(err) {
			t.Fatal("readiness file outlived the listener; Apache would keep redirecting into a dead proxy")
		}
	})

	t.Run("never written when the bind fails", func(t *testing.T) {
		busy, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = busy.Close() }()

		missing := filepath.Join(dir, "run", "not-created.up")
		srv, _, _ := testChallenge(t, ok, func(c *config) {
			c.captchaListen = busy.Addr().String() // already taken
			c.captchaReadyFile = missing
		})
		srv.serve(context.Background()) // returns immediately: cannot bind
		if _, err := os.Stat(missing); !os.IsNotExist(err) {
			t.Fatal("readiness file written despite the listener never binding")
		}
	})
}

// The return target comes from the client, so it must never be usable to bounce
// somebody off this host - the challenge sits on a domain a browser already
// trusts, which is exactly what makes an open redirect there worth having.
func TestSafeReturn(t *testing.T) {
	cases := map[string]string{
		"/wp-admin":                  "/wp-admin",
		"/a/b?c=d&e=f":               "/a/b?c=d&e=f",
		"":                           "/",
		"//evil.example":             "/", // protocol-relative
		`/\evil.example`:             "/", // some browsers normalise this the same way
		"https://evil.example":       "/",
		"http://evil.example":        "/",
		"evil.example":               "/", // no leading slash
		"/ok\r\nSet-Cookie: a=b":     "/", // header injection
		"/ok\nLocation: //elsewhere": "/",
	}
	for raw, want := range cases {
		if got := safeReturn(raw); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestChallengeCookieMode(t *testing.T) {
	srv, store, _ := testChallenge(t, ok, func(c *config) { c.captchaPassKey = passKeyCookie })
	w := httptest.NewRecorder()
	srv.handle(w, solveRequest("tok", "/dashboard", "203.0.113.9"))

	if w.Code != http.StatusFound {
		t.Fatalf("want a redirect, got %d: %s", w.Code, w.Body)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want exactly one cookie, got %v", cookies)
	}
	ck := cookies[0]
	if ck.Name != "cs_captcha" || len(ck.Value) != 32 {
		t.Fatalf("cookie = %s=%q (len %d), want a 32-char token", ck.Name, ck.Value, len(ck.Value))
	}
	if !ck.HttpOnly || !ck.Secure {
		t.Fatalf("cookie must be HttpOnly and Secure: %+v", ck)
	}
	// Lax, not Strict: a pass has to survive a top-level navigation that started
	// on another site, or a client who already solved gets challenged again.
	if ck.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax", ck.SameSite)
	}
	// The pass is keyed on the token, NOT on the address - that is the whole point
	// of cookie mode, and it is why the client's IP stops being load-bearing.
	got, _ := os.ReadFile(store.path)
	if strings.Contains(string(got), "203.0.113.9") {
		t.Fatalf("cookie mode recorded the address instead of the token: %q", got)
	}
	if strings.TrimSpace(string(got)) != ck.Value+" 1" {
		t.Fatalf("pass map = %q, want the cookie token", got)
	}

	// Two solves from one address must mint two distinct tokens, or the "per
	// browser" claim is false.
	w2 := httptest.NewRecorder()
	srv.handle(w2, solveRequest("tok", "/", "203.0.113.9"))
	if second := w2.Result().Cookies()[0].Value; second == ck.Value {
		t.Fatal("the same token was reused for a second solve")
	}
}

// Through ProxyPass every request arrives from loopback, so the address Apache
// reported is the only real source. Only the LAST X-Forwarded-For entry can be
// trusted - Apache appends what it saw to whatever the client sent.
func TestChallengeClientIP(t *testing.T) {
	srv, _, _ := testChallenge(t, ok, nil)
	cases := []struct {
		name   string
		set    func(*http.Request)
		want   string
		wantOK bool
	}{
		{"the header Apache sets wins", func(r *http.Request) {
			r.Header.Set(realIPHeader, "203.0.113.9")
			r.Header.Set("X-Forwarded-For", "198.51.100.1")
		}, "203.0.113.9", true},
		{"forged XFF entries are ignored, the last wins", func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 203.0.113.9")
		}, "203.0.113.9", true},
		{"falls back to the peer", func(_ *http.Request) {}, "192.0.2.1", true},
		{"a junk header falls through rather than being trusted", func(r *http.Request) {
			r.Header.Set(realIPHeader, "not-an-ip")
		}, "192.0.2.1", true},
		{"IPv4-mapped IPv6 is canonicalised to match %{REMOTE_ADDR}", func(r *http.Request) {
			r.Header.Set(realIPHeader, "::ffff:203.0.113.9")
		}, "203.0.113.9", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/crowdsec-verify", nil)
			req.RemoteAddr = "192.0.2.1:5555"
			c.set(req)
			got, err := srv.clientIP(req)
			if (err == nil) != c.wantOK {
				t.Fatalf("err = %v", err)
			}
			if got != c.want {
				t.Fatalf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
}

func TestChallengeRendersThePage(t *testing.T) {
	srv, _, _ := testChallenge(t, ok, nil)
	req := httptest.NewRequest(http.MethodGet, "/crowdsec-verify?r=/wp-admin", nil)
	req.Header.Set(realIPHeader, "203.0.113.9")
	w := httptest.NewRecorder()
	srv.handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		`data-cap-api-endpoint="https://cap.example/site/"`,
		`src="https://cap.example/widget.js"`,
		`action="/crowdsec-verify"`,
		`value="/wp-admin"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("challenge page missing %s", want)
		}
	}
	// A challenge is specific to one client at one moment; a cached copy is at
	// best useless and at worst served to somebody else.
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q", w.Header().Get("Content-Type"))
	}
}

func TestPassStoreExpiry(t *testing.T) {
	dir := t.TempDir()
	store := newPassStore(filepath.Join(dir, "captcha_passed.txt"), time.Minute)
	now := time.Now()
	if err := store.add("203.0.113.9", now); err != nil {
		t.Fatal(err)
	}
	if err := store.add("198.51.100.4", now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}

	// Nothing has lapsed yet, so the map must not be rewritten - an unnecessary
	// mtime bump makes Apache re-read a file that did not change.
	before, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if removed, err := store.prune(now.Add(time.Second)); err != nil || removed != 0 {
		t.Fatalf("prune removed %d (err %v), want 0", removed, err)
	}
	after, _ := os.Stat(store.path)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("the map was rewritten even though no pass had lapsed")
	}

	// The first lapses, the second has another 30s.
	removed, err := store.prune(now.Add(70 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 || store.held() != 1 {
		t.Fatalf("prune removed %d leaving %d, want 1 and 1", removed, store.held())
	}
	got, _ := os.ReadFile(store.path)
	if string(got) != "198.51.100.4 1\n" {
		t.Fatalf("pass map = %q, want only the unexpired pass", got)
	}
}

// Switching the policy over - bans to captchas, say - stops a map being produced.
// The file it used to write must be emptied, not left frozen: Apache still names
// it, still consults it first, and would go on enforcing the decision set from
// before the change forever.
func TestRetireUnusedMaps(t *testing.T) {
	dir := t.TempDir()
	banTxt := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(banTxt, []byte("203.0.113.9 1\n198.51.100.4 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Everything is overridden to captcha, so no ban map is produced any more.
	b := testBouncer(t, func(c *config) {
		c.outputFile = banTxt
		c.dbmFile = defaultDBMPath(banTxt)
		c.bouncingOnType = bouncingAll
		c.overrideRemediation = remediationCaptcha
		c.captchaListen = "127.0.0.1:0"
	})
	if b.byType[remediationBan] != nil {
		t.Fatal("precondition: no ban map should be produced under this policy")
	}
	b.retireUnusedMaps()

	got, err := os.ReadFile(banTxt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("the abandoned ban map still holds %q - Apache would keep blocking those addresses", got)
	}
}

// An already-empty map must not be rewritten: a pointless mtime bump makes Apache
// re-read a file that has not changed, on every restart.
func TestRetireUnusedMapsLeavesAnEmptyOneAlone(t *testing.T) {
	dir := t.TempDir()
	banTxt := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(banTxt, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(banTxt)
	if err != nil {
		t.Fatal(err)
	}
	b := testBouncer(t, func(c *config) {
		c.outputFile = banTxt
		c.dbmFile = defaultDBMPath(banTxt)
		c.bouncingOnType = bouncingAll
		c.overrideRemediation = remediationCaptcha
		c.captchaListen = "127.0.0.1:0"
	})
	b.retireUnusedMaps()
	after, err := os.Stat(banTxt)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("an already-empty map was rewritten")
	}
}

// A pass file left by a previous run names clients this process has no expiry
// for. prune iterates memory, so it would never drop them and Apache would honour
// those passes forever - the daemon restarting must not hand out permanent
// exemptions.
func TestPassStoreDiscardsAnInheritedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "captcha_passed.txt")
	if err := os.WriteFile(path, []byte("203.0.113.77 1\n198.51.100.4 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := newPassStore(path, time.Minute) // a fresh process: nothing in memory
	if err := store.reset(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("passes from a previous run survived the restart: %q", got)
	}
	if store.held() != 0 {
		t.Fatalf("held = %d, want 0", store.held())
	}
}

// A map deleted underneath the daemon has to come back, the way the other maps
// self-heal on resync - Apache refuses to start without it.
func TestPassStoreSelfHealsADeletedMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "captcha_passed.txt")
	store := newPassStore(path, time.Minute)
	now := time.Now()
	if err := store.add("203.0.113.9", now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Nothing has lapsed, so only the missing file should trigger the rewrite.
	if _, err := store.prune(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("deleted map was not recreated: %v", err)
	}
	if string(got) != "203.0.113.9 1\n" {
		t.Fatalf("recreated map = %q, want the pass still held in memory", got)
	}
}

// A key with whitespace would render a line Apache silently mis-parses, so the
// pass could never match - a pass that appears to work and doesn't.
func TestPassStoreRejectsUnusableKeys(t *testing.T) {
	store := newPassStore(filepath.Join(t.TempDir(), "captcha_passed.txt"), time.Minute)
	for _, key := range []string{"", "203.0.113.9 1", "tok en", "tok\nen", "tok\ten"} {
		if err := store.add(key, time.Now()); err == nil {
			t.Errorf("add(%q) was accepted; it would corrupt the map", key)
		}
	}
}
