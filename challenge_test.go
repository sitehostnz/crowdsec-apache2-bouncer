package main

import (
	"context"
	"fmt"
	"html"
	"html/template"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testChallenge builds a challenge server on an altcha config. There is no provider
// stub because there is no provider: verification happens in-process.
func testChallenge(t *testing.T, mutate func(*config)) (*challengeServer, *passStore) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config{
		captchaListen:     "127.0.0.1:0",
		captchaPath:       "/crowdsec-verify",
		captchaWidgetJS:   altchaDefaultWidgetJS,
		captchaWidgetSRI:  altchaDefaultWidgetSRI,
		captchaTokenField: "altcha",
		captchaPassFile:   filepath.Join(dir, "captcha_passed.txt"),
		captchaPassTTL:    time.Hour,
		altchaAlgorithm:   altchaDefaultAlgorithm,
		altchaCost:        1,
		altchaComplexity:  2000,
	}
	if mutate != nil {
		mutate(cfg)
	}
	store := newPassStore(cfg.captchaPassFile, cfg.captchaPassTTL)
	srv, err := newChallengeServer(cfg, store, newMetrics())
	if err != nil {
		t.Fatal(err)
	}
	return srv, store
}

func TestChallengeReadinessFile(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "run", "challenge.up")

	t.Run("appears while listening, gone afterwards", func(t *testing.T) {
		srv, _ := testChallenge(t, func(c *config) {
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
		busy, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = busy.Close() }()

		missing := filepath.Join(dir, "run", "not-created.up")
		srv, _ := testChallenge(t, func(c *config) {
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
		"/\t/evil.example":           "/", // TAB survives the Location header; browsers strip it -> //evil.example
		"/\v/evil.example":           "/", // vertical tab, same class of stripped control char
		"/\f/evil.example":           "/", // form feed, same
		"/ok\x00":                    "/", // NUL and the rest of the C0 range are refused too
	}
	for raw, want := range cases {
		if got := safeReturn(raw); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", raw, got, want)
		}
	}
}

// The error for a missing field calls the built-in page the reference, so it has
// to actually be one. The list and the page live in the same file and can drift:
// if the built-in ever loses a field, operator templates are being held to a
// standard the reference no longer meets.
func TestChallengePageMeetsItsOwnRequirements(t *testing.T) {
	tmpl, err := template.New("challenge").Parse(challengePage)
	if err != nil {
		t.Fatal(err)
	}
	used := templateFields(tmpl)
	for _, required := range requiredTemplateFields {
		if !used[required] {
			t.Errorf("the built-in page does not use .%s, but an operator template is refused without it", required)
		}
	}
}

// templateOmitting builds a page referencing every required field but one. Built
// rather than carved out of the built-in page, because the names overlap - cutting
// "Widget" out of that text would take .WidgetJS and .WidgetSRI with it and the
// test would pass for the wrong reason.
//
// The actions are written SPACED, which is the second thing under test: the
// spacing most Go documentation uses has to be accepted, since a template written
// that way works perfectly and an operator refused over it is being told their
// page does not use a field they are looking straight at.
func templateOmitting(omit string) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><body>")
	for _, f := range requiredTemplateFields {
		if f == omit {
			continue
		}
		fmt.Fprintf(&b, "{{ .%s }}", f)
	}
	b.WriteString("</body></html>")
	return b.String()
}

// An operator template missing any required field is refused at startup, naming
// the field. Without this the guard is untested in both directions - and it grew
// two entries in the round that added SRI.
func TestChallengeTemplateRefusesAMissingField(t *testing.T) {
	newServer := func(t *testing.T, page string) error {
		t.Helper()
		path := filepath.Join(t.TempDir(), "challenge.html")
		if err := os.WriteFile(path, []byte(page), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := newChallengeServer(&config{
			captchaPath:      "/crowdsec-verify",
			captchaTemplate:  path,
			captchaWidgetJS:  altchaDefaultWidgetJS,
			captchaWidgetSRI: altchaDefaultWidgetSRI,
		}, nil, newMetrics())
		return err
	}

	for _, missing := range requiredTemplateFields {
		t.Run("without "+missing, func(t *testing.T) {
			err := newServer(t, templateOmitting(missing))
			if err == nil {
				t.Fatalf("a template with no .%s was accepted", missing)
			}
			// Anchored on the dynamic clause, not a bare substring. The error also
			// carries a static sentence listing five of the six field names, so
			// `Contains(err, "."+missing)` would be satisfied by that boilerplate
			// even if the guard named the wrong field - and ".Widget" is a prefix of
			// ".WidgetJS" and ".WidgetSRI" besides.
			if want := "does not use ." + missing + ";"; !strings.Contains(err.Error(), want) {
				t.Errorf("the error does not report %q: %v", want, err)
			}
		})
	}

	// The same builder omitting nothing: spaced actions, every field present, and
	// it must be accepted. Guards against the check being satisfied by something
	// other than the fields - if this failed, every subtest above would be passing
	// for the wrong reason.
	t.Run("spaced actions are accepted", func(t *testing.T) {
		if err := newServer(t, templateOmitting("")); err != nil {
			t.Errorf("a template using {{ .Field }} spacing was refused: %v", err)
		}
	})

	// A {{define}} body is a tree of its own, so walking only the root missed every
	// field inside one and refused a page that renders. Worse than the text search
	// it replaced, which saw the whole file.
	t.Run("fields inside a define are found", func(t *testing.T) {
		page := `{{define "head"}}<script src="{{.WidgetJS}}" integrity="{{.WidgetSRI}}"></script>{{end}}` +
			`<form action="{{.Action}}"><input value="{{.Return}}">{{.Widget}}</form>` +
			`<script>x.addEventListener("{{.SolveEvent}}",f)</script>{{template "head" .}}`
		if err := newServer(t, page); err != nil {
			t.Errorf("fields declared inside {{define}} were not seen: %v", err)
		}
	})

	// {{$.X}} is how you reach the top-level data from inside a range or with. It
	// parses as a variable, not a field, so it needs its own case in the walker.
	t.Run("dollar-rooted fields are found", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(`{{range $i, $v := .Nothing}}{{end}}`)
		for _, f := range requiredTemplateFields {
			fmt.Fprintf(&b, "{{$.%s}}", f)
		}
		if err := newServer(t, b.String()); err != nil {
			t.Errorf("$-rooted field references were not seen: %v", err)
		}
	})
}

// No digest means no attribute at all. Rendering an integrity the browser cannot
// match blocks the script outright, and a blocked widget is a page that renders
// 200, says "Verifying your connection" and never resolves.
func TestChallengeOmitsIntegrityWithoutADigest(t *testing.T) {
	srv, _ := testChallenge(t, func(c *config) {
		c.captchaWidgetJS = "https://cdn.example.test/altcha.js"
		c.captchaWidgetSRI = ""
	})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/crowdsec-verify", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	w := httptest.NewRecorder()
	srv.handle(w, req)

	body := w.Body.String()
	if strings.Contains(body, "integrity=") || strings.Contains(body, "crossorigin=") {
		t.Error("integrity/crossorigin rendered with no digest configured")
	}
	if !strings.Contains(body, `src="https://cdn.example.test/altcha.js"`) {
		t.Error("the configured widget URL is missing from the page")
	}
}

func TestChallengeClientIP(t *testing.T) {
	srv, _ := testChallenge(t, nil)
	cases := []struct {
		name   string
		set    func(*http.Request)
		want   string
		wantOK bool
	}{
		{"the entry mod_proxy appended is the one used", func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "203.0.113.9")
		}, "203.0.113.9", true},
		{"forged XFF entries are ignored, the last wins", func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 203.0.113.9")
		}, "203.0.113.9", true},
		// A client naming itself gets nowhere: mod_proxy appends what it saw, so the
		// address the client chose is never the last entry. Reading any other entry
		// would let anyone record a pass against an address they do not control.
		{"a client-supplied header cannot displace the appended entry", func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9")
		}, "203.0.113.9", true},
		{"falls back to the peer", func(_ *http.Request) {}, "192.0.2.1", true},
		{"a junk header falls through rather than being trusted", func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "not-an-ip")
		}, "192.0.2.1", true},
		{"IPv4-mapped IPv6 is canonicalised to match %{REMOTE_ADDR}", func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "::ffff:203.0.113.9")
		}, "203.0.113.9", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/crowdsec-verify", nil)
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
	srv, _ := testChallenge(t, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/crowdsec-verify?r=/wp-admin", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	w := httptest.NewRecorder()
	srv.handle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	// Deliberately the RAW body: if Widget ever regressed from template.HTML to a
	// plain string the page would carry "&lt;altcha-widget", and unescaping the whole
	// document before comparing would hide exactly the regression a page-render
	// test exists to catch.
	body := w.Body.String()
	for _, want := range []string{
		`<altcha-widget`,
		`challenge="/crowdsec-verify/altcha-challenge"`,
		`src="` + altchaDefaultWidgetJS + `"`,
		`crossorigin="anonymous"`,
		`action="/crowdsec-verify"`,
		`value="/wp-admin"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("challenge page missing %s", want)
		}
	}
	// Only the digest needs unescaping, and only because html/template writes "+"
	// in an attribute as "&#43;" - see TestChallengeRendersAPlusBearingDigest. The
	// pinned digest happens to contain no "+" today, so comparing it raw would pass
	// by luck and break on roughly two thirds of future widget bumps.
	// Version pinning answers a bad upstream release; this answers a CDN edge
	// serving something else entirely, on the customer's own origin.
	if want := `integrity="` + altchaDefaultWidgetSRI + `"`; !strings.Contains(html.UnescapeString(body), want) {
		t.Errorf("challenge page missing %s", want)
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

// A "+" must survive to the DOM: SRI compares the DECODED attribute, so a literal
// "&#43;" left in it would never match and the browser would block the script.
// html/template escapes it and the HTML parser decodes it again, which is correct
// but easy to mistake for corruption - pinned here deliberately rather than left
// to whether the currently pinned digest happens to contain one.
func TestChallengeRendersAPlusBearingDigest(t *testing.T) {
	const digest = "sha384-r6ZUlDrx6zqL8kFVYTgYWJH0wLcOMs+ftxrBSkq9NoXPunl1IvinIyoNM1zVdusN"
	srv, _ := testChallenge(t, func(c *config) { c.captchaWidgetSRI = digest })
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/crowdsec-verify", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	w := httptest.NewRecorder()
	srv.handle(w, req)

	raw := w.Body.String()
	if !strings.Contains(html.UnescapeString(raw), `integrity="`+digest+`"`) {
		t.Errorf("the digest does not survive escaping:\n%s", raw)
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
