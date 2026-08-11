package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// challengeServer serves the captcha challenge and records the addresses that
// solve it.
//
// It exists because Apache cannot do this part: mod_rewrite has no HTTP client to
// call the provider's siteverify with, and no way to hold the result. A
// RewriteMap prg: program is not a way around that either - Apache runs one copy
// for the whole server behind the rewrite-map mutex, so a network call there
// blocks every worker.
//
// It listens on loopback and is reached through Apache, which is what lets the
// challenge appear on the customer's own hostname and TLS with no extra
// certificate:
//
//	ProxyPass        /crowdsec-verify http://127.0.0.1:8125/
//	ProxyPassReverse /crowdsec-verify http://127.0.0.1:8125/
//	RequestHeader    set X-CrowdSec-Real-IP "%{REMOTE_ADDR}s"
type challengeServer struct {
	cfg     *config
	metrics *metrics
	passes  *passStore
	client  *http.Client
	tmpl    *template.Template
}

// realIPHeader carries the address Apache saw, because through the proxy every
// request arrives from loopback. Apache sets it with RequestHeader, which
// overwrites anything the client sent, so it cannot be forged - but only as long
// as the listener is not reachable directly. See newChallengeServer.
const realIPHeader = "X-CrowdSec-Real-IP"

// challengePage is the default challenge. It is deliberately plain: it has to
// render for someone the server has already decided is suspicious, so it pulls in
// nothing but the widget itself.
const challengePage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Verifying your connection</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         margin: 0; min-height: 100vh; display: flex; align-items: center;
         justify-content: center; background: #f6f7f6; color: #14211f; }
  main { max-width: 30rem; padding: 2rem; text-align: center; }
  h1 { font-size: 1.3rem; font-weight: 600; margin: 0 0 .6rem; }
  p { margin: 0 0 1.5rem; color: #4a5c58; line-height: 1.5; }
  .err { color: #b03219; }
</style>
</head>
<body>
<main>
  <h1>Verifying your connection</h1>
  <p>This check runs automatically. It should only take a moment.</p>
  {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
  <form id="f" method="POST" action="{{.Action}}">
    <input type="hidden" name="r" value="{{.Return}}">
    <cap-widget id="cap" data-cap-api-endpoint="{{.APIEndpoint}}"></cap-widget>
  </form>
  <noscript><p class="err">JavaScript is required to complete this check.</p></noscript>
</main>
<script type="module" src="{{.WidgetJS}}"></script>
<script>
  document.getElementById("cap").addEventListener("solve", function () {
    document.getElementById("f").submit();
  });
</script>
</body>
</html>
`

// newChallengeServer builds the server, loading an operator template over the
// built-in one when CAPTCHA_TEMPLATE is set.
func newChallengeServer(cfg *config, passes *passStore, m *metrics) (*challengeServer, error) {
	page := challengePage
	if cfg.captchaTemplate != "" {
		// #nosec G304 -- the path comes from operator config, never from a request.
		raw, err := os.ReadFile(cfg.captchaTemplate)
		if err != nil {
			return nil, fmt.Errorf("CAPTCHA_TEMPLATE: %w", err)
		}
		page = string(raw)
	}
	tmpl, err := template.New("challenge").Parse(page)
	if err != nil {
		return nil, fmt.Errorf("CAPTCHA_TEMPLATE: %w", err)
	}
	return &challengeServer{
		cfg:     cfg,
		metrics: m,
		passes:  passes,
		// Separate from the LAPI client: this one talks to the captcha provider,
		// on the request path, so it gets a tight deadline of its own.
		client: &http.Client{Timeout: cfg.captchaVerifyTimeout},
		tmpl:   tmpl,
	}, nil
}

// startChallenge brings up the challenge listener when one is configured, and
// creates its pass map first for the same reason the other maps are pre-created:
// Apache refuses to start on a missing RewriteMap, and this one would otherwise
// not exist until somebody solved a challenge.
//
// A failure here never stops the daemon. Blocking is the job that matters, and it
// works without any of this.
func (b *bouncer) startChallenge(ctx context.Context) {
	if b.cfg.captchaListen == "" {
		return
	}
	b.passes = newPassStore(b.cfg.captchaPassFile, b.cfg.captchaPassTTL)
	if err := b.passes.reset(); err != nil {
		log.Printf("creating the pass map at %s: %v; captcha passes will not be recorded", b.cfg.captchaPassFile, err)
		b.passes = nil
		return
	}
	srv, err := newChallengeServer(b.cfg, b.passes, b.metrics)
	if err != nil {
		log.Printf("challenge listener not started: %v", err)
		b.passes = nil
		return
	}
	go srv.serve(ctx)
}

// prunePasses drops lapsed passes on each poll, so a solved challenge stops
// counting once its TTL is up.
func (b *bouncer) prunePasses() {
	if b.passes == nil {
		return
	}
	removed, err := b.passes.prune(time.Now())
	if err != nil {
		log.Printf("pruning the pass map: %v", err)
		return
	}
	if removed > 0 {
		b.metrics.passesExpired.Add(int64(removed))
		log.Printf("captcha passes: %d lapsed, %d still held", removed, b.passes.held())
	}
}

// serve runs the listener until ctx is cancelled. A failure to listen is fatal to
// the challenge, not to the bouncer: the ban list keeps being maintained either
// way, and taking the daemon down over it would take blocking down too.
func (c *challengeServer) serve(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", c.handle)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	// Bind first, separately from serving: the readiness file must appear only
	// once the port is actually accepting, never merely because the process
	// started. A daemon that came up but failed to bind - the port already taken,
	// say - would otherwise tell Apache to send clients to a challenge that is not
	// there, and every one of them would loop through a 503.
	ln, err := net.Listen("tcp", c.cfg.captchaListen)
	if err != nil {
		log.Printf("challenge listener not started: %v; captcha decisions will not be enforceable", err)
		return
	}
	c.markReady()
	defer c.clearReady()

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("challenge listener on %s -> pass map %s (ttl %s)",
		c.cfg.captchaListen, c.cfg.captchaPassFile, c.cfg.captchaPassTTL)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("challenge listener stopped: %v; captcha decisions will not be enforceable", err)
	}
}

// markReady creates the file Apache tests before redirecting anyone to the
// challenge, so "the daemon is down" is a state the config can branch on instead
// of one it discovers by proxying into a 503 - which ErrorDocument then turns
// into a redirect loop.
//
// It is written after a successful bind and removed as serve returns. systemd's
// RuntimeDirectory= removes the whole directory when the unit stops, which covers
// the case this cannot: a hard kill, where no deferred code runs at all.
func (c *challengeServer) markReady() {
	if c.cfg.captchaReadyFile == "" {
		return
	}
	// #nosec G301 -- 0755: Apache's worker user must traverse this to stat the file.
	if err := os.MkdirAll(filepath.Dir(c.cfg.captchaReadyFile), 0o755); err != nil {
		log.Printf("challenge readiness file: %v; Apache cannot tell whether the challenge is up", err)
		return
	}
	// #nosec G306 -- 0644: it carries no secret, and Apache only stats it.
	if err := os.WriteFile(c.cfg.captchaReadyFile, nil, 0o644); err != nil {
		log.Printf("challenge readiness file: %v; Apache cannot tell whether the challenge is up", err)
	}
}

// clearReady removes the readiness file on an orderly shutdown.
func (c *challengeServer) clearReady() {
	if c.cfg.captchaReadyFile == "" {
		return
	}
	if err := os.Remove(c.cfg.captchaReadyFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("removing the challenge readiness file: %v; Apache may keep sending clients to a challenge that is gone", err)
	}
}

// handle serves the challenge on GET and verifies a solved token on POST.
func (c *challengeServer) handle(w http.ResponseWriter, r *http.Request) {
	ip, err := c.clientIP(r)
	if err != nil {
		// No trustworthy address means no pass could be recorded against anything,
		// so there is nothing useful to serve.
		log.Printf("challenge: %v", err)
		http.Error(w, "cannot determine client address", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		c.metrics.challengesServed.Add(1)
		c.render(w, http.StatusOK, safeReturn(r.URL.Query().Get("r")), "")
	case http.MethodPost:
		c.solve(w, r, ip)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// solve verifies the submitted token and, only on a confirmed success, records
// the pass and sends the client back where they were going.
func (c *challengeServer) solve(w http.ResponseWriter, r *http.Request, ip string) {
	if err := r.ParseForm(); err != nil {
		c.render(w, http.StatusBadRequest, "/", "That didn't come through. Please try again.")
		return
	}
	back := safeReturn(r.PostFormValue("r"))
	token := r.PostFormValue(c.cfg.captchaTokenField)
	if token == "" {
		c.metrics.solvesRejected.Add(1)
		c.render(w, http.StatusBadRequest, back, "The check didn't complete. Please try again.")
		return
	}
	// Fail closed: an unreachable or unhappy provider leaves the client
	// challenged. Waving them through on error would turn a captcha outage into a
	// free pass for exactly the traffic the hub flagged.
	if err := c.verify(r.Context(), token); err != nil {
		c.metrics.solvesErrored.Add(1)
		log.Printf("challenge: verification failed for %s: %v", ip, err)
		c.render(w, http.StatusForbidden, back, "We couldn't verify that. Please try again.")
		return
	}
	key, cookie, err := c.newPass(ip)
	if err != nil {
		log.Printf("challenge: minting a pass for %s: %v", ip, err)
		c.render(w, http.StatusInternalServerError, back, "We couldn't complete that. Please try again.")
		return
	}
	if err := c.passes.add(key, time.Now()); err != nil {
		// The pass did not reach disk, so Apache would challenge them again on the
		// next request. Say so rather than redirecting into a loop.
		log.Printf("challenge: recording a pass for %s: %v", ip, err)
		c.render(w, http.StatusInternalServerError, back, "We couldn't complete that. Please try again.")
		return
	}
	if cookie != nil {
		// Set only after the pass is on disk: a client holding a cookie the map
		// does not know about is challenged forever, with a token that looks valid.
		http.SetCookie(w, cookie)
	}
	c.metrics.solvesOK.Add(1)
	log.Printf("challenge: %s solved; pass held for %s (%d total)", ip, c.cfg.captchaPassTTL, c.passes.held())
	http.Redirect(w, r, back, http.StatusFound)
}

// newPass mints the key a solved challenge is recorded under, and the cookie
// carrying it when there is one.
//
//   - ip:     the key is the client's address, so the pass covers every browser
//     behind it - including everyone else sharing a NAT.
//   - cookie: the key is an opaque token this process generated, so the pass is
//     per-browser. It is scoped to the domain that set it, so a client
//     challenged on one vhost is challenged again on the next.
func (c *challengeServer) newPass(ip string) (key string, cookie *http.Cookie, err error) {
	if c.cfg.captchaPassKey != passKeyCookie {
		// In ip mode the address IS the key, which is why clientIP is
		// security-critical here and merely informational in cookie mode.
		return ip, nil, nil
	}
	// 24 bytes -> 32 base64url characters, which is what the documented Apache
	// RewriteCond pattern matches.
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generating a pass token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, &http.Cookie{
		Name:     c.cfg.captchaCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(c.cfg.captchaPassTTL / time.Second),
		HttpOnly: true,
		Secure:   c.cfg.captchaCookieSecure,
		// Lax, not Strict: the pass has to survive a top-level navigation that
		// started somewhere else - a search result, a link in an email - and Strict
		// would withhold it and re-challenge a client that already passed.
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// verifyResponse is the reply from the provider's siteverify. Cap, reCAPTCHA,
// hCaptcha and Turnstile all report the outcome in "success".
type verifyResponse struct {
	Success bool     `json:"success"`
	Errors  []string `json:"error-codes"`
}

// verify asks the provider whether the token is genuine. Cap takes the reCAPTCHA
// field names - "secret" and "response" - in a JSON body.
//
// Cap's status codes are worth recording, because it redacts the reason to the
// caller and logs the detail against a correlation id instead
// (standalone/src/siteverify.js):
//
//	400 - the token is not the "siteKey:id:solution" triple it splits on
//	403 - the secret does not match the site key, or the token has expired
//	404 - the token is unknown, which INCLUDES already used: the lookup is a
//	      getdel, so a token verifies exactly once and a double submit fails
func (c *challengeServer) verify(ctx context.Context, token string) error {
	body, err := json.Marshal(map[string]string{
		"secret":   c.cfg.captchaSecret,
		"response": token,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.captchaVerifyURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	started := time.Now()
	resp, err := c.client.Do(req)
	observeDuration(&c.metrics.lastVerifySecs, time.Since(started))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// Quote what the provider said. Cap redacts its errors to the caller and
		// logs the real cause against a correlation id, so this line is the only
		// way to find that id without reproducing the failure by hand.
		return fmt.Errorf("provider returned %s: %s", resp.Status, firstLine(resp.Body, 300))
	}
	var vr verifyResponse
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&vr); err != nil {
		return fmt.Errorf("decoding the provider's reply: %w", err)
	}
	if !vr.Success {
		if len(vr.Errors) > 0 {
			return fmt.Errorf("provider rejected the token: %s", strings.Join(vr.Errors, ", "))
		}
		return errors.New("provider rejected the token")
	}
	return nil
}

// firstLine reads up to max bytes of r and flattens it to one log-safe line.
func firstLine(r io.Reader, max int64) string {
	body, _ := io.ReadAll(io.LimitReader(r, max))
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "(empty body)"
	}
	return strings.Join(strings.Fields(s), " ")
}

// render writes the challenge page.
func (c *challengeServer) render(w http.ResponseWriter, status int, back, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A challenge is specific to one client at one moment; a cached copy served to
	// somebody else, or replayed later, is at best useless.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	err := c.tmpl.Execute(w, map[string]string{
		"Action":      c.cfg.captchaPath,
		"Return":      back,
		"APIEndpoint": c.cfg.captchaAPIEndpoint,
		"WidgetJS":    c.cfg.captchaWidgetJS,
		"Error":       errMsg,
	})
	if err != nil {
		log.Printf("challenge: rendering the page: %v", err)
	}
}

// clientIP recovers the address Apache saw. Through ProxyPass every request
// arrives from loopback, so the header Apache sets is the only real source.
//
// X-Forwarded-For is the fallback, and only its LAST entry is read: Apache
// appends what it saw to whatever the client sent, so earlier entries are
// attacker-controlled. Either way this is only safe because the listener binds to
// loopback - a directly reachable listener would let anyone name their own
// address and grant themselves a pass.
func (c *challengeServer) clientIP(r *http.Request) (string, error) {
	if v := strings.TrimSpace(r.Header.Get(realIPHeader)); v != "" {
		if addr, err := netip.ParseAddr(v); err == nil {
			return addr.Unmap().String(), nil
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		last := strings.TrimSpace(parts[len(parts)-1])
		if addr, err := netip.ParseAddr(last); err == nil {
			return addr.Unmap().String(), nil
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("no usable client address (RemoteAddr=%q): %w", r.RemoteAddr, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("no usable client address (RemoteAddr=%q): %w", r.RemoteAddr, err)
	}
	return addr.Unmap().String(), nil
}

// safeReturn reduces the requested return target to a same-site path, so the
// challenge can never be used as an open redirect. Anything that could name
// another host - an absolute URL, a protocol-relative "//host", a backslash form
// some browsers normalise the same way - or that could smuggle a header, falls
// back to the site root.
func safeReturn(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return "/"
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, `/\`) {
		return "/"
	}
	if strings.ContainsAny(raw, "\r\n") {
		return "/"
	}
	return raw
}
