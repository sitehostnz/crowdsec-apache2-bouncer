package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"text/template/parse"
	"time"
)

// challengeServer serves the captcha challenge and records the addresses that
// solve it.
//
// It exists because Apache cannot do this part: mod_rewrite cannot derive a key, and
// has nowhere to hold the challenge it issued. A RewriteMap prg: program is not a way
// around that either - Apache runs one copy for the whole server behind the
// rewrite-map mutex, so any work there blocks every worker.
//
// It listens on loopback and is reached through Apache, which is what lets the
// challenge appear on the customer's own hostname and TLS with no extra
// certificate:
//
//	ProxyPass        /crowdsec-verify http://127.0.0.1:8125
//	ProxyPassReverse /crowdsec-verify http://127.0.0.1:8125
//
// That pair is the whole of it - mod_proxy adds the X-Forwarded-For that clientIP
// reads, so there is no header to configure and no mod_headers to load.
type challengeServer struct {
	cfg     *config
	metrics *metrics
	passes  *passStore
	altcha  *altchaStore
	// misroutedOnce keeps the proxy-misconfiguration hint to one line per start.
	misroutedOnce sync.Once
	tmpl          *template.Template
	// widget is the rendered <altcha-widget> element and solveEvent the event that
	// means "solved". Both depend only on config, so they are built once at
	// construction - re-rendering the element was a quarter of a page render's
	// allocations - and injected whole, so an operator template gets the element
	// right by construction.
	widget     template.HTML
	solveEvent string
}

// maxSolveBody caps the solve POST. Generous next to the ~200 bytes a real one
// carries, so a legitimate client cannot trip it.
const maxSolveBody = 64 << 10

// mintTokens bounds how many challenge derivations run at once. Deriving outside
// the store mutex removed the accidental serialisation that used to cap this, and
// the daemon's real job - polling the LAPI and rendering the ban maps - is a single
// goroutine that would otherwise compete with every request for a core.
var mintTokens = make(chan struct{}, mintConcurrency())

// mintConcurrency is half the CPUs, at least one - leaving room for the poll loop
// that actually maintains the ban maps.
func mintConcurrency() int {
	if n := runtime.NumCPU() / 2; n > 0 {
		return n
	}
	return 1
}

// challengePage is the default challenge. It is deliberately plain: it has to
// render for someone the server has already decided is suspicious, so it pulls in
// nothing but the widget itself.
// has no en-GB spelling and the page would not render with one.
//
//nolint:misspell // "center" and "color" below are CSS keywords, not prose - CSS
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
  <p>Complete the check below to continue. It should only take a moment.</p>
  {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
  <form id="f" method="POST" action="{{.Action}}">
    <input type="hidden" name="r" value="{{.Return}}">
    {{.Widget}}
  </form>
  <noscript><p class="err">JavaScript is required to complete this check.</p></noscript>
</main>
<script type="module" src="{{.WidgetJS}}"{{if .WidgetSRI}} integrity="{{.WidgetSRI}}" crossorigin="anonymous"{{end}}></script>
<script>
  document.getElementById("cs-widget").addEventListener(
    "{{.SolveEvent}}", function () { document.getElementById("f").submit(); });
</script>
</body>
</html>
`

// requiredTemplateFields are the fields an operator template must reference.
// html/template silently ignores fields a template does not use, so a page
// written against an older field set parses cleanly, renders 200, and is broken
// in a way nothing logs. Refused at startup instead, naming what is missing.
//
// SolveEvent is in here because the form carries no submit button: the listener
// it names is what submits. A template with the widget but no listener renders a
// checkbox that says "verified" and then does nothing at all - the silent hang
// this list exists to stop, and the one an operator is least likely to test for.
//
// WidgetSRI is in here for the opposite reason. Leaving it out does not break the
// page; it quietly stops the browser checking the script it loads, which is a
// downgrade that looks like nothing. Required rather than injected, because only
// the template knows where its own script tag is.
//
// TestChallengePageMeetsItsOwnRequirements pins that the built-in page satisfies
// this list - the error calls it the reference, so it has to be one.
var requiredTemplateFields = []string{
	"Widget", "WidgetJS", "WidgetSRI", "Action", "Return", "SolveEvent",
}

// templateFields returns every field name a parsed template references, wherever
// it appears: a bare {{.X}}, a condition like {{if .X}}, or an argument buried in
// a pipeline.
//
// This walks the parse tree rather than searching the source text, and the
// difference is not academic. Template actions are whitespace-insensitive, so
// `{{ .Widget }}` is the same template as `{{.Widget}}` - and it is the spacing
// most Go documentation uses. A substring test refuses the first while the page
// it describes works perfectly, and the operator is then told their template
// "does not use {{.Widget}}" while looking straight at it. Worse, it fails
// quietly: startChallenge logs and returns, no readiness file appears, and the
// shipped Apache rules refuse every challenged client instead of challenging
// them. Captcha degrades to a block with nothing saying why.
//
// Deliberately scope-blind, and therefore permissive: {{with .Foo}}{{.Widget}}
// records Widget even though it means .Foo.Widget there. That is the right way
// for this to be wrong. It is a safety net against a stale field set, not a
// validator, and a false REJECT costs a listener that will not start, where a
// false accept costs no more than having no check at all. Do not tighten it into
// scope tracking - the expensive failures here have all been over-strictness.
func templateFields(t *template.Template) map[string]bool {
	found := map[string]bool{}
	var walk func(parse.Node)
	walk = func(n parse.Node) {
		// Every case below re-checks for a nil POINTER, not just a nil interface.
		// A branch with no {{else}} carries a typed-nil *parse.ListNode, and a `case
		// nil` in a type switch does not match that - the interface is non-nil, only
		// the pointer inside it is nil. Dereferencing it panics, which for this
		// package means the whole daemon dies while parsing an operator's template.
		if n == nil {
			return
		}
		switch n := n.(type) {
		case *parse.FieldNode:
			// .A.B references A; only the first element names a field of the data.
			if n != nil && len(n.Ident) > 0 {
				found[n.Ident[0]] = true
			}
		case *parse.VariableNode:
			// {{$.Widget}} is the idiom for reaching the top-level data from inside
			// a range or with, and it parses as a variable rather than a field - so
			// without this the walker sees nothing and refuses a working page.
			// Ident is ["$", "Widget"]. Only "$" is followed: {{$v := .}}{{$v.X}}
			// would need a scope stack to resolve, for a form nobody writes here.
			if n != nil && len(n.Ident) > 1 && n.Ident[0] == "$" {
				found[n.Ident[1]] = true
			}
		case *parse.ChainNode: // (expr).Field
			if n != nil {
				walk(n.Node)
			}
		case *parse.ListNode:
			if n == nil {
				return
			}
			for _, c := range n.Nodes {
				walk(c)
			}
		case *parse.ActionNode:
			if n != nil {
				walk(n.Pipe)
			}
		case *parse.PipeNode:
			if n == nil {
				return
			}
			for _, c := range n.Cmds {
				walk(c)
			}
		case *parse.CommandNode:
			if n == nil {
				return
			}
			for _, a := range n.Args {
				walk(a)
			}
		case *parse.IfNode:
			if n != nil {
				walk(n.Pipe)
				walk(n.List)
				walk(n.ElseList)
			}
		case *parse.RangeNode:
			if n != nil {
				walk(n.Pipe)
				walk(n.List)
				walk(n.ElseList)
			}
		case *parse.WithNode:
			if n != nil {
				walk(n.Pipe)
				walk(n.List)
				walk(n.ElseList)
			}
		case *parse.TemplateNode:
			if n != nil {
				walk(n.Pipe)
			}
		}
	}
	// Every associated template, not just the root. A {{define}} body - and
	// {{block}}, which is sugar for one - parses into a tree of its own, and the
	// TemplateNode case above walks only the INVOCATION's argument, never the body
	// it invokes. Walking the root alone therefore refused a page that renders
	// perfectly, and did so more strictly than the plain text search this replaced.
	// Nil-guarded because a template invoked but never defined has no tree.
	for _, assoc := range t.Templates() {
		if assoc.Tree != nil {
			walk(assoc.Tree.Root)
		}
	}
	return found
}

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
	// html/template silently ignores fields a template does not reference, so a page
	// written against an older field set parses cleanly, renders 200, and contains no
	// widget at all - a dead page for every challenged visitor, with nothing logged.
	// Refuse at startup instead, naming what is missing.
	if cfg.captchaTemplate != "" {
		used := templateFields(tmpl)
		for _, required := range requiredTemplateFields {
			if !used[required] {
				return nil, fmt.Errorf("CAPTCHA_TEMPLATE %s does not use .%s; the built-in page in challenge.go is the reference. "+
					"Missing .Widget, .WidgetJS, .Action, .Return or .SolveEvent renders a page that cannot be solved; "+
					"missing .WidgetSRI renders one whose script the browser no longer verifies",
					cfg.captchaTemplate, required)
			}
		}
	}
	srv := &challengeServer{
		cfg:     cfg,
		metrics: m,
		passes:  passes,
		tmpl:    tmpl,
		altcha:  newAltchaStore(),
	}
	srv.widget, srv.solveEvent = srv.widgetMarkup()
	return srv, nil
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
	// Kept so the poll loop can expire abandoned challenges - see prunePasses.
	b.altcha = srv.altcha
	srv.altcha.minted = func() { b.metrics.challengesMinted.Add(1) }
	go srv.serve(ctx)
}

// prunePasses drops lapsed passes on each poll, so a solved challenge stops
// counting once its TTL is up.
func (b *bouncer) prunePasses() {
	// Challenges nobody came back for. Unlike a pass, an outstanding challenge is
	// pure memory - no map to rewrite - so this is silent unless something is
	// accumulating.
	if b.altcha != nil {
		if dropped := b.altcha.prune(time.Now()); dropped > 0 {
			b.metrics.challengesLapsed.Add(int64(dropped))
			log.Printf("altcha challenges: %d expired unsolved, %d still outstanding", dropped, b.altcha.held())
		}
	}
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
	// The widget fetches its challenge from here; there is no provider to fetch from.
	mux.HandleFunc(altchaChallengePath, c.altchaChallenge)
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
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", c.cfg.captchaListen)
	if err != nil {
		log.Printf("challenge listener not started: %v; captcha decisions will not be enforceable", err)
		return
	}
	c.markReady()
	defer c.clearReady()

	go func() {
		<-ctx.Done()
		// Deliberately detached: ctx is already cancelled, so deriving the shutdown
		// deadline from it would give in-flight requests no grace at all.
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second) //nolint:contextcheck // see above
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("challenge listener on %s -> pass map %s (ttl %s)",
		c.cfg.captchaListen, c.cfg.captchaPassFile, c.cfg.captchaPassTTL)
	{
		// Spell out what the dials add up to. complexity and cost multiply, and the
		// product is what a visitor actually waits for - easy to misjudge from either
		// number alone.
		log.Printf("altcha: %s cost=%d complexity=%d -> ~%d KDF iterations and ~%d WebCrypto calls per solve, challenge ttl %s",
			c.cfg.altchaAlgorithm, c.cfg.altchaCost, c.cfg.altchaComplexity,
			c.cfg.altchaComplexity/2*int64(c.cfg.altchaCost),
			altchaWebCryptoCalls(c.cfg.altchaAlgorithm, c.cfg.altchaCost, c.cfg.altchaComplexity),
			altchaChallengeTTL)
	}
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

// altchaChallengePath is where the widget fetches a challenge. Apache proxies the
// whole of CAPTCHA_PATH to this listener, so it needs no rule of its own.
const altchaChallengePath = "/altcha-challenge"

// altchaChallenge issues a challenge and remembers the answer it expects. The
// answer is what is kept, not a signature - see altchaStore.
func (c *challengeServer) altchaChallenge(w http.ResponseWriter, r *http.Request) {
	// Minting costs a KDF pass, so only the verb the widget actually uses gets to
	// trigger one. Without this, POST minted too - which is half of what made
	// alternating fetch-and-junk-solve an amplifier.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip, err := c.clientIP(r)
	if err != nil {
		log.Printf("challenge: %v", err)
		http.Error(w, "cannot determine client address", http.StatusBadRequest)
		return
	}
	// Bound the derivations in flight; see mintTokens. The wait is bounded by the
	// work ahead of it, and single-flight means a reload never queues behind its
	// own address.
	select {
	case mintTokens <- struct{}{}:
		defer func() { <-mintTokens }()
	case <-r.Context().Done():
		return // the client gave up; do not start work for nobody
	}
	// Same challenge back until it is solved or expires, so reloads cost nothing.
	ch, err := c.altcha.challengeFor(ip, c.cfg.altchaAlgorithm, c.cfg.altchaCost, c.cfg.altchaComplexity, time.Now())
	if err != nil {
		log.Printf("challenge: issuing an ALTCHA challenge: %v", err)
		http.Error(w, "cannot issue a challenge", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // one challenge per client, never reused
	_ = json.NewEncoder(w).Encode(ch)
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
	// A request that LOOKS like the challenge endpoint but did not match its route
	// means the proxy in front is misconfigured - most often a trailing slash on the
	// ProxyPass target, which maps /crowdsec-verify/altcha-challenge to
	// //altcha-challenge. Serving the HTML page here would leave the widget trying to
	// parse a page as JSON, which is a spinner that never resolves and nothing in any
	// log. Say so instead, once, with the fix in the message.
	if strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), altchaChallengePath) {
		c.misroutedOnce.Do(func() {
			// %q, not %s: the path is attacker-controlled and %0a decodes to a real
			// newline, which would let a request forge log lines. Go's quoting escapes
			// it. gosec cannot see that, hence the suppression rather than a change.
			log.Printf("challenge: %q reached the catch-all handler, so the widget is asking for a path Apache is not mapping here. "+ //nolint:gosec // G706: %q escapes control characters
				"Check ProxyPass has NO trailing slash on either side: "+
				"ProxyPass /crowdsec-verify http://%s", r.URL.Path, c.cfg.captchaListen)
		})
		http.Error(w, "misrouted challenge request", http.StatusNotFound)
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
	// A real solve is a couple of hundred bytes. Without this, ParseForm accepts
	// net/http's 10MB default and the token is then base64-decoded, unmarshalled,
	// lower-cased and converted before a length check rejects it - measured at 40MB
	// of allocation for ONE request, on an endpoint that cannot be authenticated.
	r.Body = http.MaxBytesReader(w, r.Body, maxSolveBody)
	if err := r.ParseForm(); err != nil {
		// Counted, because this is the path an oversized body takes and it was the
		// one outcome moving no metric at all: a client hammering the endpoint with
		// bodies too large to parse left challenge_solves_total flat while the
		// process burned CPU on them. The abuse the cap exists to stop was the only
		// abuse invisible on /metrics.
		c.metrics.solvesRejected.Add(1)
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
	// Fail closed: a solution that does not check out leaves the client challenged.
	// Waving them through on error would turn any fault here into a free pass for
	// exactly the traffic the hub flagged.
	spent, err := c.check(token, ip)
	if err != nil {
		c.metrics.solvesErrored.Add(1)
		// ip is canonical - clientIP parses it with netip.ParseAddr, so it cannot
		// carry newlines - and err is ours, never client text.
		log.Printf("challenge: verification failed for %s: %v", ip, err) //nolint:gosec // G706: ip is parsed, not passed through
		c.render(w, http.StatusForbidden, back, "We couldn't verify that. Please try again.")
		return
	}
	if err := c.passes.add(ip, time.Now()); err != nil {
		// The pass did not reach disk, so Apache would challenge them again on the
		// next request. Say so rather than redirecting into a loop - and give the
		// challenge back, because the solve was correct and the fault is ours: they
		// should not have to re-grind a multi-second proof for our full disk.
		c.altcha.restore(ip, spent, time.Now())
		c.metrics.solvesErrored.Add(1)                                // otherwise a pass-map outage is invisible
		log.Printf("challenge: recording a pass for %s: %v", ip, err) //nolint:gosec // G706: ip is parsed by clientIP
		c.render(w, http.StatusInternalServerError, back, "We couldn't complete that. Please try again.")
		return
	}
	c.metrics.solvesOK.Add(1)
	log.Printf("challenge: %s solved; pass held for %s (%d total)", ip, c.cfg.captchaPassTTL, c.passes.held()) //nolint:gosec // G706: ip is parsed by clientIP
	// back has been through safeReturn, which rejects anything that is not a
	// single-slash-rooted local path - that is the open-redirect guard.
	http.Redirect(w, r, back, http.StatusFound) //nolint:gosec // G710: safeReturn is the guard
}

// check verifies a solve, returning the challenge it consumed so solve can hand it
// back if it cannot finish - see solve. It never leaves the process: no request,
// no secret on the wire, nothing to be down.
func (c *challengeServer) check(token, ip string) (altchaEntry, error) {
	key, err := parseAltchaPayload(token)
	if err != nil {
		return altchaEntry{}, err
	}
	// Looked up by the IP we issued it to, so a caller cannot point the lookup
	// elsewhere, and spent only on success - see altchaStore.redeem.
	return c.altcha.redeem(ip, key, time.Now())
}

// render writes the challenge page.
func (c *challengeServer) render(w http.ResponseWriter, status int, back, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A challenge is specific to one client at one moment; a cached copy served to
	// somebody else, or replayed later, is at best useless.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	err := c.tmpl.Execute(w, map[string]any{
		"Action":     c.cfg.captchaPath,
		"Return":     back,
		"WidgetJS":   c.cfg.captchaWidgetJS,
		"WidgetSRI":  c.cfg.captchaWidgetSRI,
		"Widget":     c.widget,
		"SolveEvent": c.solveEvent,
		"Error":      errMsg,
	})
	if err != nil {
		log.Printf("challenge: rendering the page: %v", err)
	}
}

// clientIP recovers the address Apache saw. Through ProxyPass every request
// arrives from loopback, so X-Forwarded-For is the only real source.
//
// Only its LAST entry is read: mod_proxy appends the peer it saw to whatever the
// client sent, so the last entry is server-written and every earlier one is
// attacker-controlled.
//
// X-Forwarded-For rather than a header of our own, because mod_proxy sets it
// itself - ProxyAddHeaders defaults to On - so it is there by virtue of the
// ProxyPass that makes any of this work. A custom header has to be configured
// separately with mod_headers, and a deployment that copies the ProxyPass pair
// but misses that line gets a daemon trusting a header anyone can send. One
// source, and it is the one that cannot go missing on its own.
//
// None of this is safe if the listener is reachable directly: whoever can connect
// to it can name their own address and grant themselves a pass. Bind it to
// loopback.
func (c *challengeServer) clientIP(r *http.Request) (string, error) {
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
//
// The control-character check has to cover more than CR and LF. Browsers strip
// every ASCII tab and newline out of a URL before parsing it (per the WHATWG URL
// spec), so "/\t/host" survives intact through the Location header - a tab is a
// legal header-value byte that Go does not escape - and is then read as "//host",
// a protocol-relative jump off-site that slips straight past the "//" prefix guard
// above. Rejecting the whole C0 range plus DEL closes tab, vertical tab and form
// feed alongside the CR/LF header smuggling.
func safeReturn(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") {
		return "/"
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, `/\`) {
		return "/"
	}
	if strings.IndexFunc(raw, func(r rune) bool { return r <= 0x1f || r == 0x7f }) >= 0 {
		return "/"
	}
	return raw
}

// altchaElement renders the widget with contextual escaping.
//
// Attribute names verified against the published widget (v3) - "challenge"
// carries the endpoint URL ("challengeurl" was v1 and is not read at all),
// "name" is the hidden field the payload arrives in, and auto="onload" makes
// the widget solve as soon as it upgrades instead of waiting for a click.
// That trades away the earlier caution (an automatic solve that fails looks
// identical to a hung page, which is exactly how the MIME fault read from the
// outside) for a check nobody has to notice a checkbox to pass. Server cost
// is unchanged: the mint a click used to trigger happens at first render
// instead, and it is the same single mint - challenges are per-address, and a
// re-fetch inside the TTL returns the one already outstanding.
var altchaElement = template.Must(template.New("altcha").Parse(
	`<altcha-widget id="cs-widget" challenge="{{.Challenge}}" name="{{.Name}}" auto="onload"></altcha-widget>`))

// widgetMarkup builds the element and names the event that means "solved". Run
// once at construction and kept on the server - the inputs are config, which
// never changes while the process lives.
//
// Rendered through html/template rather than fmt.Sprintf: %q is GO quoting, not
// HTML escaping, so a config value holding a double quote would break out of the
// attribute and a bare & would stop being entity-escaped. These values are
// operator-set rather than attacker-set, which makes it a latent hazard rather
// than a live one - the kind worth closing while it is still cheap.
func (c *challengeServer) widgetMarkup() (template.HTML, string) {
	var buf bytes.Buffer
	_ = altchaElement.Execute(&buf, map[string]string{
		"Challenge": strings.TrimSuffix(c.cfg.captchaPath, "/") + altchaChallengePath,
		"Name":      c.cfg.captchaTokenField,
	})
	return template.HTML(buf.String()), "verified" // #nosec G203 -- html/template escaped it
}
