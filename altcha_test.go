package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Small enough that the test solves it in milliseconds. The counter is uniform
// below this, so scanning to it always finds the answer.
const testAltchaComplexity = 2000

// wrongDerivedKey is a WRONG answer of the RIGHT shape: exactly altchaKeyLength
// bytes of hex, so it survives parseAltchaPayload's length check and actually
// reaches redeem's comparison.
//
// The tests that submit it exist to pin behaviour inside redeem - that a wrong
// answer leaves the challenge in place. Short junk like "deadbeef" cannot test
// that: parseAltchaPayload rejects it on length first, so redeem never runs and
// the test passes even with the guard removed. Verified by mutation - re-adding
// the delete on redeem's wrong-answer branch fails these tests with this value
// and passed with the old one.
var wrongDerivedKey = strings.Repeat("ab", altchaKeyLength)

func testAltchaServer(t *testing.T) (*challengeServer, *passStore) {
	t.Helper()
	srv, store := testChallenge(t, func(c *config) {
		c.altchaComplexity = testAltchaComplexity
	})
	return srv, store
}

func altchaSolveRequest(payload, back, ip string) *http.Request {
	form := "altcha=" + strings.ReplaceAll(payload, "+", "%2B") + "&r=" + back
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/crowdsec-verify", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", ip)
	return req
}

// fetchChallenge pulls one from the endpoint, as the widget would.
func fetchAltchaChallenge(t *testing.T, srv *challengeServer, ip string) altchaChallenge {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, altchaChallengePath, nil)
	req.Header.Set("X-Forwarded-For", ip)
	srv.altchaChallenge(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge endpoint: %d", w.Code)
	}
	var ch altchaChallenge
	if err := json.NewDecoder(w.Body).Decode(&ch); err != nil {
		t.Fatal(err)
	}
	return ch
}

// The wire format must be the widget's NATIVE one. These are precisely the fields
// its isChallengeValid() insists on: a challenge missing any of them is rejected
// before a single hash is computed, and the page then hangs with no visible error.
func TestAltchaEmitsTheNativeFormat(t *testing.T) {
	srv, _ := testAltchaServer(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, altchaChallengePath, nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	srv.altchaChallenge(w, req)

	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	params, isObject := raw["parameters"].(map[string]any)
	if !isObject {
		t.Fatalf("no parameters object - this is the v1 shape: %v", raw)
	}
	for _, want := range []string{"algorithm", "nonce", "salt", "keyPrefix"} {
		if _, ok := params[want]; !ok {
			t.Errorf("parameters.%s missing - isChallengeValid() would reject this", want)
		}
	}
	// The v1 fields must be gone, or the widget takes its compatibility path and
	// solves with a decimal-string counter instead of the uint32 we derive against.
	for _, gone := range []string{"challenge", "maxnumber", "number"} {
		if _, present := raw[gone]; present {
			t.Errorf("legacy v1 field %q still emitted", gone)
		}
	}
	// Half the key, and no more: publishing all of it would hand over the answer.
	if prefix, _ := params["keyPrefix"].(string); len(prefix) != altchaKeyPrefixLen*2 {
		t.Errorf("keyPrefix is %d hex chars, want %d (half the key)", len(prefix), altchaKeyPrefixLen*2)
	}
}

// The whole journey, with no provider in existence: fetch a challenge, solve it,
// submit it, get a pass. The verify URL points at a dead port, so a pass here
// proves nothing was called out to.
func TestAltchaEndToEnd(t *testing.T) {
	srv, store := testAltchaServer(t)
	ch := fetchAltchaChallenge(t, srv, "203.0.113.9")
	if ch.Parameters.Algorithm != altchaDefaultAlgorithm || ch.Parameters.KeyPrefix == "" {
		t.Fatalf("malformed challenge: %+v", ch)
	}
	key, found := solveAltcha(ch, testAltchaComplexity)
	if !found {
		t.Fatal("challenge was not solvable within the counter range")
	}

	w := httptest.NewRecorder()
	srv.handle(w, altchaSolveRequest(encodeAltchaPayload(key), "/wp-admin", "203.0.113.9"))
	if w.Code != http.StatusFound {
		t.Fatalf("want a redirect after a good solve, got %d: %s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/wp-admin" {
		t.Fatalf("returned to %q", loc)
	}
	got, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "203.0.113.9 1\n" {
		t.Fatalf("pass map = %q", got)
	}
}

// THE point of this design. A solved payload must work exactly once: the whole
// attack it defends against is one solve being handed round a botnet, each node
// redeeming it for a pass of its own.
func TestAltchaSolutionCannotBeReplayed(t *testing.T) {
	srv, store := testAltchaServer(t)
	ch := fetchAltchaChallenge(t, srv, "203.0.113.9")
	key, _ := solveAltcha(ch, testAltchaComplexity)
	payload := encodeAltchaPayload(key)

	w := httptest.NewRecorder()
	srv.handle(w, altchaSolveRequest(payload, "/", "203.0.113.9"))
	if w.Code != http.StatusFound {
		t.Fatalf("first solve rejected: %d", w.Code)
	}

	// Same payload, same client.
	w2 := httptest.NewRecorder()
	srv.handle(w2, altchaSolveRequest(payload, "/", "203.0.113.9"))
	if w2.Code == http.StatusFound {
		t.Error("the same solution was accepted twice")
	}

	// Same payload, a different client - the botnet case.
	w3 := httptest.NewRecorder()
	srv.handle(w3, altchaSolveRequest(payload, "/", "198.51.100.4"))
	if w3.Code == http.StatusFound {
		t.Error("a solution was redeemed by a client it was not issued to")
	}
	if store.held() != 1 {
		t.Errorf("one solve should mean one pass, got %d", store.held())
	}
}

// A wrong answer must NOT consume the challenge. Consuming it looked stricter and
// was worse: the unpublished half is 16 bytes, so guessing is 2^128 attempts, while
// discarding the entry let a junk POST force a fresh KDF mint and let anyone behind
// the same NAT void a real visitor's challenge mid-solve.
func TestAltchaWrongAnswerKeepsTheChallenge(t *testing.T) {
	srv, _ := testAltchaServer(t)
	ch := fetchAltchaChallenge(t, srv, "203.0.113.9")
	key, _ := solveAltcha(ch, testAltchaComplexity)

	w := httptest.NewRecorder()
	srv.handle(w, altchaSolveRequest(encodeAltchaPayload(strings.Repeat("0", len(key))), "/", "203.0.113.9"))
	if w.Code == http.StatusFound {
		t.Fatal("a wrong key was accepted")
	}
	// The visitor's browser can retry with the challenge it already holds.
	w2 := httptest.NewRecorder()
	srv.handle(w2, altchaSolveRequest(encodeAltchaPayload(key), "/", "203.0.113.9"))
	if w2.Code != http.StatusFound {
		t.Errorf("a wrong guess destroyed a challenge that was still valid: %d", w2.Code)
	}
}

// A junk POST must not buy a fresh challenge. Alternating fetch and junk solve was
// measured at ~1,470 full PBKDF2 mints/sec from one client, on an endpoint nothing
// rate-limits.
func TestAltchaJunkSolveDoesNotForceAFreshMint(t *testing.T) {
	srv, _ := testAltchaServer(t)
	first := fetchAltchaChallenge(t, srv, "203.0.113.9")
	for range 5 {
		srv.handle(httptest.NewRecorder(), altchaSolveRequest(encodeAltchaPayload(wrongDerivedKey), "/", "203.0.113.9"))
		if got := fetchAltchaChallenge(t, srv, "203.0.113.9"); got.Parameters.KeyPrefix != first.Parameters.KeyPrefix {
			t.Fatal("a junk solve caused a new challenge to be minted")
		}
	}
}

// Everyone behind a NAT shares one address, so one of them must not be able to void
// the challenge another is part-way through solving.
func TestAltchaNeighbourCannotVoidAnOutstandingChallenge(t *testing.T) {
	srv, _ := testAltchaServer(t)
	ch := fetchAltchaChallenge(t, srv, "203.0.113.9")
	key, _ := solveAltcha(ch, testAltchaComplexity)

	// The neighbour (or a bot at the same address) submits rubbish repeatedly.
	for range 3 {
		srv.handle(httptest.NewRecorder(), altchaSolveRequest(encodeAltchaPayload(wrongDerivedKey), "/", "203.0.113.9"))
	}
	// The visitor finishes their grind and must still get through.
	w := httptest.NewRecorder()
	srv.handle(w, altchaSolveRequest(encodeAltchaPayload(key), "/", "203.0.113.9"))
	if w.Code != http.StatusFound {
		t.Errorf("a neighbour's junk POSTs denied a legitimate solve: %d", w.Code)
	}
}

// Minting costs a KDF pass, so only the verb the widget uses may trigger one.
func TestAltchaChallengeRejectsNonGet(t *testing.T) {
	srv, _ := testAltchaServer(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, altchaChallengePath, nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	srv.altchaChallenge(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST to the challenge endpoint returned %d, want 405", w.Code)
	}
}

// The endpoint has to be reachable the way Apache actually proxies it - through the
// mux, not by calling the handler. Both altcha tests previously called
// srv.altchaChallenge directly, which is why a routing break went unnoticed.
func TestAltchaChallengeIsRoutableThroughTheMux(t *testing.T) {
	srv, _ := testAltchaServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc(altchaChallengePath, srv.altchaChallenge)
	mux.HandleFunc("/", srv.handle)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, altchaChallengePath, nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("mux returned %d for %s", w.Code, altchaChallengePath)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Fatalf("challenge served as %q - the widget needs JSON, and HTML here is the silent hang", ct)
	}
}

// Reloading the challenge page must not mint new work. Apache sends a challenged
// visitor here on every request, so minting per request would let anyone being
// bounced turn reloads into KDF passes for us.
func TestAltchaReloadReturnsTheSameChallenge(t *testing.T) {
	srv, _ := testAltchaServer(t)
	first := fetchAltchaChallenge(t, srv, "203.0.113.9")
	second := fetchAltchaChallenge(t, srv, "203.0.113.9")
	if first.Parameters.KeyPrefix != second.Parameters.KeyPrefix {
		t.Error("a reload minted a fresh challenge")
	}
	// A different client must get its own.
	other := fetchAltchaChallenge(t, srv, "198.51.100.4")
	if other.Parameters.KeyPrefix == first.Parameters.KeyPrefix {
		t.Error("two clients were issued the same challenge")
	}
}

// Every algorithm we advertise must round-trip. The widget rejects an unknown name
// outright, and one we accept but derive differently from the widget would leave the
// browser grinding to a timeout with no error.
func TestAltchaEveryAdvertisedAlgorithm(t *testing.T) {
	for _, alg := range altchaAlgorithmNames() {
		t.Run(alg, func(t *testing.T) {
			s := newAltchaStore()
			ch, err := s.challengeFor("203.0.113.9", alg, 1, 500, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if ch.Parameters.Algorithm != alg {
				t.Fatalf("algorithm = %q", ch.Parameters.Algorithm)
			}
			// The widget derives an AES-GCM key for the PBKDF2 family, and WebCrypto
			// only accepts 128/192/256-bit AES keys.
			if ch.Parameters.KeyLength != 32 {
				t.Fatalf("%s: keyLength = %d, must be 16/24/32 for AES-GCM", alg, ch.Parameters.KeyLength)
			}
			key, found := solveAltcha(ch, 500)
			if !found {
				t.Fatal("not solvable within the counter range")
			}
			if _, err := s.redeem("203.0.113.9", key, time.Now()); err != nil {
				t.Fatalf("own solution rejected: %v", err)
			}
		})
	}
}

// The counter is appended as four big-endian bytes in the native format, where v1
// appended its decimal string. Getting this wrong still produces a plausible hash for
// every candidate, so nothing errors - the browser simply never finds a match and
// grinds until it times out. Pin it against a fixed vector.
func TestAltchaCounterEncodingIsUint32BigEndian(t *testing.T) {
	params := altchaParameters{Algorithm: "SHA-256", Cost: 1, Salt: "0a0b0c0d", Nonce: "01020304", KeyLength: 32}
	derived, err := altchaDeriveKey(params, 258) // 0x00000102
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x01, 0x02})
	if got, want := hex.EncodeToString(derived), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("derivation mismatch\n got %s\nwant %s", got, want)
	}
}

func TestAltchaRejectsGarbage(t *testing.T) {
	s := newAltchaStore()
	ch, _ := s.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, time.Now())
	key, _ := solveAltcha(ch, testAltchaComplexity)

	for name, payload := range map[string]string{
		"empty":       "",
		"not base64":  "not-base64!!",
		"empty json":  base64.StdEncoding.EncodeToString([]byte("{}")),
		"no solution": base64.StdEncoding.EncodeToString([]byte(`{"solution":{}}`)),
	} {
		if _, err := parseAltchaPayload(payload); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An expired challenge is refused even with the right answer.
	if _, err := s.redeem("203.0.113.9", key, time.Now().Add(altchaChallengeTTL+time.Minute)); err == nil {
		t.Error("accepted an expired challenge")
	}
}

// The page must declare the widget in the form it actually reads.
func TestAltchaPageUsesTheAltchaWidget(t *testing.T) {
	srv, _ := testAltchaServer(t)
	w := httptest.NewRecorder()
	srv.handle(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/crowdsec-verify?r=/x", nil))
	body := w.Body.String()
	for _, want := range []string{
		"<altcha-widget",
		`challenge="/crowdsec-verify/altcha-challenge"`,
		`name="altcha"`,
		// Asserted exactly: the widget ignores an attribute it does not recognise,
		// so a misspelling here would silently fall back to waiting for a click.
		`auto="onload"`,
		`"verified"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("challenge page missing %s", want)
		}
	}
}

// Extending a challenge must move the PUBLISHED expiry too. The widget arms a timer
// from parameters.expiresAt and expires the challenge on arrival if it is already
// past, so a stale value locked a visitor out for the rest of the window with
// nothing logged on either side.
func TestAltchaExtensionMovesThePublishedExpiry(t *testing.T) {
	s := newAltchaStore()
	start := time.Now()
	first, err := s.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, start)
	if err != nil {
		t.Fatal(err)
	}
	// A reload part-way through extends the entry, which is what puts the server-side
	// expiry ahead of the published one.
	if _, err := s.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, start.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Now past the ORIGINAL expiry but still inside the extended one.
	later := start.Add(altchaChallengeTTL + time.Minute)
	again, err := s.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, later)
	if err != nil {
		t.Fatal(err)
	}
	if again.Parameters.KeyPrefix != first.Parameters.KeyPrefix {
		t.Fatal("expected the same challenge back")
	}
	if got := time.Unix(again.Parameters.ExpiresAt, 0); !got.After(later) {
		t.Errorf("published expiresAt is %s, already past at %s - the widget expires this on arrival",
			got.Format(time.RFC3339), later.Format(time.RFC3339))
	}
}

// A path that looks like the challenge endpoint but reached the catch-all means the
// proxy is misconfigured. Serving the HTML page leaves the widget parsing a page as
// JSON: a spinner that never resolves, with nothing in any log.
func TestAltchaMisroutedChallengePathIsRefused(t *testing.T) {
	srv, _ := testAltchaServer(t)
	for _, path := range []string{
		"/crowdsec-verify" + altchaChallengePath, // proxy did not strip the prefix
		altchaChallengePath + "/",                // trailing slash
	} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.9")
		w := httptest.NewRecorder()
		srv.handle(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s returned %d, want 404 - a 200 here is the silent hang", path, w.Code)
		}
	}
}

// Re-fetching must not let one address hold its slot forever. Extension is capped
// at altchaMaxLifetime from the mint; without that cap a visitor (or a bot)
// reloading just before each expiry pushes the entry out another TTL every time,
// and at altchaMaxLive that locks every new client out.
//
// This pins the clamp itself: removing it survives the rest of the suite.
func TestAltchaExtensionIsCappedAtMaxLifetime(t *testing.T) {
	s := newAltchaStore()
	start := time.Now()
	const ip = "203.0.113.9"
	if _, err := s.challengeFor(ip, altchaDefaultAlgorithm, 1, testAltchaComplexity, start); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	first := s.live[ip]
	s.mu.Unlock()

	now := start
	for range 10 {
		// Just before the current expiry, which is what a reload looks like.
		now = now.Add(altchaChallengeTTL - time.Minute)
		if _, err := s.challengeFor(ip, altchaDefaultAlgorithm, 1, testAltchaComplexity, now); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		e, live := s.live[ip]
		s.mu.Unlock()
		if !live {
			t.Fatal("the entry vanished while it was still being re-fetched")
		}
		if e.key != first.key {
			return // aged out and re-minted, which is the cap doing its job
		}
		if limit := first.created.Add(altchaMaxLifetime); e.expires.After(limit) {
			t.Fatalf("re-fetching pushed the expiry to mint+%s, past the %s cap",
				e.expires.Sub(first.created), altchaMaxLifetime)
		}
	}
}

// The salt must be at least 128 bits. FIPS 140-only mode refuses a shorter PBKDF2
// salt, and with the default algorithm that turns every mint into a 500 - no
// visitor on a FIPS-hardened host could obtain a challenge at all. Shrinking it
// back to 12 bytes otherwise survives the whole suite.
func TestAltchaSaltMeetsTheFIPSMinimum(t *testing.T) {
	e, err := newAltchaChallenge(altchaDefaultAlgorithm, 1, testAltchaComplexity, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	salt, err := hex.DecodeString(e.publish().Parameters.Salt)
	if err != nil {
		t.Fatalf("published salt is not hex: %v", err)
	}
	if len(salt) < 16 {
		t.Errorf("salt is %d bytes (%d bits); FIPS 140 refuses a PBKDF2 salt under 16 (128 bits)",
			len(salt), len(salt)*8)
	}
}

// CI runs the suite under -race because "a data race between the metrics scrape and
// the poll loop shipped through three review rounds precisely because the suite was
// green without it". That covered the poll path. Everything this branch added is
// request-paced, and until now nothing drove any of it from two goroutines at once -
// so -race was running with nothing to observe on the new code, and the two
// mechanisms below existed only for the concurrent case that never happened.
//
// Both are asserted by BEHAVIOUR, not just by the race detector: deleting either
// mechanism has to fail here, which a "did not crash" test would not catch.
func TestAltchaStoreUnderConcurrentUse(t *testing.T) {
	const workers = 24

	// Single-flight. Its own comment gives the damage it prevents: "64 connections
	// from one client bought dozens of mints, which is the amplification per-IP
	// keying exists to prevent". One PBKDF2 pass is ~0.7ms on an endpoint that by
	// design cannot be authenticated, so the count is the whole point.
	t.Run("concurrent first requests for one address mint exactly once", func(t *testing.T) {
		s := newAltchaStore()
		var mints atomic.Int64
		s.minted = func() { mints.Add(1) }

		var wg sync.WaitGroup
		var start sync.WaitGroup
		start.Add(1)
		errs := make(chan error, workers)
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				start.Wait() // all in flight together, or single-flight is untested
				if _, err := s.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, time.Now()); err != nil {
					errs <- err
				}
			}()
		}
		start.Done()
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("a concurrent challenge fetch failed: %v", err)
		}
		if got := mints.Load(); got != 1 {
			t.Fatalf("%d derivations for one address, want exactly 1 - single-flight is not holding, so N connections buy N PBKDF2 passes", got)
		}
	})

	// The double-spend re-check in redeem. A sequential replay exits at redeem's
	// `!ok` guard because the first redeem already deleted the entry, so the existing
	// replay test never reaches the re-check - only two concurrent submissions do.
	t.Run("concurrent submissions of one solution are honoured once", func(t *testing.T) {
		s := newAltchaStore()
		ch, err := s.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		key, found := solveAltcha(ch, testAltchaComplexity)
		if !found {
			t.Fatal("the test solver could not solve its own challenge")
		}

		var wg sync.WaitGroup
		var start sync.WaitGroup
		start.Add(1)
		var accepted atomic.Int64
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				start.Wait()
				if _, err := s.redeem("203.0.113.9", key, time.Now()); err == nil {
					accepted.Add(1)
				}
			}()
		}
		start.Done()
		wg.Wait()
		if got := accepted.Load(); got != 1 {
			t.Fatalf("one solution redeemed %d times, want exactly 1", got)
		}
	})
}

// pass.go states the reason it carries a mutex at all: "Unlike the rest of the daemon
// this is touched from two goroutines: the HTTP listener adds passes, the poll loop
// prunes them." Nothing exercised that. prune and writeLocked both RANGE over the
// map while add writes to it, and concurrent map iteration and write is a runtime
// fatal error no recover catches - it takes the whole daemon down, ban enforcement
// included, which is exactly the failure metrics_test.go spells out for the poll
// path. The assertion is -race plus the runtime's own map check.
func TestPassStoreUnderConcurrentAddAndPrune(t *testing.T) {
	store := newPassStore(filepath.Join(t.TempDir(), "captcha_passed.txt"), time.Hour)
	if err := store.reset(); err != nil {
		t.Fatal(err)
	}

	// Distinct keys rather than i%256. With repeats a later add overwrites an
	// earlier one, and then no count of adds against removals has to balance - the
	// conservation check at the end would be unsound rather than merely weak.
	key := func(i int) string { return fmt.Sprintf("203.0.%d.%d", i/256, i%256) }

	// One writer each, both read after wg.Wait, which is the happens-before edge
	// that makes reading them here safe.
	var added, removed, prunes int

	// The pruner runs until the writer is finished rather than for a fixed count.
	// A fixed 300 does not overlap: an add writes the whole map to disk and a prune
	// with nothing to do is one stat, so the pruner finishes while the writer is
	// still on its first handful of entries, and the interleaving this test exists
	// to produce barely happens.
	writerDone := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer close(writerDone)
		for i := range 300 {
			if err := store.add(key(i), time.Now()); err != nil {
				t.Errorf("add: %v", err)
				return
			}
			added++
		}
	}()
	go func() {
		defer wg.Done()
		// Two hours against the one-hour TTL, so every pass in the map has lapsed and
		// prune takes its mutating path. Pruning at time.Now() was the bug in this
		// test: nothing could ever lapse, so every call returned at prune's
		// removed == 0 guard, and the delete, the rewrite and the rollback - the
		// three things this test exists to race against add - ran zero times.
		//
		// Capped as well as signalled: the cap is a runaway guard, not the exit.
		for range 100_000 {
			n, err := store.prune(time.Now().Add(2 * time.Hour))
			if err != nil {
				t.Errorf("prune: %v", err)
				return
			}
			removed += n
			prunes++
			select {
			case <-writerDone:
				return
			default:
			}
		}
	}()
	wg.Wait()

	// The regression guard for what was wrong here. If a later edit puts the prune
	// time back inside the TTL, or raises the TTL past it, nothing lapses and this
	// fires - rather than the test going quietly back to exercising one stat.
	if removed == 0 {
		t.Errorf("%d prunes removed nothing: prune never took its mutating path, so this test raced nothing", prunes)
	}

	// Every pass is either still held or was dropped by exactly one prune. Losing
	// one, or counting one twice, is what a mishandled interleaving looks like on a
	// run where -race happens not to fire - so this is the assertion that makes the
	// test more than a race probe.
	if held := store.held(); removed+held != added {
		t.Errorf("%d passes added, %d pruned + %d held = %d: a pass was lost or double-counted",
			added, removed, held, removed+held)
	}
}

// fillAltchaStoreToCapacity writes altchaMaxLive entries straight into the store.
// The capacity guard counts ENTRIES, not derivations, so it sees exactly what it
// would see under a real flood - and filling honestly would mean 200,000 PBKDF2
// passes, which is why no test reached this branch before. A planted panic in the
// refusal never fired across the whole suite, and three of four semantic mutations
// to the guard survived it.
//
// Capacity is not a parameter because every caller wants exactly the cap: a count
// below it does not reach the guard at all, and one above it tests nothing further.
func fillAltchaStoreToCapacity(t *testing.T, s *altchaStore, expires time.Time) {
	t.Helper()
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range altchaMaxLive {
		s.live[ipAt(i)] = altchaEntry{created: now, expires: expires}
	}
}

func TestAltchaRefusesAtCapacity(t *testing.T) {
	srv, _ := testAltchaServer(t)
	now := time.Now()
	fillAltchaStoreToCapacity(t, srv.altcha, now.Add(time.Hour))

	t.Run("a fresh address is refused with the capacity sentinel", func(t *testing.T) {
		// The sentinel is what lets the handler tell a full store from a config or
		// entropy fault; matching on the message would pass just as well against an
		// unrelated error, which is the thing the counter must not count.
		_, err := srv.altcha.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, now)
		if !errors.Is(err, errAtCapacity) {
			t.Fatalf("challengeFor at capacity = %v, want errAtCapacity", err)
		}
	})

	t.Run("an address already holding a challenge is still served", func(t *testing.T) {
		// Refusing here would lock out precisely the clients partway through solving,
		// which is worse than turning newcomers away.
		if _, err := srv.altcha.challengeFor(ipAt(0), altchaDefaultAlgorithm, 1, testAltchaComplexity, now); err != nil {
			t.Fatalf("an address already in the store was refused at capacity: %v", err)
		}
	})

	t.Run("the endpoint 500s and the refusal counter moves", func(t *testing.T) {
		// The counter is the whole point: at capacity altcha_challenges pins at the cap
		// and challenges_minted_total stops advancing, so without this the exposition
		// is indistinguishable from quiet traffic.
		before := srv.metrics.challengesRefused.Load()
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, altchaChallengePath, nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.10")
		srv.altchaChallenge(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
		}
		if moved := srv.metrics.challengesRefused.Load() - before; moved != 1 {
			t.Errorf("challenges_refused moved by %d, want 1", moved)
		}
	})

	t.Run("an error that is not capacity does not move the refusal counter", func(t *testing.T) {
		// The counter has to mean "the store is full", not "the mint failed". Without
		// this, narrowing the check to errAtCapacity and counting every error look
		// identical, and a config fault would page whoever is on call for a flood.
		// altchaComplexity = 1 trips newAltchaChallenge's counter-range guard, which is
		// a bug-in-the-caller error rather than a capacity one.
		broken, _ := testChallenge(t, func(c *config) { c.altchaComplexity = 1 })
		before := broken.metrics.challengesRefused.Load()
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, altchaChallengePath, nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.12")
		broken.altchaChallenge(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d - the fixture did not produce the error it meant to", w.Code, http.StatusInternalServerError)
		}
		if moved := broken.metrics.challengesRefused.Load() - before; moved != 0 {
			t.Errorf("challenges_refused moved by %d on a non-capacity error, want 0", moved)
		}
	})

	t.Run("a mint that succeeds does not move the refusal counter", func(t *testing.T) {
		// Otherwise the counter would be a request counter wearing a refusal's name,
		// and alerting on it would page for ordinary traffic.
		fresh, _ := testAltchaServer(t)
		before := fresh.metrics.challengesRefused.Load()
		fetchAltchaChallenge(t, fresh, "203.0.113.11")
		if moved := fresh.metrics.challengesRefused.Load() - before; moved != 0 {
			t.Errorf("challenges_refused moved by %d on a successful mint, want 0", moved)
		}
	})
}

// The guard sweeps before refusing, so a store full of lapsed entries must readmit
// rather than turn clients away on a count it no longer really holds. Dropping that
// sweep was one of the mutations the suite used to survive.
func TestAltchaSweepsBeforeRefusingAtCapacity(t *testing.T) {
	srv, _ := testAltchaServer(t)
	now := time.Now()
	fillAltchaStoreToCapacity(t, srv.altcha, now.Add(-time.Minute)) // every entry lapsed

	before := srv.metrics.challengesRefused.Load()
	if _, err := srv.altcha.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, now); err != nil {
		t.Fatalf("a store full of lapsed entries refused a new client: %v", err)
	}
	if moved := srv.metrics.challengesRefused.Load() - before; moved != 0 {
		t.Errorf("challenges_refused moved by %d when the sweep should have made room, want 0", moved)
	}
}

// The sweep walks every entry under s.mu, so a refused request must not be able to
// buy that scan: unthrottled it collapsed a full store to 68 req/s and stalled warm
// clients for hundreds of milliseconds. Driven by setting lastSweep directly, because
// the throttle is only observable as a sweep that does NOT happen.
func TestAltchaThrottlesTheSweepBetweenRefusals(t *testing.T) {
	srv, _ := testAltchaServer(t)
	now := time.Now()
	fillAltchaStoreToCapacity(t, srv.altcha, now.Add(-time.Minute)) // every entry lapsed

	srv.altcha.mu.Lock()
	srv.altcha.lastSweep = now // a sweep has just run
	srv.altcha.mu.Unlock()

	// Inside the window the store must refuse rather than re-scan, even though every
	// entry in it is lapsed and a sweep would have made room.
	if _, err := srv.altcha.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, now); !errors.Is(err, errAtCapacity) {
		t.Fatalf("challengeFor inside the sweep window = %v, want errAtCapacity - the sweep was not throttled", err)
	}
	if held := srv.altcha.held(); held != altchaMaxLive {
		t.Errorf("store holds %d after a throttled refusal, want %d - it swept anyway", held, altchaMaxLive)
	}

	// Past the window the sweep runs again and the client is admitted.
	later := now.Add(altchaSweepEvery + time.Millisecond)
	if _, err := srv.altcha.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, later); err != nil {
		t.Fatalf("challengeFor past the sweep window: %v, want a challenge", err)
	}
}

// The throttle has to be armed by a real refusal, not just honoured once something
// sets lastSweep. Dropping the assignment inside the guard leaves the store sweeping
// on every refusal - the whole defect - and the test above cannot see it, because it
// sets lastSweep itself. So this one never touches the field: it lets the first
// refusal arm the throttle and checks the second is suppressed.
func TestAltchaRefusalArmsTheSweepThrottle(t *testing.T) {
	srv, _ := testAltchaServer(t)
	now := time.Now()
	// Entries lapse partway through the window, so the first refusal has nothing to
	// sweep and the second would find the store clearable if it were allowed to look.
	fillAltchaStoreToCapacity(t, srv.altcha, now.Add(altchaSweepEvery/2))

	if _, err := srv.altcha.challengeFor("203.0.113.9", altchaDefaultAlgorithm, 1, testAltchaComplexity, now); !errors.Is(err, errAtCapacity) {
		t.Fatalf("first refusal = %v, want errAtCapacity", err)
	}

	// Every entry is lapsed by now, but this is still inside the window the first
	// refusal opened, so the scan must not run again.
	within := now.Add(altchaSweepEvery * 3 / 4)
	if _, err := srv.altcha.challengeFor("198.51.100.7", altchaDefaultAlgorithm, 1, testAltchaComplexity, within); !errors.Is(err, errAtCapacity) {
		t.Errorf("second refusal inside the window = %v, want errAtCapacity - the first refusal did not arm the throttle", err)
	}
	if held := srv.altcha.held(); held != altchaMaxLive {
		t.Errorf("store holds %d, want %d - it swept twice inside one window", held, altchaMaxLive)
	}
}
