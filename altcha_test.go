package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Small enough that the test solves it in milliseconds. The counter is uniform
// below this, so scanning to it always finds the answer.
const testAltchaComplexity = 2000

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
		srv.handle(httptest.NewRecorder(), altchaSolveRequest(encodeAltchaPayload("deadbeef"), "/", "203.0.113.9"))
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
		srv.handle(httptest.NewRecorder(), altchaSolveRequest(encodeAltchaPayload("00"), "/", "203.0.113.9"))
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
		`"verified"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("challenge page missing %s", want)
		}
	}
	// No auto= attribute: the widget must wait to be clicked rather than start on
	// load, so merely rendering the page mints nothing.
	if strings.Contains(body, "auto=") {
		t.Error("widget carries an auto= attribute - the page would solve unprompted")
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
