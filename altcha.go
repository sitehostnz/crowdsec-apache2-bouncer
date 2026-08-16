package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log"
	"maps"
	"math"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"
)

// ALTCHA needs no captcha service at all. Where Cap has the daemon POST a token to
// another host and wait for a verdict, ALTCHA has the daemon issue the challenge
// itself and check the answer locally.
//
// That removes the Cap container, its Valkey, the network round trip, the secret
// crossing the wire, and the per-IP rate limiter that all of the Apache proxying
// existed to serve.
//
// HOW THE PROOF WORKS. We derive a key from a counter we keep to ourselves and
// publish only its FIRST HALF. The browser walks counters up from zero, running the
// KDF over nonce||counter each time, until the derived key starts with the published
// prefix - then sends back the whole key. The unpublished half is the proof: it
// cannot be known without having run the KDF at the right counter.
//
// So verification is a string comparison, not a KDF pass. Three things follow, and
// they are why this shape was chosen over signing a stateless challenge:
//
//   - a challenge is single-use BY CONSTRUCTION, because redeeming it removes it.
//     Replay is not something a second mechanism has to catch; there is nothing left
//     to replay. This is the property Cap gets from its siteverify getdel, and the
//     one ALTCHA's security guidance asks implementers to provide.
//   - verifying costs one comparison rather than re-deriving, which matters because
//     the cost dial multiplies a KDF pass.
//   - there is no signature to reproduce byte for byte, so nothing depends on
//     canonical JSON.
//
// The cost is that a challenge lives in this process: it does not survive a restart
// and could not be verified by a second instance. That matches how the pass map
// already behaves.
//
// Outstanding challenges are keyed by CLIENT IP, not by nonce. Minting one costs a
// KDF pass, and Apache sends a challenged visitor here on every request, so keying
// by nonce would let anyone already being bounced turn page reloads into arbitrary
// work for us. Keyed by IP, a visitor gets the same challenge back until they solve
// it or it expires - which is also the rate limiting ALTCHA's notes ask for. Sharing
// one challenge across a NAT costs nothing, because the pass beside it is already
// per IP.
//
// This mirrors the nginx bouncer's lua implementation deliberately, so the two
// behave the same way when something has to be debugged at 3am.

// altchaAlgorithms are the ones the published widget can actually solve: it looks
// the name up in a registry and throws "Unsupported algorithm" for anything else,
// before doing any work. Two families behind these names - see altchaDeriveKey.
//
// The two families cost the BROWSER very differently, which is the thing to know
// before changing ALTCHA_ALGORITHM. PBKDF2 is one importKey + deriveKey + exportKey
// per candidate whatever cost is, because the iterations happen inside WebCrypto.
// The plain family is a loop of `await crypto.subtle.digest` - cost separate awaited
// calls per candidate - so at the shipped defaults it asks for ~12,500,000 WebCrypto
// calls against PBKDF2's ~7,500. Per-call overhead dominates, the widget's own 90s
// timeout fires, and solveChallenge returns null with no error: the silent hang
// again. altchaWebCryptoCalls exists to refuse that at startup.
//
// The longer digests are not "stronger" here either - the work is the search, not
// the hash. They are faster per byte on 64-bit hardware, so within the PLAIN family
// they make the grind slightly cheaper; within PBKDF2 the call count is what
// matters and the digest barely shows.
//
// argon2id and scrypt are deliberately absent. The widget ships workers for them,
// but both are memory-hard, and we run the same derivation to mint every challenge
// on an endpoint that is unauthenticated by necessity. That turns issuance into an
// amplifier.
var altchaAlgorithms = map[string]struct {
	newHash func() hash.Hash
	pbkdf2  bool
}{
	"SHA-256":        {sha256.New, false},
	"SHA-384":        {sha512.New384, false},
	"SHA-512":        {sha512.New, false},
	"PBKDF2/SHA-256": {sha256.New, true},
	"PBKDF2/SHA-384": {sha512.New384, true},
	"PBKDF2/SHA-512": {sha512.New, true},
}

const (
	// The default when ALTCHA_ALGORITHM is unset, matching the nginx bouncer.
	altchaDefaultAlgorithm = "PBKDF2/SHA-256"
	// The full path to the ESM build, pinned. NOT the bare package URL: that
	// resolves to the package "main", a .cjs file jsDelivr serves as
	// Content-Type application/node with nosniff, which browsers refuse to execute.
	// The widget then never registers, the element never upgrades, and the page sits
	// on "Verifying your connection" forever with nothing wrong in the markup and
	// nothing logged anywhere.
	//
	// Pinned because an unreviewed major would arrive on every customer page with no
	// deploy here, and the attribute names moved between v1 and v3.
	altchaDefaultWidgetJS = "https://cdn.jsdelivr.net/npm/altcha@3.2.1/dist/main/altcha.js"
	// The SRI digest of that exact build, so the browser refuses anything else.
	//
	// Pinning the version covers a bad upstream RELEASE. It does nothing about a
	// compromised or hijacked CDN edge, which is the more serious case: the
	// challenge page is served on the customer's own origin, to visitors of every
	// vhost we challenge, so script the CDN substitutes would run with the
	// customer's cookies. Version pinning and SRI answer different threats and this
	// needs both.
	//
	// Regenerate when the pinned version moves:
	//
	//	curl -sL <url> | openssl dgst -sha384 -binary | openssl base64 -A
	altchaDefaultWidgetSRI = "sha384-brhp3NfINJBvUHF6gRWcBMLNYdQHko9s54cNvo7jLY0Ldzll9Ff1DG0JApAN83a4"
	// 32 bytes derived, the first 16 published as keyPrefix. The widget derives an
	// AES-GCM key for the PBKDF2 family and WebCrypto only accepts 128/192/256-bit
	// AES keys, so 32 is also the largest value valid across every algorithm here.
	altchaKeyLength    = 32
	altchaKeyPrefixLen = altchaKeyLength / 2
	// Together these are ~12.5M PBKDF2 iterations - a second or two of browser work
	// spread across its workers.
	//
	// The nginx bouncer uses the same cost with complexity 10000, so this asks for
	// half the work it does. Deliberate: the check only has to be expensive enough
	// that grinding it at scale costs more than it is worth, and the visitor paying
	// it is one we have already decided is suspicious but probably human.
	//
	// Weighted towards cost rather than complexity on purpose. On paper complexity
	// is the cheaper dial - it costs the client alone, where cost is also paid once
	// per challenge we mint - and the same client work could be had with cost=1 and
	// complexity around 7,000,000. But every candidate is a separate
	// crypto.subtle.deriveKey call in the browser, and millions of those would be
	// dominated by per-call overhead rather than by the KDF. Fewer, heavier
	// candidates amortise that away.
	altchaDefaultCost       = 5000
	altchaDefaultComplexity = 5000
	// 20 minutes: ALTCHA's guidance asks for 20 minutes to an hour, and the low end
	// is right for us. The widget waits to be clicked now, so the gap between
	// issuing and redeeming is however long a person takes to notice the checkbox -
	// and a backgrounded tab has its workers throttled.
	altchaChallengeTTL = 20 * time.Minute
	// However often a challenge is re-fetched, it stops being extended this long
	// after it was minted. Extension is what keeps a slow visitor's answer valid
	// (see challengeFor); the cap is what stops an address holding a slot forever,
	// which at capacity would deny every new client a challenge.
	altchaMaxLifetime = 2 * altchaChallengeTTL
)

// altchaParameters is the challenge body the widget solves. There is deliberately
// no signature: the challenge is remembered rather than signed.
type altchaParameters struct {
	Algorithm string `json:"algorithm"`
	Cost      int    `json:"cost"`
	ExpiresAt int64  `json:"expiresAt"`
	KeyLength int    `json:"keyLength"`
	KeyPrefix string `json:"keyPrefix"`
	Nonce     string `json:"nonce"`
	Salt      string `json:"salt"`
}

// altchaChallenge is the JSON the widget fetches.
type altchaChallenge struct {
	Parameters altchaParameters `json:"parameters"`
}

// altchaSolution is the widget's answer. Only derivedKey is read: "counter" is the
// client telling us how it got there, which we neither need nor trust, and "time"
// is telemetry.
type altchaSolution struct {
	DerivedKey string `json:"derivedKey"`
}

// altchaPayload is what the widget submits, base64-encoded in the form field. The
// challenge it echoes back is ignored entirely - the answer is looked up by the IP
// we issued it to, so a caller cannot point the lookup somewhere else.
type altchaPayload struct {
	Solution altchaSolution `json:"solution"`
}

// altchaDeriveKey reproduces the widget's derivation for one candidate counter.
// This is the whole proof-of-work: the client calls it until the result matches, we
// call it once to mint.
func altchaDeriveKey(p altchaParameters, counter uint32) ([]byte, error) {
	alg, ok := altchaAlgorithms[p.Algorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm %q", p.Algorithm)
	}
	salt, err := hex.DecodeString(p.Salt)
	if err != nil {
		return nil, fmt.Errorf("salt is not hex: %w", err)
	}
	nonce, err := hex.DecodeString(p.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce is not hex: %w", err)
	}
	keyLength := p.KeyLength
	if keyLength <= 0 {
		keyLength = altchaKeyLength
	}
	iterations := max(1, p.Cost)

	// The counter is appended big-endian in four bytes - PasswordBuffer.setCounter
	// in the widget's native "uint32" mode. The legacy v1 mode appended its decimal
	// string instead, which is the only wire difference in the solving loop.
	password := make([]byte, len(nonce)+4)
	copy(password, nonce)
	binary.BigEndian.PutUint32(password[len(nonce):], counter)

	if alg.pbkdf2 {
		return pbkdf2.Key(alg.newHash, string(password), salt, iterations, keyLength)
	}
	// Plain family: hash salt||password once, then re-hash the previous derived key
	// for each further iteration, truncating each round - matching the widget's
	// digest(...).slice(0, keyLength).
	//
	// One digest and two buffers for the whole loop, not a fresh h := New /
	// h.Sum(nil) per round: that shape allocated ~800KB across 10k objects for one
	// cost-5000 mint, all garbage, which under a mint flood was more allocator and
	// GC work than hashing. Two buffers rather than one, so Sum never appends over
	// the bytes the digest was just fed.
	h := alg.newHash()
	cur := make([]byte, 0, h.Size())
	next := make([]byte, 0, h.Size())
	for i := 0; i < iterations; i++ {
		h.Reset()
		if i == 0 {
			h.Write(salt)
			h.Write(password)
		} else {
			h.Write(cur)
		}
		next = h.Sum(next[:0])
		if keyLength < len(next) {
			next = next[:keyLength]
		}
		cur, next = next, cur
	}
	return cur, nil
}

// altchaEntry is one outstanding challenge and the answer it expects, held raw.
// Hex strings and the published JSON are rebuilt by publish on each fetch rather
// than stored: entries exist to survive a flood - one per address whoever is
// attacking cares to name - so the resident shape is the one worth shrinking.
// Raw, an entry retains about half of what the string form did (measured by
// BenchmarkAltchaHeapAtCap), and the per-fetch encoding it buys back is noise
// beside the JSON marshalling that follows it.
type altchaEntry struct {
	algorithm string // one of altchaAlgorithms' keys; shares the config's string
	cost      int
	key       [altchaKeyLength]byte // the whole derived key; only half is ever published
	salt      [16]byte
	nonce     [16]byte
	created   time.Time
	expires   time.Time
}

// publish renders the JSON body the widget fetches. Only the key's first half
// goes out; the rest cannot be known without running the KDF at the right
// counter, which is the work being asked for.
//
// ExpiresAt is read from the entry's own expiry every time, so however often the
// challenge is re-issued or extended, the published copy cannot fall out of step
// with the one enforced. That is load-bearing: the widget arms a timer from
// parameters.expiresAt and calls onExpired() immediately when it is already
// past, so a published value staler than the entry's hands the visitor a
// challenge their browser expires on arrival - no verified event, no submit,
// nothing logged.
func (e altchaEntry) publish() altchaChallenge {
	return altchaChallenge{Parameters: altchaParameters{
		Algorithm: e.algorithm,
		Cost:      e.cost,
		ExpiresAt: e.expires.Unix(),
		KeyLength: altchaKeyLength,
		KeyPrefix: hex.EncodeToString(e.key[:altchaKeyPrefixLen]),
		Nonce:     hex.EncodeToString(e.nonce[:]),
		Salt:      hex.EncodeToString(e.salt[:]),
	}}
}

// altchaMaxLive caps the challenges held at once. One entry per challenged address
// at ~195 bytes (BenchmarkAltchaHeapAtCap), and the addresses are chosen by whoever
// is attacking: a single IPv6 /64 offers 2^64 of them, each a fresh key. Unbounded,
// that is hundreds of MB and eventually an OOM kill - which takes ban enforcement
// down with it, not just the captcha. 200k entries is ~37MiB and far above any real
// number of simultaneously challenged clients.
const altchaMaxLive = 200_000

// altchaStore holds the challenges currently in flight, one per client. Touched
// from every request goroutine, hence the mutex.
type altchaStore struct {
	mu   sync.Mutex
	live map[string]altchaEntry
	// minting holds one channel per address currently being derived for, closed
	// when that derivation lands. Without it, N concurrent requests for a cold
	// address all miss the cache and all derive: 64 connections from one client
	// bought dozens of mints, which is the amplification per-IP keying exists to
	// prevent. Now the first caller derives and the rest wait for its result.
	minting map[string]chan struct{}
	// minted counts DERIVATIONS, for the metric - not insertions. Counting inserts
	// undercounted exactly the flood the metric exists to show.
	minted func()
	// full is set while the store is at capacity, so the log line is written once
	// per episode rather than once per request.
	full bool
}

func newAltchaStore() *altchaStore {
	return &altchaStore{
		live:    make(map[string]altchaEntry),
		minting: make(map[string]chan struct{}),
		minted:  func() {},
	}
}

// challengeFor returns the challenge outstanding for ip, minting one if there is
// none. Returning the SAME challenge to a repeat request is what stops a challenged
// visitor turning reloads into KDF work - and it costs them nothing, because the one
// they already hold is still solvable.
func (s *altchaStore) challengeFor(ip, algorithm string, cost int, maxCounter int64, now time.Time) (altchaChallenge, error) {
	var done chan struct{}
	for {
		s.mu.Lock()
		if e, ok := s.live[ip]; ok && now.Before(e.expires) {
			// A live entry is handed back as-is and given MORE time, never replaced.
			// Replacing it voided an answer already being computed: a second tab, a
			// NAT neighbour loading the page, or simply a slow visitor would discard
			// a correct multi-second solve and show "We couldn't verify that".
			//
			// Extension is capped at altchaMaxLifetime from the mint, so re-fetching
			// cannot hold a slot indefinitely - which at capacity would lock every
			// new client out.
			if ext := now.Add(altchaChallengeTTL); ext.After(e.expires) {
				if limit := e.created.Add(altchaMaxLifetime); ext.After(limit) {
					ext = limit
				}
				e.expires = ext
				s.live[ip] = e
			}
			// publish derives the widget-visible expiry from e.expires, so the
			// extension above reaches the browser's timer as well as our own.
			ch := e.publish()
			s.mu.Unlock()
			return ch, nil
		}
		if inflight, busy := s.minting[ip]; busy {
			// Someone is already deriving for this address. Wait for their result
			// rather than deriving in parallel: without this, N concurrent first
			// requests from one client each paid a full KDF, which is the
			// amplification per-IP keying exists to prevent.
			s.mu.Unlock()
			<-inflight
			continue
		}
		// Capacity is checked BEFORE deriving. Checking afterwards meant every
		// request at capacity paid a full PBKDF2 and then threw it away - the cap
		// bounded memory but not CPU, on an endpoint nothing authenticates.
		_, replacing := s.live[ip]
		if !replacing && len(s.live) >= altchaMaxLive {
			s.pruneLocked(now) // prune only runs on the poll tick; sweep before refusing
			_, replacing = s.live[ip]
		}
		if !replacing && len(s.live) >= altchaMaxLive {
			full := !s.full
			s.full = true
			n := len(s.live)
			s.mu.Unlock()
			if full {
				log.Printf("altcha: %d challenges outstanding, at capacity - refusing new ones. "+
					"A challenged client cannot solve without a challenge, so it stays blocked; "+
					"entries age out %s after minting, but rate limit /crowdsec-verify at Apache "+
					"if this is not transient.", n, altchaMaxLifetime)
			}
			return altchaChallenge{}, errors.New("too many challenges outstanding")
		}
		s.full = false
		done = make(chan struct{})
		s.minting[ip] = done
		s.mu.Unlock()
		break
	}
	defer func() {
		s.mu.Lock()
		delete(s.minting, ip)
		s.mu.Unlock()
		close(done) // after the delete, so a waiter re-checking finds no claim
	}()

	// Derive OUTSIDE the store mutex. Holding it across the KDF serialised every
	// redeem, prune and held() behind ~730us of work, so a /metrics scrape was the
	// first thing to stall under exactly the flood an operator was trying to see.
	s.minted() // a derivation, counted whether or not it ends up being stored
	e, err := newAltchaChallenge(algorithm, cost, maxCounter, now)
	if err != nil {
		return altchaChallenge{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.live[ip] = e
	return e.publish(), nil
}

// redeem checks a submitted key against the challenge issued to ip, consuming the
// challenge only when the answer is RIGHT.
//
// Consuming it on a wrong answer too - which is what the nginx implementation does
// - looks stricter and is worse on both counts. It bought nothing: the unpublished
// half is 16 bytes, so "unlimited guesses" means 2^128 of them. And it cost two
// real attacks, because the entry is keyed by IP:
//
//   - a junk POST freed the address to be issued a brand-new challenge, so two
//     cheap requests bought a full KDF mint. Alternating GET and junk POST pinned
//     a core at ~1,470 mints/sec on an endpoint nothing rate-limits.
//   - anyone sharing a NAT could void a legitimate visitor's outstanding challenge
//     mid-solve, indefinitely, for the cost of one request per second.
//
// A wrong answer now leaves the challenge in place, so the visitor's browser can
// simply try again with the one it already holds - and an attacker gains no
// leverage, because a fresh challenge is exactly what they were trying to force.
func (s *altchaStore) redeem(ip, derivedKey string, now time.Time) (altchaEntry, error) {
	s.mu.Lock()
	e, ok := s.live[ip]
	s.mu.Unlock()

	if !ok {
		// Expired, never issued, or already spent - indistinguishable from here, and
		// all mean the same thing: take a fresh challenge.
		return altchaEntry{}, errors.New("no challenge outstanding for this client")
	}
	if now.After(e.expires) {
		return altchaEntry{}, errors.New("challenge expired")
	}
	// hex.DecodeString reads either case, which is the case-insensitivity the
	// strings.ToLower this replaces provided; anything that is not hex at all
	// fails the decode and is rejected the same as a wrong answer.
	submitted, err := hex.DecodeString(derivedKey)
	if err != nil || len(submitted) != len(e.key) ||
		subtle.ConstantTimeCompare(submitted, e.key[:]) != 1 {
		return altchaEntry{}, errors.New("solution does not match the challenge")
	}
	// Right answer: spend it. Deleting under the lock, and only if the entry is
	// still the one we compared against, so two concurrent correct submissions
	// cannot both be honoured.
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, still := s.live[ip]; !still || cur.key != e.key {
		return altchaEntry{}, errors.New("challenge already spent")
	}
	delete(s.live, ip)
	return e, nil // returned so the caller can restore it if it cannot finish
}

// restore puts a redeemed challenge back. The caller consumed it and then could not
// finish - persisting the pass failed - so the visitor would otherwise have to
// re-grind a fresh multi-second challenge for a fault that was ours.
func (s *altchaStore) restore(ip string, e altchaEntry, now time.Time) {
	if !now.Before(e.expires) {
		return // nothing to give back
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.live[ip]; !taken {
		s.live[ip] = e
	}
}

// prune drops challenges nobody came back for. Called on the poll tick, beside the
// pass map, so an abandoned challenge cannot pin memory beyond its TTL.
func (s *altchaStore) prune(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneLocked(now)
}

// pruneLocked is prune's body; callers hold the mutex.
func (s *altchaStore) pruneLocked(now time.Time) int {
	before := len(s.live)
	removed := 0
	for ip, e := range s.live {
		if now.After(e.expires) {
			delete(s.live, ip)
			removed++
		}
	}
	// Go never returns bucket memory on delete, so a flood's peak footprint would
	// otherwise be permanent for the life of the process. Rebuild once the map has
	// mostly emptied - the same reasoning as remediation.go's sortedIPs handling.
	if removed > 0 && len(s.live)*4 < before {
		fresh := make(map[string]altchaEntry, len(s.live))
		maps.Copy(fresh, s.live)
		s.live = fresh
	}
	return removed
}

// held reports how many challenges are outstanding, for the log lines.
func (s *altchaStore) held() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

// newAltchaChallenge picks a secret counter below maxCounter and derives the key
// from it, returning the entry to remember; publish is what exposes the key's
// first half. maxCounter is the work dial: the client scans upward from zero, so
// it expects to try half of them.
func newAltchaChallenge(algorithm string, cost int, maxCounter int64, now time.Time) (altchaEntry, error) {
	if _, ok := altchaAlgorithms[algorithm]; !ok {
		return altchaEntry{}, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
	if maxCounter < 2 {
		// Refuse rather than clamp, and refuse 1 as well as 0: rand.Int over [0,1)
		// always returns zero, so maxCounter = 1 means the counter is always zero,
		// so the "proof" is a fixed value anyone can compute - a captcha that looks
		// like it is working and asks for nothing. The config floor keeps this out of
		// reach in production; a caller that gets here has a bug worth hearing about.
		return altchaEntry{}, fmt.Errorf("counter range %d is too small to ask any work of the client", maxCounter)
	}
	if maxCounter > math.MaxUint32 {
		// The counter is carried in four bytes, so anything past this is unreachable
		// for the client no matter how long it grinds.
		maxCounter = math.MaxUint32
	}
	// 16 bytes, not 12: FIPS 140-only mode refuses a PBKDF2 salt under 128 bits,
	// and with the default algorithm that turns every mint into a 500 - no visitor
	// on a FIPS-hardened host could obtain a challenge at all.
	var saltRaw, nonceRaw [16]byte
	if _, err := rand.Read(saltRaw[:]); err != nil {
		return altchaEntry{}, err
	}
	if _, err := rand.Read(nonceRaw[:]); err != nil {
		return altchaEntry{}, err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(maxCounter))
	if err != nil {
		return altchaEntry{}, err
	}

	// The transient hex form, because the derivation is shared byte-for-byte with
	// the widget's - altchaDeriveKey reads the published wire format, and minting
	// through the same code path is what keeps the two provably in agreement.
	params := altchaParameters{
		Algorithm: algorithm,
		Cost:      max(1, cost),
		KeyLength: altchaKeyLength,
		Nonce:     hex.EncodeToString(nonceRaw[:]),
		Salt:      hex.EncodeToString(saltRaw[:]),
	}
	counter := n.Int64()
	if counter < 0 || counter > math.MaxUint32 {
		// Unreachable: maxCounter is clamped to MaxUint32 above. Explicit so the
		// conversion below is provably in range rather than merely known to be.
		return altchaEntry{}, fmt.Errorf("counter %d out of range", counter)
	}
	derived, err := altchaDeriveKey(params, uint32(counter))
	if err != nil {
		return altchaEntry{}, err
	}
	if len(derived) != altchaKeyLength {
		// Unreachable with the params above; explicit so the array conversion below
		// cannot panic on a future caller that gets this wrong.
		return altchaEntry{}, fmt.Errorf("derived key is %d bytes, want %d", len(derived), altchaKeyLength)
	}
	return altchaEntry{
		algorithm: algorithm,
		cost:      params.Cost,
		key:       [altchaKeyLength]byte(derived),
		salt:      saltRaw,
		nonce:     nonceRaw,
		created:   now,
		expires:   now.Add(altchaChallengeTTL),
	}, nil
}

// parseAltchaPayload pulls the derived key out of what the widget submitted.
// Nothing else in the payload is used: the challenge it echoes back is the client's
// own copy, and trusting any of it would undo the point of looking the answer up by
// IP.
func parseAltchaPayload(encoded string) (string, error) {
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("payload is not base64: %w", err)
	}
	var p altchaPayload
	if err := json.Unmarshal(blob, &p); err != nil {
		return "", fmt.Errorf("payload is not the expected JSON: %w", err)
	}
	// A solution is always exactly the hex of an altchaKeyLength key. Checking the
	// length here means an oversized one is rejected before redeem lower-cases and
	// converts it - three more copies of whatever was sent.
	if got := len(p.Solution.DerivedKey); got != altchaKeyLength*2 {
		return "", fmt.Errorf("derived key is %d characters, want %d", got, altchaKeyLength*2)
	}
	return p.Solution.DerivedKey, nil
}

// altchaAlgorithmNames lists the supported names, sorted, for error messages.
func altchaAlgorithmNames() []string {
	names := make([]string, 0, len(altchaAlgorithms))
	for name := range altchaAlgorithms {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// altchaWebCryptoCalls estimates the crypto.subtle calls a browser makes for an
// expected solve. It is the number that decides whether a configuration is
// solvable at all, and it is not proportional to the configured work: the two
// families spend it completely differently. See altchaAlgorithms.
func altchaWebCryptoCalls(algorithm string, cost int, complexity int64) int64 {
	candidates := max(1, complexity/2)
	if alg, ok := altchaAlgorithms[algorithm]; ok && alg.pbkdf2 {
		return candidates * 3 // importKey + deriveKey + exportKey, cost is internal
	}
	return candidates * int64(max(1, cost))
}

// altchaMaxWebCryptoCalls is where a configuration stops being solvable. The widget
// gives up at 90 seconds; a browser gets through very roughly 100k awaited
// crypto.subtle calls a second on a decent machine, so a few million is already
// beyond a phone. Deliberately generous - this is here to catch the configuration
// that cannot work at all, not to second-guess a deliberate one.
const altchaMaxWebCryptoCalls = 5_000_000

// altchaMaxIterations bounds the TOTAL work a solve asks for, which the call count
// cannot see for PBKDF2 - there the iterations happen inside a single call. The
// shipped defaults are ~12.5M, and a browser spreads them across its workers in a
// second or two; 250M is an order of magnitude past that and well beyond the widget's
// timeout on anything portable.
const altchaMaxIterations = 250_000_000

// canonicalAltchaAlgorithm accepts the widget's names in any case. The names are
// mixed-case on the wire ("PBKDF2/SHA-256"), so an operator writing
// "pbkdf2/sha-256" is spelling it the way a config file usually looks rather than
// making a mistake.
func canonicalAltchaAlgorithm(name string) string {
	for known := range altchaAlgorithms {
		if strings.EqualFold(known, name) {
			return known
		}
	}
	return name
}
