package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// bouncer holds the HTTP client and one refcounted IP set per remediation type
// it enforces, each backing its own Apache map.
type bouncer struct {
	cfg    *config
	client *http.Client

	// state guards the list against the metrics listener, which is the only other
	// goroutine that reads it. Held across a whole apply rather than around each
	// read: applyFull empties every map before refilling it, so a scrape landing
	// in that window would otherwise report a near-zero map_ips for a list that
	// never actually changed - and page someone over it.
	//
	// Nothing else needs it. The poll loop is the sole writer, and the render
	// path runs on that same goroutine.
	state sync.RWMutex

	// remediations is the enforced set per decision type, in config order, and
	// byType indexes the same values for routing a decision to its set.
	remediations []*remediation
	byType       map[string]*remediation

	// operator-maintained allow/deny lists kept beside the CrowdSec maps; nil
	// when CUSTOM_LIST_DIR is empty
	customLists []*customList

	// passes records clients that have solved a challenge; nil unless the
	// challenge listener is configured and came up
	passes *passStore

	// altcha holds the challenges currently in flight, so the poll loop can expire
	// the ones nobody came back for; nil unless the listener came up
	altcha *altchaStore

	// pendingShrink counts consecutive full snapshots that would have dropped most
	// of the list; see acceptSnapshot.
	pendingShrink int

	skippedRanges int

	// metrics is always present; the listener that exposes it is optional.
	metrics *metrics
}

// A full snapshot replaces the list wholesale, so one that arrives short unbans
// everything it omits. A truncated-but-valid 200 is indistinguishable from a
// genuine mass-unban at the point of decode - the LAPI can commit a 200 and start
// writing JSON before it finishes reading its database - so a snapshot that would
// drop most of the list is treated as suspect rather than authoritative.
const (
	// minSnapshotDecisions is the size below which the list is too small for a
	// proportional test to mean anything: a handful of decisions can legitimately
	// halve in one interval.
	minSnapshotDecisions = 50
	// snapshotShrinkDenom expresses the limit as a fraction: a snapshot holding
	// fewer than 1/2 of the decisions currently held has to be confirmed.
	snapshotShrinkDenom = 2
)

// acceptSnapshot reports whether a full snapshot should be allowed to replace the
// current list. A big shrink is refused the first time and accepted only if the
// next snapshot agrees, so a transient LAPI fault costs one resync interval of
// staleness instead of unbanning everyone. A genuine flush still lands, one
// interval later.
//
// The test is across every remediation at once, because one snapshot carries all
// of them: a response truncated mid-stream shortens whichever types it cut off,
// and judging each map on its own would let a small one veto an otherwise good
// snapshot.
func (b *bouncer) acceptSnapshot(incoming int) bool {
	held := b.decisionCount()
	if held < minSnapshotDecisions || incoming*snapshotShrinkDenom >= held {
		b.pendingShrink = 0
		return true
	}
	b.pendingShrink++
	if b.pendingShrink >= 2 {
		b.pendingShrink = 0
		return true // a second snapshot agrees, so the drop is real
	}
	return false
}

// newBouncer constructs a bouncer, wiring the HTTP client's TLS trust from the
// config: the system CA store by default, a custom CA_BUNDLE, or INSECURE.
func newBouncer(cfg *config) (*bouncer, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// REQUEST_TIMEOUT bounds connecting + waiting for the LAPI to start responding
	// (fast-fail if it's unreachable/unresponsive). The overall per-query deadline,
	// including reading a large stream body, is STREAM_REQUEST_TIMEOUT (applied per
	// request in fetch).
	transport.DialContext = (&net.Dialer{Timeout: cfg.requestTimeout, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = cfg.requestTimeout
	transport.ResponseHeaderTimeout = cfg.requestTimeout
	if strings.HasPrefix(strings.ToLower(cfg.lapiURL), "https") {
		tlsCfg := &tls.Config{}
		if cfg.insecure {
			log.Printf("WARNING: INSECURE=true - TLS verification disabled")
			tlsCfg.InsecureSkipVerify = true
		} else if cfg.caBundle != "" {
			pem, err := os.ReadFile(cfg.caBundle)
			if err != nil {
				return nil, fmt.Errorf("CA_BUNDLE: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("CA_BUNDLE %s: no certificates found", cfg.caBundle)
			}
			tlsCfg.RootCAs = pool
		}
		transport.TLSClientConfig = tlsCfg
	}
	rems := make([]*remediation, 0, len(cfg.remediations))
	byType := make(map[string]*remediation, len(cfg.remediations))
	for _, name := range cfg.remediations {
		txt, dbm := cfg.mapPaths(name)
		r := newRemediation(name, txt, dbm)
		rems = append(rems, r)
		byType[name] = r
	}
	return &bouncer{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			// Never follow a redirect. Go strips only the Authorization/Cookie
			// family when a redirect crosses hosts, so the X-Api-Key set in fetch
			// would be handed verbatim to whatever the target is - and that key
			// reads the whole decision stream, usually shared across bouncers. The
			// stream endpoint has no legitimate reason to redirect, so returning
			// the 3xx unfollowed turns it into a non-200, which lands in the
			// existing "keep the current list" path.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		metrics:      newMetrics(),
		remediations: rems,
		byType:       byType,
		customLists:  newCustomLists(cfg.customListDir),
	}, nil
}

// setFor returns the set a decision of this type belongs in, or nil when the
// bouncer renders no map for it. Matching is case-insensitive: the LAPI's casing
// is not guaranteed.
//
// FORCE_REMEDIATION sends every enforceable decision to one map regardless of its
// own type. It still only redirects types the bouncer would otherwise have
// enforced - a throttle has no map of its own, and forcing it into one would
// apply a remediation the hub never asked for.
func (b *bouncer) setFor(decisionType string) *remediation {
	return b.byType[b.cfg.resolveRemediation(decisionType)]
}

// decisionCount is the number of decisions held across every map.
func (b *bouncer) decisionCount() int {
	n := 0
	for _, r := range b.remediations {
		n += len(r.decisionIPs)
	}
	return n
}

// totals renders the per-map IP counts for the log lines, e.g. "ban=128963
// captcha=412". One aggregate number would hide the map that stopped growing.
func (b *bouncer) totals() string {
	var sb strings.Builder
	for i, r := range b.remediations {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%s=%d", r.name, len(r.refcount))
	}
	return sb.String()
}

// forget drops a decision from every set except keep. It is what stops a
// decision that changed type between polls - a captcha the hub has escalated to
// a ban - from lingering in the map it no longer belongs to and being enforced
// twice, and it deletes by id rather than by the type on the decision, because
// the id is the part the LAPI guarantees is stable.
func (b *bouncer) forget(id string, keep *remediation) {
	for _, r := range b.remediations {
		if r == keep {
			continue
		}
		if ips, ok := r.decisionIPs[id]; ok {
			delete(r.decisionIPs, id)
			r.unref(ips)
		}
	}
}

// add records (or refreshes) a decision's IPs in the set for its remediation
// type, bumping the refcount for each IP it contributes. It's a no-op when the
// decision's IPs are unchanged - expand is deterministic, so comparing the slices
// in order is the same test as comparing them as sets.
func (b *bouncer) add(d decision) {
	id := d.ID.String()
	if id == "" {
		return
	}
	r := b.setFor(d.Type)
	b.forget(id, r) // it may have arrived under a different type last time
	if r == nil {
		return // a type this bouncer renders no map for
	}
	var newIPs []string
	if b.included(d) {
		newIPs = b.expand(d)
	}
	oldIPs, existed := r.decisionIPs[id]
	if existed && slices.Equal(oldIPs, newIPs) {
		return
	}
	if existed {
		r.unref(oldIPs)
		delete(r.decisionIPs, id)
	}
	if len(newIPs) > 0 {
		r.decisionIPs[id] = newIPs
		for _, ip := range newIPs {
			r.ref(ip)
		}
	}
}

// remove drops a decision and decrements the refcount of every IP it contributed,
// wherever it was held.
func (b *bouncer) remove(d decision) {
	if id := d.ID.String(); id != "" {
		b.forget(id, nil)
	}
}

// applyFull rebuilds every map from a full snapshot of decisions and returns the
// net IPs added/removed versus before, summed across the maps. It diffs each
// outgoing refcount map against its replacement directly - they are being
// replaced anyway, so there is nothing to copy.
func (b *bouncer) applyFull(newDecisions []decision) (added, removed int) {
	b.state.Lock()
	defer b.state.Unlock()

	before := make([]map[string]int, len(b.remediations))
	for i, r := range b.remediations {
		before[i] = r.reset(len(newDecisions))
	}
	b.skippedRanges = 0
	for _, d := range newDecisions {
		b.add(d)
	}
	for i, r := range b.remediations {
		r.rebuildSorted()
		a, rm := r.diff(before[i])
		added, removed = added+a, removed+rm
	}
	return added, removed
}

// applyDelta applies an incremental update (deleted decisions first, then new
// ones) and returns the net IPs added/removed versus before, summed across the
// maps.
func (b *bouncer) applyDelta(newDecisions, deleted []decision) (added, removed int) {
	b.state.Lock()
	defer b.state.Unlock()

	b.skippedRanges = 0
	for _, r := range b.remediations {
		r.touched = make(map[string]bool, len(newDecisions)+len(deleted))
	}
	for _, d := range deleted {
		b.remove(d)
	}
	for _, d := range newDecisions {
		b.add(d)
	}
	for _, r := range b.remediations {
		a, rm := r.settle()
		added, removed = added+a, removed+rm
		r.touched = nil
	}
	return added, removed
}
