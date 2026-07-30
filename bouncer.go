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
	"time"
)

// bouncer holds the HTTP client and the refcounted IP set that backs the map.
type bouncer struct {
	cfg    *config
	client *http.Client

	// refcounted so overlapping decisions sharing an IP are correct
	decisionIPs map[string][]string // decision id -> the IPs it contributes
	refcount    map[string]int      // ip -> contributing decisions

	// sortedIPs is the blocklist keyset held in sorted order and maintained as
	// IPs enter and leave, so writeTxt never re-sorts a list that barely moved:
	// a poll typically changes a handful of IPs out of six figures.
	sortedIPs []string

	// touched is non-nil only for the duration of an applyDelta. It records, for
	// each IP whose refcount crossed zero, whether that IP was in the list when
	// the delta started - which makes the added/removed report O(changed) rather
	// than O(list). applyFull leaves it nil and diffs the two maps directly.
	touched map[string]bool

	skippedRanges int
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
	return &bouncer{
		cfg:         cfg,
		client:      &http.Client{Transport: transport},
		decisionIPs: make(map[string][]string),
		refcount:    make(map[string]int),
	}, nil
}

// add records (or refreshes) a decision's IPs in the refcounted set, bumping the
// refcount for each IP it contributes. It's a no-op when the decision's IPs are
// unchanged - expand is deterministic, so comparing the slices in order is the
// same test as comparing them as sets.
func (b *bouncer) add(d decision) {
	id := d.ID.String()
	if id == "" {
		return
	}
	var newIPs []string
	if b.included(d) {
		newIPs = b.expand(d)
	}
	oldIPs, existed := b.decisionIPs[id]
	if existed && slices.Equal(oldIPs, newIPs) {
		return
	}
	if existed {
		b.unref(oldIPs)
		delete(b.decisionIPs, id)
	}
	if len(newIPs) > 0 {
		b.decisionIPs[id] = newIPs
		for _, ip := range newIPs {
			b.ref(ip)
		}
	}
}

// remove drops a decision and decrements the refcount of every IP it contributed.
func (b *bouncer) remove(d decision) {
	id := d.ID.String()
	if id == "" {
		return
	}
	oldIPs, ok := b.decisionIPs[id]
	if !ok {
		return
	}
	delete(b.decisionIPs, id)
	b.unref(oldIPs)
}

// ref adds one reference to ip, putting it on the blocklist if it's the first.
func (b *bouncer) ref(ip string) {
	n := b.refcount[ip]
	if n == 0 {
		b.note(ip, false)
	}
	b.refcount[ip] = n + 1
}

// unref decrements the refcount of each IP, deleting it from the set once no
// remaining decision references it.
func (b *bouncer) unref(ips []string) {
	for _, ip := range ips {
		if n := b.refcount[ip]; n <= 1 {
			delete(b.refcount, ip)
			b.note(ip, true)
		} else {
			b.refcount[ip] = n - 1
		}
	}
}

// note records an IP's presence as at the START of the current delta, and only
// the first time that IP moves. An IP that leaves and re-enters within the one
// delta therefore nets to zero, which is what a before/after set diff would have
// reported.
func (b *bouncer) note(ip string, presentBefore bool) {
	if b.touched == nil {
		return // applyFull: the old-vs-new map diff covers it instead
	}
	if _, seen := b.touched[ip]; !seen {
		b.touched[ip] = presentBefore
	}
}

// resortThreshold is the point where splicing changes into sortedIPs one at a
// time stops paying: a splice is a single O(N) memmove (tens of microseconds at
// six-figure lists) against ~20ms for a full rebuild-and-sort, so the crossover
// is a few hundred changes. Below it, splice; above it - a bulk blocklist import
// - rebuild once, because 80k splices would be quadratic.
const resortThreshold = 512

// settle turns the touched set into the added/removed counts applyDelta reports
// and brings sortedIPs back in step, both in O(changed).
func (b *bouncer) settle() (added, removed int) {
	type change struct {
		ip    string
		added bool
	}
	// only worth collecting while splicing is still on the table - one past the
	// threshold is enough to know we've lost that bet and will rebuild instead.
	changes := make([]change, 0, min(len(b.touched), resortThreshold+1))
	for ip, presentBefore := range b.touched {
		_, presentNow := b.refcount[ip]
		switch {
		case presentNow && !presentBefore:
			added++
			if len(changes) <= resortThreshold {
				changes = append(changes, change{ip, true})
			}
		case !presentNow && presentBefore:
			removed++
			if len(changes) <= resortThreshold {
				changes = append(changes, change{ip, false})
			}
		}
	}
	if len(changes) > resortThreshold {
		b.rebuildSorted()
		return added, removed
	}
	for _, c := range changes {
		if c.added {
			b.insertSorted(c.ip)
		} else {
			b.removeSorted(c.ip)
		}
	}
	return added, removed
}

// insertSorted splices ip into sortedIPs at its ordered position.
func (b *bouncer) insertSorted(ip string) {
	i, found := slices.BinarySearch(b.sortedIPs, ip)
	if found {
		return // already listed; refcount, not this slice, counts the holders
	}
	b.sortedIPs = slices.Insert(b.sortedIPs, i, ip)
}

// removeSorted drops ip from sortedIPs.
func (b *bouncer) removeSorted(ip string) {
	if i, found := slices.BinarySearch(b.sortedIPs, ip); found {
		b.sortedIPs = slices.Delete(b.sortedIPs, i, i+1)
	}
}

// rebuildSorted regenerates sortedIPs from the refcount keyset - for a full
// snapshot, or a delta big enough that splicing each change would cost more than
// one sort.
func (b *bouncer) rebuildSorted() {
	b.sortedIPs = slices.Grow(b.sortedIPs[:0], len(b.refcount))
	for ip := range b.refcount {
		b.sortedIPs = append(b.sortedIPs, ip)
	}
	slices.Sort(b.sortedIPs)
}

// applyFull rebuilds the whole IP set from a full snapshot of decisions and
// returns the net IPs added/removed versus before (decision counts != IP counts:
// one range decision is many IPs, an overlapping ban is zero net change). It
// diffs the outgoing refcount map against the incoming one directly - it's
// replacing the map anyway, so there's nothing to copy.
func (b *bouncer) applyFull(newDecisions []decision) (added, removed int) {
	before := b.refcount
	b.decisionIPs = make(map[string][]string, len(newDecisions))
	// on a resync the previous size is the better estimate; on a cold start there
	// is no previous size, and one IP per decision is the floor.
	b.refcount = make(map[string]int, max(len(before), len(newDecisions)))
	b.skippedRanges = 0
	for _, d := range newDecisions {
		b.add(d)
	}
	b.rebuildSorted()
	for ip := range b.refcount {
		if _, ok := before[ip]; !ok {
			added++
		}
	}
	for ip := range before {
		if _, ok := b.refcount[ip]; !ok {
			removed++
		}
	}
	return added, removed
}

// applyDelta applies an incremental update (deleted decisions first, then new
// ones) and returns the net IPs added/removed versus before.
func (b *bouncer) applyDelta(newDecisions, deleted []decision) (added, removed int) {
	b.skippedRanges = 0
	b.touched = make(map[string]bool, len(newDecisions)+len(deleted))
	for _, d := range deleted {
		b.remove(d)
	}
	for _, d := range newDecisions {
		b.add(d)
	}
	added, removed = b.settle()
	b.touched = nil
	return added, removed
}
