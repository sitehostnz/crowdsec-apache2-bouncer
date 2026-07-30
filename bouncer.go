package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// bouncer holds the HTTP client and the refcounted IP set that backs the map.
type bouncer struct {
	cfg    *config
	client *http.Client

	// refcounted so overlapping decisions sharing an IP are correct
	decisionIPs   map[string]map[string]struct{} // decision id -> set(ip)
	refcount      map[string]int                 // ip -> contributing decisions
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
		decisionIPs: make(map[string]map[string]struct{}),
		refcount:    make(map[string]int),
	}, nil
}

// setsEqual reports whether two IP sets contain exactly the same keys.
func setsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// add records (or refreshes) a decision's IPs in the refcounted set, bumping the
// refcount for each IP it contributes. It's a no-op when the decision's IP set is
// unchanged.
func (b *bouncer) add(d decision) {
	id := d.ID.String()
	if id == "" {
		return
	}
	var newIPs map[string]struct{}
	if b.included(d) {
		newIPs = b.expand(d)
	}
	oldIPs, existed := b.decisionIPs[id]
	if existed && setsEqual(oldIPs, newIPs) {
		return
	}
	if existed {
		b.unref(oldIPs)
		delete(b.decisionIPs, id)
	}
	if len(newIPs) > 0 {
		b.decisionIPs[id] = newIPs
		for ip := range newIPs {
			b.refcount[ip]++
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

// unref decrements the refcount of each IP, deleting it from the set once no
// remaining decision references it.
func (b *bouncer) unref(ips map[string]struct{}) {
	for ip := range ips {
		if b.refcount[ip] <= 1 {
			delete(b.refcount, ip)
		} else {
			b.refcount[ip]--
		}
	}
}

// snapshotIPs captures the current blocklist keyset so apply* can report how
// many IPs actually appeared/disappeared (decision counts != IP counts: one
// range decision is many IPs, an overlapping ban is zero net change).
func (b *bouncer) snapshotIPs() map[string]struct{} {
	before := make(map[string]struct{}, len(b.refcount))
	for ip := range b.refcount {
		before[ip] = struct{}{}
	}
	return before
}

// diffIPs compares the current IP set against a snapshot, returning how many IPs
// were added and removed.
func (b *bouncer) diffIPs(before map[string]struct{}) (added, removed int) {
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

// applyFull rebuilds the whole IP set from a full snapshot of decisions and
// returns the net IPs added/removed versus before.
func (b *bouncer) applyFull(newDecisions []decision) (added, removed int) {
	before := b.snapshotIPs()
	b.decisionIPs = make(map[string]map[string]struct{})
	b.refcount = make(map[string]int)
	b.skippedRanges = 0
	for _, d := range newDecisions {
		b.add(d)
	}
	return b.diffIPs(before)
}

// applyDelta applies an incremental update (deleted decisions first, then new
// ones) and returns the net IPs added/removed versus before.
func (b *bouncer) applyDelta(newDecisions, deleted []decision) (added, removed int) {
	before := b.snapshotIPs()
	b.skippedRanges = 0
	for _, d := range deleted {
		b.remove(d)
	}
	for _, d := range newDecisions {
		b.add(d)
	}
	return b.diffIPs(before)
}
