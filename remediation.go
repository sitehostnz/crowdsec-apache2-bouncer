package main

import "slices"

// remediation is the refcounted IP set for one CrowdSec decision type, together
// with the pair of map files it renders to.
//
// There is one per type the bouncer enforces, because the type decides both
// which map Apache consults and what Apache then does with a hit: a ban is
// blocked outright, a captcha has to be challenged instead. Rendering them into
// one map would silently turn every captcha into a block. The sets are separate
// rather than one set tagged by type because a single IP can hold decisions of
// both kinds at once, each expiring on its own schedule.
type remediation struct {
	name string // the decision type, lowercased: "ban" | "captcha"
	txt  string // the rendered "<ip> 1" map
	dbm  string // the hash map built from txt, when MAP_TYPE=dbm

	// refcounted so overlapping decisions sharing an IP are correct
	decisionIPs map[string][]string // decision id -> the IPs it contributes
	refcount    map[string]int      // ip -> contributing decisions

	// sortedIPs is the keyset held in sorted order and maintained as IPs enter
	// and leave, so writeTxt never re-sorts a list that barely moved: a poll
	// typically changes a handful of IPs out of six figures.
	sortedIPs []string

	// touched is non-nil only for the duration of an applyDelta. It records, for
	// each IP whose refcount crossed zero, whether that IP was in the list when
	// the delta started - which makes the added/removed report O(changed) rather
	// than O(list). A full snapshot leaves it nil and diffs the two maps instead.
	touched map[string]bool
}

// newRemediation builds an empty set for one decision type.
func newRemediation(name, txt, dbm string) *remediation {
	return &remediation{
		name:        name,
		txt:         txt,
		dbm:         dbm,
		decisionIPs: make(map[string][]string),
		refcount:    make(map[string]int),
	}
}

// ref adds one reference to ip, putting it on the list if it's the first.
func (r *remediation) ref(ip string) {
	n := r.refcount[ip]
	if n == 0 {
		r.note(ip, false)
	}
	r.refcount[ip] = n + 1
}

// unref decrements the refcount of each IP, deleting it from the set once no
// remaining decision references it.
func (r *remediation) unref(ips []string) {
	for _, ip := range ips {
		if n := r.refcount[ip]; n <= 1 {
			delete(r.refcount, ip)
			r.note(ip, true)
		} else {
			r.refcount[ip] = n - 1
		}
	}
}

// note records an IP's presence as at the START of the current delta, and only
// the first time that IP moves. An IP that leaves and re-enters within the one
// delta therefore nets to zero, which is what a before/after set diff would have
// reported.
func (r *remediation) note(ip string, presentBefore bool) {
	if r.touched == nil {
		return // full snapshot: the old-vs-new map diff covers it instead
	}
	if _, seen := r.touched[ip]; !seen {
		r.touched[ip] = presentBefore
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
func (r *remediation) settle() (added, removed int) {
	type change struct {
		ip    string
		added bool
	}
	// only worth collecting while splicing is still on the table - one past the
	// threshold is enough to know we've lost that bet and will rebuild instead.
	changes := make([]change, 0, min(len(r.touched), resortThreshold+1))
	for ip, presentBefore := range r.touched {
		_, presentNow := r.refcount[ip]
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
		r.rebuildSorted()
		return added, removed
	}
	for _, c := range changes {
		if c.added {
			r.insertSorted(c.ip)
		} else {
			r.removeSorted(c.ip)
		}
	}
	return added, removed
}

// insertSorted splices ip into sortedIPs at its ordered position.
func (r *remediation) insertSorted(ip string) {
	i, found := slices.BinarySearch(r.sortedIPs, ip)
	if found {
		return // already listed; refcount, not this slice, counts the holders
	}
	r.sortedIPs = slices.Insert(r.sortedIPs, i, ip)
}

// removeSorted drops ip from sortedIPs.
func (r *remediation) removeSorted(ip string) {
	if i, found := slices.BinarySearch(r.sortedIPs, ip); found {
		r.sortedIPs = slices.Delete(r.sortedIPs, i, i+1)
	}
}

// rebuildSorted regenerates sortedIPs from the refcount keyset - for a full
// snapshot, or a delta big enough that splicing each change would cost more than
// one sort.
func (r *remediation) rebuildSorted() {
	r.sortedIPs = slices.Grow(r.sortedIPs[:0], len(r.refcount))
	for ip := range r.refcount {
		r.sortedIPs = append(r.sortedIPs, ip)
	}
	slices.Sort(r.sortedIPs)
}

// remediationState is the pair of maps a full snapshot displaces, kept for the
// duration of the apply so a refused snapshot can be put back; see applyFull.
//
// sortedIPs is not part of it: rebuildSorted reuses that slice's backing array, so a
// stashed copy would alias the rebuilt one. restore regenerates it from refcount.
type remediationState struct {
	decisionIPs map[string][]string
	refcount    map[string]int
}

// reset empties the set for a full snapshot and returns the state it replaced,
// for diff to compare against and restore to put back. The previous size is the
// better estimate of the next one on a resync; on a cold start there is none, so
// one IP per decision is the floor.
func (r *remediation) reset(decisions int) (before remediationState) {
	before = remediationState{decisionIPs: r.decisionIPs, refcount: r.refcount}
	size := len(before.refcount)
	if size == 0 {
		size = decisions
	}
	r.decisionIPs = make(map[string][]string, len(r.decisionIPs))
	r.refcount = make(map[string]int, size)
	return before
}

// restore puts back the state reset displaced, undoing a full snapshot that was
// applied and then refused.
func (r *remediation) restore(before remediationState) {
	r.decisionIPs = before.decisionIPs
	r.refcount = before.refcount
	r.rebuildSorted()
}

// diff reports how the set changed against the refcount map it replaced. Decision
// counts are not IP counts: one range decision is many IPs, and an overlapping
// ban is no net change at all.
func (r *remediation) diff(before map[string]int) (added, removed int) {
	for ip := range r.refcount {
		if _, ok := before[ip]; !ok {
			added++
		}
	}
	for ip := range before {
		if _, ok := r.refcount[ip]; !ok {
			removed++
		}
	}
	return added, removed
}
