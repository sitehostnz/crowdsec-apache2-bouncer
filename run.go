package main

import (
	"context"
	"log"
	"strings"
	"time"
)

// warnAboutEnforcement says, once at startup, where the configuration leaves
// decisions written but unenforced. Every case here is silent otherwise: the maps
// fill up exactly as they should and the poll lines look healthy, while Apache
// blocks less than the operator thinks - or nothing at all.
func (b *bouncer) warnAboutEnforcement() {
	log.Printf("remediation policy: bouncing_on=%s override=%q fallback=%q -> ban:%s captcha:%s throttle:%s",
		b.cfg.bouncingOnType, b.cfg.overrideRemediation, b.cfg.fallbackRemediation,
		describeRemediation(b.cfg.resolveRemediation(remediationBan)),
		describeRemediation(b.cfg.resolveRemediation(remediationCaptcha)),
		describeRemediation(b.cfg.resolveRemediation("throttle")))

	// There is deliberately no "captcha map with no listener" warning here any more.
	// That state needed an empty FALLBACK_REMEDIATION to reach: with the fallback
	// always set, a captcha that cannot be served resolves to the fallback instead,
	// so the captcha map is never rendered without a listener behind it. A warning
	// for an unreachable state is worse than none - it implies the check is load
	// bearing when nothing can trip it.
	if b.byType[remediationBan] == nil {
		log.Printf("WARNING: nothing renders to a ban map under this policy, so no request will ever be refused outright")
	}
}

// describeRemediation renders what a decision type resolves to for the startup
// line, naming the case where it resolves to nothing at all.
func describeRemediation(r string) string {
	if r == "" {
		return "ignored"
	}
	return r
}

// run does the initial full sync (retrying until it succeeds) then loops on
// UPDATE_FREQUENCY, applying deltas or a periodic full resync until ctx is
// cancelled. It never wipes the list on an LAPI error.
func (b *bouncer) run(ctx context.Context) {
	maps := make([]string, 0, len(b.remediations))
	for _, r := range b.remediations {
		out := r.txt
		if b.cfg.mapType == "dbm" {
			out = r.dbm
		}
		maps = append(maps, r.name+"="+out)
	}
	log.Printf("starting: lapi=%s map=%s out=[%s] freq=%s expand_cap=%d",
		b.cfg.lapiURL, b.cfg.mapType, strings.Join(maps, " "), b.cfg.updateFrequency, b.cfg.expandMaxHosts)
	b.warnAboutEnforcement()

	// The operator lists don't come from the LAPI, so put them in place before the
	// first fetch: Apache refuses to start on a missing RewriteMap file, and the
	// initial sync below can retry for a long time if the LAPI is unreachable.
	b.syncCustomLists()
	b.ensureMap()
	b.retireUnusedMaps()
	b.startChallenge(ctx)
	// Deferred rather than called at each return, so shutting down during the initial
	// sync retry clears the pass map too. run is called synchronously from main, so
	// unlike a defer inside the listener goroutine this cannot lose a race with
	// process exit.
	defer b.stopChallenge()
	// AFTER startChallenge, and that order is load-bearing rather than tidy:
	// renderMetrics reads b.passes and b.altcha from the scrape goroutine, and
	// starting that goroutine here is the only thing making startChallenge's writes
	// to those fields visible to it. Hoisting this line above startChallenge would be
	// a data race on both fields, which -race would only catch if a test happened to
	// scrape during startup.
	go b.serveMetrics(ctx)

	// initial full sync - retry forever; never write an empty file on a fetch failure.
	//
	// An empty snapshot from a SUCCESSFUL fetch is not covered. heldIPs is 0 on the
	// first pass, so the floor in acceptSnapshot short-circuits and the snapshot is
	// taken at face value, while the map on disk may hold a full list that write()
	// then truncates - the mass unban ensureMap's comment describes, via the one path
	// ensureMap cannot cover (it runs before this loop and skips existing maps).
	//
	// So the refusal branch below covers the second and later passes only. Closing the
	// first-pass gap means giving heldIPs a source on disk; nothing reads r.txt back
	// today. Known gap.
	backoff := time.Second
	for {
		sr, err := b.fetch(ctx, true)
		if err == nil {
			added, removed, accepted := b.applyFull(sr.New)
			// Write either way: applyFull has already rolled a refused snapshot back, so
			// this still lands the retained list and self-heals a deleted map.
			werr := b.write()
			if werr != nil {
				log.Printf("startup write failed: %v; retry in %s", werr, backoff)
			} else if !accepted {
				// Before the DBM check, so a broken httxt2dbm cannot mask a refusal. No
				// break: falling through fetches the confirming snapshot, where breaking
				// would stamp lastFull and push it a whole RESYNC_INTERVAL out. It cannot
				// spin - the second consecutive refusal takes pendingShrink to 2.
				b.metrics.resyncRefused.Add(1)
				log.Printf("WARNING: startup snapshot would have removed %d IPs and added %d, against %s held - refusing to unban that much on a single snapshot; keeping the current list and re-checking in %s",
					removed, added, b.totals(), backoff)
			} else if missing := b.missingDBM(); missing != "" {
				log.Printf("startup: DBM %s not built (httxt2dbm failed?); retry in %s", missing, backoff)
			} else {
				log.Printf("startup ok: %d decisions -> %s IPs (%d ranges skipped)",
					b.decisionCount(), b.totals(), b.skippedRanges)
				break
			}
		} else {
			log.Printf("startup failed: %v; retry in %s (check API key/URL)", err, backoff)
		}
		// Expire challenges and passes while we retry. The listener came up before
		// this loop and is already minting, but prunePasses lives in the ticker loop
		// below - which a failing startup sync never reaches. Left alone, an LAPI
		// outage meant challenges accumulated to capacity and then refused everyone,
		// while anyone who solved during the outage stayed exempt indefinitely.
		b.prunePasses()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}

	lastFull := time.Now()
	ticker := time.NewTicker(b.cfg.updateFrequency)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("shutting down")
			return
		case <-ticker.C:
		}
		cycleStart := time.Now()
		b.syncCustomLists() // independent of the LAPI, so do it even if the poll fails
		b.prunePasses()     // likewise: lapsed passes must expire even while the LAPI is down
		resync := b.cfg.resyncInterval > 0 && time.Since(lastFull) >= b.cfg.resyncInterval
		sr, err := b.fetch(ctx, resync)
		if err != nil {
			b.metrics.pollsFailed.Add(1)
			observeDuration(&b.metrics.lastPollSecs, time.Since(cycleStart))
			log.Printf("poll failed (%v); keeping current list", err)
			continue
		}
		b.metrics.pollsOK.Add(1)
		b.metrics.lastPollUnix.Store(time.Now().Unix())
		switch {
		case resync:
			added, removed, accepted := b.applyFull(sr.New)
			if !accepted {
				// lastFull is not advanced, so the next tick asks for another snapshot
				// instead of waiting a whole RESYNC_INTERVAL to confirm. The list is
				// already rolled back, so this write still self-heals a deleted map.
				b.metrics.resyncRefused.Add(1)
				log.Printf("WARNING: resync would have removed %d IPs and added %d, against %s held - refusing to unban that much on a single snapshot; keeping the current list and re-checking on the next poll",
					removed, added, b.totals())
				if err := b.write(); err != nil {
					log.Printf("write failed: %v", err)
				}
				continue
			}
			lastFull = time.Now()
			b.metrics.resyncsOK.Add(1)
			// always rewrite on resync (self-heals an externally deleted file)
			if err := b.write(); err != nil {
				log.Printf("write failed: %v", err)
				continue
			}
			log.Printf("resync: %d decisions -> %s IPs (+%d added, -%d removed)",
				b.decisionCount(), b.totals(), added, removed)
		case len(sr.New) > 0 || len(sr.Deleted) > 0:
			added, removed := b.applyDelta(sr.New, sr.Deleted)
			// only rewrite (and rebuild the DBM) when the IP set actually changed -
			// an overlapping re-ban of an already-listed IP is a no-op for the file
			if added > 0 || removed > 0 {
				if err := b.write(); err != nil {
					log.Printf("write failed: %v", err)
					continue
				}
			}
			log.Printf("update: decisions +%d/-%d -> IPs +%d added, -%d removed (total %s)",
				len(sr.New), len(sr.Deleted), added, removed, b.totals())
		default:
			log.Printf("poll: no changes (total %s)", b.totals())
		}
		observeDuration(&b.metrics.lastPollSecs, time.Since(cycleStart))
	}
}
