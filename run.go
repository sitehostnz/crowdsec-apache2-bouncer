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

	// A captcha map with no listener is inert: the file fills up correctly and
	// Apache does nothing with it, which looks identical to working. Only reachable
	// when FALLBACK_REMEDIATION is empty, since otherwise it degrades instead.
	if captcha := b.byType[remediationCaptcha]; captcha != nil && !b.cfg.captchaUsable() {
		log.Printf("WARNING: captcha decisions are being written to %s, but CAPTCHA_LISTEN is unset so no challenge is served - nothing enforces that map. Set FALLBACK_REMEDIATION=ban to block them instead",
			captcha.txt)
	}
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
	go b.serveMetrics(ctx)

	// initial full sync - retry forever; never write an empty file on failure
	backoff := time.Second
	for {
		sr, err := b.fetch(ctx, true)
		if err == nil {
			b.applyFull(sr.New)
			if werr := b.write(); werr != nil {
				log.Printf("startup write failed: %v; retry in %s", werr, backoff)
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
			if !b.acceptSnapshot(len(sr.New)) {
				// lastFull is deliberately NOT advanced, so the next tick asks for
				// another snapshot rather than waiting a whole RESYNC_INTERVAL to
				// confirm. The list is untouched, so this write still self-heals a
				// deleted map; only the incoming snapshot is withheld.
				b.metrics.resyncRefused.Add(1)
				log.Printf("WARNING: resync returned %d decisions against %d held - refusing to unban that much on a single snapshot; keeping the current list and re-checking on the next poll",
					len(sr.New), b.decisionCount())
				if err := b.write(); err != nil {
					log.Printf("write failed: %v", err)
				}
				continue
			}
			lastFull = time.Now()
			b.metrics.resyncsOK.Add(1)
			added, removed := b.applyFull(sr.New)
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
