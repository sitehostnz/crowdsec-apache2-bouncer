package main

import (
	"context"
	"log"
	"time"
)

// run does the initial full sync (retrying until it succeeds) then loops on
// UPDATE_FREQUENCY, applying deltas or a periodic full resync until ctx is
// cancelled. It never wipes the list on an LAPI error.
func (b *bouncer) run(ctx context.Context) {
	mapOut := b.cfg.outputFile
	if b.cfg.mapType == "dbm" {
		mapOut = b.cfg.dbmFile
	}
	log.Printf("starting: lapi=%s map=%s out=%s freq=%s expand_cap=%d only_ban=%t",
		b.cfg.lapiURL, b.cfg.mapType, mapOut, b.cfg.updateFrequency, b.cfg.expandMaxHosts, b.cfg.onlyBan)

	// The operator lists don't come from the LAPI, so put them in place before the
	// first fetch: Apache refuses to start on a missing RewriteMap file, and the
	// initial sync below can retry for a long time if the LAPI is unreachable.
	b.syncCustomLists()

	// initial full sync - retry forever; never write an empty file on failure
	backoff := time.Second
	for {
		sr, err := b.fetch(ctx, true)
		if err == nil {
			b.applyFull(sr.New)
			if werr := b.write(); werr != nil {
				log.Printf("startup write failed: %v; retry in %s", werr, backoff)
			} else if !b.dbmReady() {
				log.Printf("startup: DBM %s not built (httxt2dbm failed?); retry in %s", b.cfg.dbmFile, backoff)
			} else {
				log.Printf("startup ok: %d decisions -> %d IPs (%d ranges skipped) -> %s",
					len(b.decisionIPs), len(b.refcount), b.skippedRanges, mapOut)
				break
			}
		} else {
			log.Printf("startup failed: %v; retry in %s (check API key/URL)", err, backoff)
		}
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
		b.syncCustomLists() // independent of the LAPI, so do it even if the poll fails
		resync := b.cfg.resyncInterval > 0 && time.Since(lastFull) >= b.cfg.resyncInterval
		sr, err := b.fetch(ctx, resync)
		if err != nil {
			log.Printf("poll failed (%v); keeping current list", err)
			continue
		}
		switch {
		case resync:
			added, removed := b.applyFull(sr.New)
			lastFull = time.Now()
			// always rewrite on resync (self-heals an externally deleted file)
			if err := b.write(); err != nil {
				log.Printf("write failed: %v", err)
				continue
			}
			log.Printf("resync: %d decisions -> %d IPs (+%d added, -%d removed)",
				len(b.decisionIPs), len(b.refcount), added, removed)
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
			log.Printf("update: decisions +%d/-%d -> IPs +%d added, -%d removed (total %d)",
				len(sr.New), len(sr.Deleted), added, removed, len(b.refcount))
		default:
			log.Printf("poll: no changes (total %d)", len(b.refcount))
		}
	}
}
