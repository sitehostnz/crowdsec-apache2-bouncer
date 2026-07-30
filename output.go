package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// write renders the txt map and, when MAP_TYPE=dbm, rebuilds the DBM. A DBM
// failure is logged but never fatal - the previous DBM is kept.
func (b *bouncer) write() error {
	if err := b.writeTxt(); err != nil {
		return err
	}
	if b.cfg.mapType == "dbm" {
		b.buildDBM() // keeps the previous DBM on failure; logs, never fatal
	}
	return nil
}

// writeTxt writes the sorted "<ip> 1" map to a temp file and atomically renames
// it into place, so Apache never reads a half-written map and the mtime bump
// triggers a RewriteMap reload.
func (b *bouncer) writeTxt() error {
	dir := filepath.Dir(b.cfg.outputFile)
	// 0755: Apache's worker user (daemon/apache) must traverse this directory
	// to read the map.
	// #nosec G301
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".blocklist.*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name()) // no-op after successful rename
	}()

	// sortedIPs is kept in order as the set changes, so there is nothing to
	// collect or sort here - only the render. One buffer beats streaming through
	// a bufio.Writer: measured, the extra write syscalls cost more than the
	// allocation saves.
	w := make([]byte, 0, len(b.sortedIPs)*20)
	for _, ip := range b.sortedIPs {
		w = append(w, ip...)
		w = append(w, " 1\n"...)
	}
	if _, err := tmp.Write(w); err != nil {
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// No fsync by design: after a crash the list is rebuilt from the LAPI on the
	// next startup, so durability of this file isn't required.
	return os.Rename(tmp.Name(), b.cfg.outputFile) // atomic; mtime change -> RewriteMap reload
}

// buildDBM rebuilds the CrowdSec map's DBM. A failure is logged but never fatal.
// The error says what state the map is in, so it is logged as-is.
func (b *bouncer) buildDBM() {
	if err := b.buildDBMFrom(b.cfg.outputFile, b.cfg.dbmFile); err != nil {
		log.Printf("%v", err)
	}
}

// buildDBMFrom converts the txt map at src into a DBM at dst (O(1) lookups) via
// Apache's httxt2dbm, then moves the generated file(s) into place. Globbing the
// temp basename handles both single-file (DB/GDBM) and two-file (SDBM .pag/.dir)
// backends. On failure dst is left exactly as it was, so a bad conversion never
// costs Apache the map it already has.
func (b *bouncer) buildDBMFrom(src, dst string) error {
	base := dst
	tmp := base + ".new"
	if stale, _ := filepath.Glob(tmp + "*"); len(stale) > 0 {
		for _, f := range stale {
			_ = os.Remove(f)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// binary path and file arguments come from operator-owned config
	// (HTTXT2DBM/OUTPUT_FILE/CUSTOM_LIST_DIR), never from request or decision data.
	// #nosec G204
	out, err := exec.CommandContext(ctx, b.cfg.httxt2dbm, "-i", src, "-o", tmp).CombinedOutput()
	// Nothing has been moved yet on either of these paths, so whatever Apache is
	// reading is untouched - which is the useful half of the message.
	if err != nil {
		return fmt.Errorf("httxt2dbm %s failed (%w): %s; keeping the previous %s",
			src, err, strings.TrimSpace(string(out)), dst)
	}
	produced, _ := filepath.Glob(tmp + "*")
	if len(produced) == 0 {
		return fmt.Errorf("httxt2dbm produced no output for %s; keeping the previous %s", src, dst)
	}
	// NOTE: for two-file backends (SDBM .pag/.dir) this is one rename per file, so
	// there is a brief window where Apache can read a new .pag with an old .dir.
	// The window is short and rebuilds are infrequent, and a fully atomic
	// multi-file swap isn't feasible without hardlink tricks - prefer a single-file
	// backend (or pin SDBM per the README) if this matters.
	var swapErrs []error
	for _, f := range produced {
		suffix := strings.TrimPrefix(f, tmp) // "" | ".db" | ".pag" | ".dir"
		// best effort: the converter may have run as another user (e.g. via a
		// docker wrapper), in which case chmod fails but the file is still 0644.
		// 0644 is required: Apache's worker user must read the map.
		// #nosec G302
		_ = os.Chmod(f, 0o644)
		if err := os.Rename(f, base+suffix); err != nil {
			// Past this point some files may already have moved, so the previous map
			// is NOT necessarily intact - say that rather than reassuring wrongly.
			swapErrs = append(swapErrs, fmt.Errorf(
				"swapping %s into place: %w; %s may now be a mix of old and new files", f, err, dst))
		}
	}
	return errors.Join(swapErrs...)
}

// ensureMap writes an empty map, and its DBM, when none exists yet. Apache
// validates every RewriteMap file as it parses its config and refuses to start if
// one is missing, and Before=apache2.service does not actually hold the web server
// back: with Type=simple systemd considers this unit started the moment it execs,
// while the first snapshot can retry for a long time against an unreachable LAPI.
// On a boot where the LAPI comes up after Apache, that would take every site on
// the host down - far worse than a briefly empty ban list.
//
// An existing map is left completely alone. Overwriting it would turn a restart
// during a LAPI outage into a mass unban, which is the failure this is guarding.
func (b *bouncer) ensureMap() {
	if _, err := os.Stat(b.cfg.outputFile); err == nil {
		return
	}
	// The set is empty at this point, so this renders an empty map - enough for
	// Apache to parse its config; the first sync fills it in.
	if err := b.write(); err != nil {
		log.Printf("creating an empty map at %s: %v", b.cfg.outputFile, err)
		return
	}
	log.Printf("created an empty map at %s so Apache can parse its config before the first sync", b.cfg.outputFile)
}

// dbmPresent reports whether a DBM built at base exists on disk, checking the
// single-file and two-file backend names.
func dbmPresent(base string) bool {
	for _, suffix := range []string{"", ".db", ".pag", ".dir"} {
		if _, err := os.Stat(base + suffix); err == nil {
			return true
		}
	}
	return false
}

// dbmReady reports whether the DBM map Apache reads actually exists on disk. In
// txt mode there is no DBM, so it is trivially ready. run() uses this on startup
// so it never logs "startup ok" when buildDBM failed and the map Apache consumes
// is missing.
func (b *bouncer) dbmReady() bool {
	return b.cfg.mapType != "dbm" || dbmPresent(b.cfg.dbmFile)
}
