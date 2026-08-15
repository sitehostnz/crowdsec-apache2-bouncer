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

// write renders every remediation's map. A write failure stops there and is
// returned, so the caller keeps the maps it already had rather than a set that
// is half old and half new.
func (b *bouncer) write() error {
	for _, r := range b.remediations {
		if err := b.writeMap(r); err != nil {
			return err
		}
	}
	return nil
}

// writeMap renders one remediation's txt map and, when MAP_TYPE=dbm, rebuilds its
// DBM. A DBM failure is logged but never fatal - the previous DBM is kept.
func (b *bouncer) writeMap(r *remediation) error {
	if err := b.writeTxt(r); err != nil {
		b.metrics.mapWriteFail.Add(1)
		return err
	}
	b.metrics.mapWrites.Add(1)
	if b.cfg.mapType == "dbm" {
		b.buildDBM(r) // keeps the previous DBM on failure; logs, never fatal
	}
	return nil
}

// writeTxt writes the sorted "<ip> 1" map to a temp file and atomically renames
// it into place, so Apache never reads a half-written map and the mtime bump
// triggers a RewriteMap reload.
func (b *bouncer) writeTxt(r *remediation) error {
	dir := filepath.Dir(r.txt)
	// 0755: Apache's worker user (daemon/apache) must traverse this directory
	// to read the map.
	// #nosec G301
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Temp name derived from the map's own basename, so two maps in one directory
	// can never collide and the glob that cleans up after a crash stays per-map.
	tmp, err := os.CreateTemp(dir, "."+strings.TrimSuffix(filepath.Base(r.txt), ".txt")+".*.tmp")
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
	w := make([]byte, 0, len(r.sortedIPs)*20)
	for _, ip := range r.sortedIPs {
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
	return os.Rename(tmp.Name(), r.txt) // atomic; mtime change -> RewriteMap reload
}

// buildDBM rebuilds one remediation map's DBM. A failure is logged but never
// fatal. The error says what state the map is in, so it is logged as-is.
func (b *bouncer) buildDBM(r *remediation) {
	if err := b.buildDBMFrom(r.txt, r.dbm); err != nil {
		b.metrics.dbmFailures.Add(1)
		log.Printf("%s: %v", r.name, err)
		return
	}
	b.metrics.dbmRebuilds.Add(1)
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
// Each map is judged on its own, so adding a remediation to an existing install
// creates only the new map and leaves the established one untouched.
func (b *bouncer) ensureMap() {
	for _, r := range b.remediations {
		if _, err := os.Stat(r.txt); err == nil {
			continue
		}
		// The set is empty at this point, so this renders an empty map - enough for
		// Apache to parse its config; the first sync fills it in.
		if err := b.writeMap(r); err != nil {
			log.Printf("creating an empty map at %s: %v", r.txt, err)
			continue
		}
		log.Printf("created an empty map at %s so Apache can parse its config before the first sync", r.txt)
	}
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

// retireUnusedMaps empties the maps this policy no longer produces.
//
// Changing BOUNCING_ON_TYPE or OVERRIDE_REMEDIATION can stop a remediation being
// rendered at all. The file it used to write is then frozen at whatever it held
// when the policy changed - while the operator's Apache config still names it and
// still consults it on every request. Switching bans over to captchas that way
// leaves the old ban map enforcing a decision set from before the change,
// permanently, and because the ban rule is checked first those addresses never
// even reach the captcha rule. Nothing in the logs would say so.
//
// The file is emptied rather than removed: Apache refuses to start when a
// RewriteMap path is missing, so deleting it would take the web server down at
// the next reload or restart.
func (b *bouncer) retireUnusedMaps() {
	for _, name := range knownRemediations {
		if b.byType[name] != nil {
			continue // still produced
		}
		txt, dbm := b.cfg.mapPaths(name)
		info, err := os.Stat(txt)
		if err != nil || info.Size() == 0 {
			// Never written here, or already empty - leave the mtime alone rather
			// than making Apache re-read an unchanged file on every restart.
			continue
		}
		if err := b.writeMap(newRemediation(name, txt, dbm)); err != nil {
			log.Printf("WARNING: %s is no longer enforced but its map at %s could not be emptied (%v); "+
				"Apache is still applying its old contents", name, txt, err)
			continue
		}
		log.Printf("%s is not produced under this policy: emptied %s so Apache stops applying the decisions it still held",
			name, txt)
	}
}

// missingDBM returns the path of the first DBM Apache would look for and not
// find, or "" when every map is in place. In txt mode there is no DBM, so it is
// trivially "". run() uses this on startup so it never logs "startup ok" when
// buildDBM failed and a map Apache consumes is missing - and names which one.
func (b *bouncer) missingDBM() string {
	if b.cfg.mapType != "dbm" {
		return ""
	}
	for _, r := range b.remediations {
		if !dbmPresent(r.dbm) {
			return r.dbm
		}
	}
	return ""
}
