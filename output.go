package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

	ips := make([]string, 0, len(b.refcount))
	for ip := range b.refcount {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	w := make([]byte, 0, len(ips)*20)
	for _, ip := range ips {
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

// buildDBM converts the txt map to a DBM (O(1) lookups) via Apache's httxt2dbm,
// then moves the generated file(s) into place. Globbing the temp basename
// handles both single-file (DB/GDBM) and two-file (SDBM .pag/.dir) backends.
func (b *bouncer) buildDBM() {
	base := b.cfg.dbmFile
	tmp := base + ".new"
	if stale, _ := filepath.Glob(tmp + "*"); len(stale) > 0 {
		for _, f := range stale {
			_ = os.Remove(f)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// binary path and file arguments come from operator-owned config
	// (HTTXT2DBM/OUTPUT_FILE), never from request or decision data.
	// #nosec G204
	out, err := exec.CommandContext(ctx, b.cfg.httxt2dbm, "-i", b.cfg.outputFile, "-o", tmp).CombinedOutput()
	if err != nil {
		log.Printf("httxt2dbm failed (%v): %s; keeping previous DBM", err, strings.TrimSpace(string(out)))
		return
	}
	produced, _ := filepath.Glob(tmp + "*")
	if len(produced) == 0 {
		log.Printf("httxt2dbm produced no output; keeping previous DBM")
		return
	}
	// NOTE: for two-file backends (SDBM .pag/.dir) this is one rename per file, so
	// there is a brief window where Apache can read a new .pag with an old .dir.
	// The window is short and rebuilds are infrequent, and a fully atomic
	// multi-file swap isn't feasible without hardlink tricks - prefer a single-file
	// backend (or pin SDBM per the README) if this matters.
	for _, f := range produced {
		suffix := strings.TrimPrefix(f, tmp) // "" | ".db" | ".pag" | ".dir"
		// best effort: the converter may have run as another user (e.g. via a
		// docker wrapper), in which case chmod fails but the file is still 0644.
		// 0644 is required: Apache's worker user must read the map.
		// #nosec G302
		_ = os.Chmod(f, 0o644)
		if err := os.Rename(f, base+suffix); err != nil {
			log.Printf("swapping %s into place: %v", f, err)
		}
	}
}

// dbmReady reports whether the DBM map Apache reads actually exists on disk
// (checking the single-file and two-file backend names). In txt mode there is no
// DBM, so it is trivially ready. run() uses this on startup so it never logs
// "startup ok" when buildDBM failed and the map Apache consumes is missing.
func (b *bouncer) dbmReady() bool {
	if b.cfg.mapType != "dbm" {
		return true
	}
	for _, suffix := range []string{"", ".db", ".pag", ".dir"} {
		if _, err := os.Stat(b.cfg.dbmFile + suffix); err == nil {
			return true
		}
	}
	return false
}
