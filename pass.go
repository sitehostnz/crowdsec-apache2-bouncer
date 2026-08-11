package main

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// passStore records the addresses that have solved a challenge, and renders them
// to a RewriteMap Apache checks before the captcha map.
//
// It is deliberately a txt map rather than a DBM. Every other map here is built
// with httxt2dbm and goes live on the next poll, which is fine for a ban list; a
// pass is different, because a person is sitting there waiting for it. Apache
// re-reads a txt map as soon as its mtime changes, so a solve takes effect on the
// client's very next request. The list is also small - it holds solvers, not
// offenders - so the linear scan a txt map costs is irrelevant.
//
// Unlike the rest of the daemon this is touched from two goroutines: the HTTP
// listener adds passes, the poll loop prunes them. Hence the mutex.
type passStore struct {
	mu     sync.Mutex
	path   string
	ttl    time.Duration
	passes map[string]time.Time // ip -> when the pass lapses
}

func newPassStore(path string, ttl time.Duration) *passStore {
	return &passStore{path: path, ttl: ttl, passes: make(map[string]time.Time)}
}

// add records a solved challenge under key and republishes the map. The caller
// gets the error because it is answering a request: a pass that was not persisted
// must not be reported as success, or the client is waved through by this
// response and challenged again on the next one.
//
// The store does not care what the key means. In ip mode it is the client's
// canonical address and Apache looks it up with %{REMOTE_ADDR}; in cookie mode it
// is an opaque token and Apache pulls it out of the Cookie header. Keeping the
// store agnostic is what lets one implementation serve both - the key is only
// ever an opaque string to be matched exactly.
func (p *passStore) add(key string, now time.Time) error {
	if key == "" {
		return errors.New("refusing to record a pass under an empty key")
	}
	if strings.ContainsAny(key, " \t\r\n") {
		// A key with whitespace in it would render a line Apache silently
		// mis-parses, so it can never match - a pass that appears to work and
		// doesn't.
		return fmt.Errorf("refusing to record a pass under %q: keys cannot contain whitespace", key)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.passes[key] = now.Add(p.ttl)
	return p.writeLocked()
}

// prune drops lapsed passes and rewrites the map when anything actually left.
// Rewriting unconditionally would bump the mtime on every poll and make Apache
// re-read a file that had not changed.
func (p *passStore) prune(now time.Time) (removed int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for ip, expires := range p.passes {
		if !now.Before(expires) {
			delete(p.passes, ip)
			removed++
		}
	}
	// Rewrite when something actually lapsed - an unconditional rewrite would bump
	// the mtime every poll and make Apache re-read a file that had not changed -
	// or when the map has gone missing underneath us, which self-heals a deletion
	// the way the other maps do on resync.
	if removed == 0 && p.present() {
		return 0, nil
	}
	return removed, p.writeLocked()
}

// present reports whether the map is still on disk. Callers must hold the mutex.
func (p *passStore) present() bool {
	_, err := os.Stat(p.path)
	return err == nil
}

// held reports how many passes are current, for the log lines.
func (p *passStore) held() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.passes)
}

// writeLocked renders the map atomically. Callers must hold the mutex.
func (p *passStore) writeLocked() error {
	dir := filepath.Dir(p.path)
	// #nosec G301 -- 0755: Apache's worker user must traverse this directory.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(p.path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name()) // no-op after a successful rename
	}()

	// Sorted so the file is stable and diffable; the list is small enough that
	// sorting it on every change costs nothing.
	out := make([]byte, 0, len(p.passes)*20)
	for _, ip := range slices.Sorted(maps.Keys(p.passes)) {
		out = append(out, ip...)
		out = append(out, " 1\n"...)
	}
	if _, err := tmp.Write(out); err != nil {
		return err
	}
	if err := tmp.Chmod(0o644); err != nil { // Apache's worker user must read it
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p.path) // atomic; mtime change -> RewriteMap reload
}

// reset publishes an empty map at startup. Apache refuses to start if a
// RewriteMap file is missing, and this one would otherwise not exist until
// somebody solved a challenge - possibly days after the config naming it went
// live.
//
// It overwrites an existing file rather than leaving it alone, which is the
// opposite of how the ban maps are treated, and for the opposite reason. Passes
// live only in memory, so a file inherited from a previous run names clients this
// process holds no expiry for: prune would iterate an empty map, find nothing to
// drop and never rewrite, leaving every one of those passes valid forever.
// Discarding them costs those clients one more challenge. Keeping them would
// exempt those addresses permanently, which is the failure that actually matters
// - for a pass map, wiping errs towards MORE enforcement, not less.
func (p *passStore) reset() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.writeLocked()
}
