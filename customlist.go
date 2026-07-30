package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"
)

// customList is an operator-maintained map kept beside the CrowdSec one: a local
// allowlist (bypass a ban) and a local blocklist (manual bans CrowdSec doesn't
// know about). The daemon never touches their contents - only the operator does -
// but it does two things so they behave like the CrowdSec map. It creates the file
// when it's missing, because Apache refuses to start if a RewriteMap file doesn't
// exist. And in dbm mode it rebuilds the hash map whenever the text file changes,
// which is otherwise a manual httxt2dbm step that's easy to forget - leaving an
// edit that appears to do nothing.
type customList struct {
	name string // "allowlist" | "denylist", for log lines
	txt  string // the file the operator edits
	dbm  string // the map Apache reads, rebuilt from txt

	// state of txt as at the last rebuild attempt, so an untouched file isn't
	// converted again on every poll
	lastMod   time.Time
	lastSize  int64
	attempted bool // a rebuild has been tried for the state above
	built     bool // ...and it succeeded
	warned    bool // an unreadable/uncreatable list has already been reported
}

// customListNames are the lists the daemon manages inside CUSTOM_LIST_DIR.
var customListNames = []string{"allowlist", "denylist"}

// newCustomLists builds the lists to manage under dir, or nil when the feature is
// switched off (an empty CUSTOM_LIST_DIR).
func newCustomLists(dir string) []*customList {
	if dir == "" {
		return nil
	}
	lists := make([]*customList, 0, len(customListNames))
	for _, name := range customListNames {
		txt := filepath.Join(dir, name+".txt")
		lists = append(lists, &customList{name: name, txt: txt, dbm: defaultDBMPath(txt)})
	}
	return lists
}

// syncCustomLists creates any list file the operator hasn't made yet, and rebuilds
// the DBM of any that changed. It is best-effort by design: these lists sit
// alongside the CrowdSec map rather than feeding it, so a failure is logged and
// the poll carries on.
func (b *bouncer) syncCustomLists() {
	for _, list := range b.customLists {
		info, err := list.ensureTxt()
		if err != nil {
			// Say so once, not every poll: the unit runs with ProtectSystem=full, so
			// a source install whose directory the package never created leaves this
			// failing forever, and at poll rate it would bury everything else.
			if !list.warned {
				log.Printf("%s: %v", list.name, err)
				list.warned = true
			}
			continue
		}
		list.warned = false
		// In txt mode Apache reads the operator's file directly - nothing to build.
		if b.cfg.mapType != "dbm" || !list.needsBuild(info) {
			continue
		}
		err = b.buildDBMFrom(list.txt, list.dbm)
		list.record(info, err == nil)
		if err != nil {
			log.Printf("%s: %v", list.name, err)
			continue
		}
		log.Printf("%s: rebuilt %s from %s", list.name, list.dbm, list.txt)
	}
}

// ensureTxt creates the list, and the directory holding it, when the operator
// hasn't yet - so Apache always has a file to read - and returns its state.
func (l *customList) ensureTxt() (os.FileInfo, error) {
	info, err := os.Stat(l.txt)
	if err == nil {
		return info, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("checking %s: %w", l.txt, err)
	}
	// 0755 directory, 0644 file: the operator edits these, and Apache's worker user
	// has to traverse to and read them. The explicit chmods matter, because the
	// modes passed to MkdirAll/WriteFile are masked by the process umask. A
	// directory that already exists is left exactly as the operator set it.
	dir := filepath.Dir(l.txt)
	if _, derr := os.Stat(dir); errors.Is(derr, fs.ErrNotExist) {
		// #nosec G301
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("creating %s: %w", dir, err)
		}
		// #nosec G302
		_ = os.Chmod(dir, 0o755)
	}
	// #nosec G306
	if err := os.WriteFile(l.txt, nil, 0o644); err != nil {
		return nil, fmt.Errorf("creating %s: %w", l.txt, err)
	}
	// #nosec G302
	if err := os.Chmod(l.txt, 0o644); err != nil {
		return nil, fmt.Errorf("setting permissions on %s: %w", l.txt, err)
	}
	log.Printf("%s: created empty %s", l.name, l.txt)
	return os.Stat(l.txt)
}

// needsBuild reports whether the DBM should be rebuilt: the text file has moved
// since the last attempt, or it hasn't changed but the map Apache reads has since
// gone missing (which self-heals a deleted map, as the CrowdSec one does). A list
// whose last conversion failed is left alone until the operator touches it again,
// so one malformed file can't fill the log at poll rate.
func (l *customList) needsBuild(info os.FileInfo) bool {
	if !l.attempted || !info.ModTime().Equal(l.lastMod) || info.Size() != l.lastSize {
		return true
	}
	return l.built && !dbmPresent(l.dbm)
}

// record stores the state the DBM was last built from, and whether that worked.
func (l *customList) record(info os.FileInfo, ok bool) {
	l.lastMod, l.lastSize, l.attempted, l.built = info.ModTime(), info.Size(), true, ok
}
