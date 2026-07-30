package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// countingStub writes an httxt2dbm stand-in that records every call and either
// copies its input to its output or fails outright. It returns the stub's path
// and a func reporting how many times it has run.
func countingStub(t *testing.T, succeed bool) (string, func() int) {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	body := "#!/bin/sh\necho x >> \"" + calls + "\"\n" +
		"while [ $# -gt 0 ]; do case $1 in -i) IN=$2; shift 2;; -o) OUT=$2; shift 2;; *) shift;; esac; done\n"
	if succeed {
		body += "cp \"$IN\" \"$OUT\"\n"
	} else {
		body += "exit 1\n"
	}
	return writeStub(t, dir, body), func() int {
		data, err := os.ReadFile(calls)
		if err != nil {
			return 0
		}
		return bytes.Count(data, []byte("\n"))
	}
}

// customBouncer returns a bouncer managing its lists in a directory that does not
// exist yet, along with that directory.
func customBouncer(t *testing.T, mutate func(*config)) (*bouncer, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "crowdsec")
	b := testBouncer(t, func(c *config) {
		c.customListDir = dir
		if mutate != nil {
			mutate(c)
		}
	})
	return b, dir
}

func dbmStubBouncer(t *testing.T, succeed bool) (*bouncer, string, func() int) {
	t.Helper()
	stub, calls := countingStub(t, succeed)
	b, dir := customBouncer(t, func(c *config) {
		c.mapType = "dbm"
		c.httxt2dbm = stub
	})
	return b, dir, calls
}

func TestCustomListsCreateMissingFiles(t *testing.T) {
	b, dir := customBouncer(t, nil) // txt mode
	b.syncCustomLists()

	for _, name := range customListNames {
		path := filepath.Join(dir, name+".txt")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s not created: %v", name, err)
		}
		if info.Size() != 0 {
			t.Errorf("%s should start empty, got %d bytes", name, info.Size())
		}
		// Apache's worker user has to read these, whatever the daemon's umask.
		if perm := info.Mode().Perm(); perm != 0o644 {
			t.Errorf("%s mode = %#o, want 0644", name, perm)
		}
		if dbmPresent(defaultDBMPath(path)) {
			t.Errorf("%s: built a DBM in txt mode", name)
		}
	}
}

// The daemon owns these files' existence, never their contents.
func TestCustomListsLeaveOperatorContentAlone(t *testing.T) {
	b, dir := customBouncer(t, nil)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "allowlist.txt")
	want := "203.0.113.5 1\n"
	if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}

	b.syncCustomLists()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("daemon rewrote the operator's list: %q", got)
	}
}

func TestCustomListsBuildDBMOnChangeOnly(t *testing.T) {
	b, dir, calls := dbmStubBouncer(t, true)

	b.syncCustomLists() // creates both lists, builds both DBMs
	if n := calls(); n != 2 {
		t.Fatalf("first sync ran httxt2dbm %d times, want 2 (one per list)", n)
	}
	for _, name := range customListNames {
		if !dbmPresent(defaultDBMPath(filepath.Join(dir, name+".txt"))) {
			t.Fatalf("%s: no DBM built", name)
		}
	}

	b.syncCustomLists()
	if n := calls(); n != 2 {
		t.Fatalf("untouched lists were rebuilt (%d calls, want 2)", n)
	}

	// The operator edits one list. Changing the size as well as the mtime keeps
	// this robust whatever the filesystem's timestamp granularity.
	if err := os.WriteFile(filepath.Join(dir, "allowlist.txt"), []byte("203.0.113.5 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b.syncCustomLists()
	if n := calls(); n != 3 {
		t.Fatalf("after one edit httxt2dbm had run %d times, want 3", n)
	}
}

func TestCustomListsRebuildWhenDBMGoesMissing(t *testing.T) {
	b, dir, calls := dbmStubBouncer(t, true)
	b.syncCustomLists()

	dbm := defaultDBMPath(filepath.Join(dir, "denylist.txt"))
	if err := os.Remove(dbm); err != nil {
		t.Fatal(err)
	}

	b.syncCustomLists()
	if !dbmPresent(dbm) {
		t.Fatal("a deleted DBM was not rebuilt")
	}
	if n := calls(); n != 3 {
		t.Fatalf("httxt2dbm ran %d times, want 3 (2 initial + 1 repair)", n)
	}
}

// A list the converter chokes on must not be retried on every poll, or one bad
// file fills the log - but an edit has to get another go.
func TestCustomListsFailedBuildWaitsForAnEdit(t *testing.T) {
	b, dir, calls := dbmStubBouncer(t, false)

	b.syncCustomLists()
	if n := calls(); n != 2 {
		t.Fatalf("first sync ran httxt2dbm %d times, want 2", n)
	}

	b.syncCustomLists()
	b.syncCustomLists()
	if n := calls(); n != 2 {
		t.Fatalf("a failing list was retried %d times without changing", n-2)
	}

	if err := os.WriteFile(filepath.Join(dir, "allowlist.txt"), []byte("203.0.113.5 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b.syncCustomLists()
	if n := calls(); n != 3 {
		t.Fatalf("an edited list was not retried (%d calls, want 3)", n)
	}
}

func TestCustomListsDisabled(t *testing.T) {
	b := testBouncer(t, func(c *config) { c.customListDir = "" })
	if b.customLists != nil {
		t.Fatalf("an empty CUSTOM_LIST_DIR should switch the lists off, got %d", len(b.customLists))
	}
	b.syncCustomLists() // must be a no-op rather than a panic
}

// An unwritable directory is reported once, not on every poll.
func TestCustomListsReportUnwritableDirOnce(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil { // no write permission
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	b := testBouncer(t, func(c *config) { c.customListDir = filepath.Join(parent, "crowdsec") })
	b.syncCustomLists()
	for _, list := range b.customLists {
		if !list.warned {
			t.Fatalf("%s: a creation failure went unreported", list.name)
		}
	}
	b.syncCustomLists() // still failing, but already reported
	for _, list := range b.customLists {
		if list.attempted {
			t.Fatalf("%s: tried to build a DBM for a list that doesn't exist", list.name)
		}
	}
}
