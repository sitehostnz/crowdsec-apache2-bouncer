package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// clearEnv blanks every config env var so ambient environment can't leak in.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"CROWDSEC_LAPI_URL", "CROWDSEC_API_KEY", "BLOCKLIST_DIR", "OUTPUT_FILE", "UPDATE_FREQUENCY",
		"EXPAND_MAX_HOSTS", "ONLY_BAN", "RESYNC_INTERVAL", "REQUEST_TIMEOUT",
		"MAP_TYPE", "HTTXT2DBM", "DBM_FILE", "INSECURE", "CA_BUNDLE",
		"STREAM_REQUEST_TIMEOUT",
	} {
		t.Setenv(v, "")
	}
	// CUSTOM_LIST_DIR is read with envOptional, where a set-but-empty value means
	// "off" rather than "use the default" - so it has to be genuinely unset, not
	// blanked, or every test below would silently run with the lists disabled.
	// The t.Setenv first is what registers the cleanup that restores it.
	t.Setenv("CUSTOM_LIST_DIR", "")
	_ = os.Unsetenv("CUSTOM_LIST_DIR")
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("X_STR", "value")
	t.Setenv("X_EMPTY", "")
	if envStr("X_STR", "d") != "value" || envStr("X_EMPTY", "d") != "d" || envStr("X_UNSET_1", "d") != "d" {
		t.Error("envStr defaults wrong")
	}

	t.Setenv("X_INT", "42")
	t.Setenv("X_INT_PAD", " 7 ")
	t.Setenv("X_INT_BAD", "not-a-number")
	if envInt("X_INT", 1) != 42 || envInt("X_INT_PAD", 1) != 7 {
		t.Error("envInt parse wrong")
	}
	if envInt("X_INT_BAD", 9) != 9 || envInt("X_UNSET_2", 9) != 9 {
		t.Error("envInt should fall back to default on bad/unset")
	}

	for v, want := range map[string]bool{
		"1": true, "true": true, "TRUE": true, "Yes": true, "on": true,
		"0": false, "false": false, "no": false, "off": false, "garbage": false,
	} {
		t.Setenv("X_BOOL", v)
		if envBool("X_BOOL", !want) != want {
			t.Errorf("envBool(%q) != %v", v, want)
		}
	}
	if envBool("X_UNSET_3", true) != true || envBool("X_UNSET_4", false) != false {
		t.Error("envBool unset should return default")
	}
}

func TestDefaultDBMPath(t *testing.T) {
	if got := defaultDBMPath("/var/lib/crowdsec-apache2-bouncer/blocklist.txt"); got != "/var/lib/crowdsec-apache2-bouncer/blocklist.dbm" {
		t.Errorf("got %q", got)
	}
	if got := defaultDBMPath("/etc/httpd/map"); got != "/etc/httpd/map.dbm" {
		t.Errorf("non-.txt input: got %q", got)
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("missing API key is fatal", func(t *testing.T) {
		clearEnv(t)
		if _, err := loadConfig(); err == nil {
			t.Fatal("want error without CROWDSEC_API_KEY")
		}
	})

	t.Run("defaults", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.lapiURL != "http://127.0.0.1:8080" ||
			cfg.outputFile != "/var/lib/crowdsec-apache2-bouncer/blocklist.txt" ||
			cfg.updateFrequency != 10*time.Second ||
			cfg.expandMaxHosts != 65536 ||
			!cfg.onlyBan ||
			cfg.resyncInterval != 21600*time.Second ||
			cfg.streamRequestTimeout != 15*time.Second ||
			cfg.mapType != "txt" ||
			cfg.customListDir != "/etc/apache2/crowdsec" ||
			cfg.dbmFile != "/var/lib/crowdsec-apache2-bouncer/blocklist.dbm" {
			t.Fatalf("unexpected defaults: %+v", cfg)
		}
	})

	t.Run("overrides + URL trailing slash trimmed", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("CROWDSEC_LAPI_URL", "https://crowdsec.example:8085/")
		t.Setenv("UPDATE_FREQUENCY", "30")
		t.Setenv("ONLY_BAN", "false")
		t.Setenv("DBM_FILE", "/custom/path.dbm")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.lapiURL != "https://crowdsec.example:8085" ||
			cfg.updateFrequency != 30*time.Second ||
			cfg.onlyBan ||
			cfg.dbmFile != "/custom/path.dbm" {
			t.Fatalf("overrides not applied: %+v", cfg)
		}
	})

	t.Run("dbm without httxt2dbm is fatal", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("MAP_TYPE", "dbm")
		t.Setenv("HTTXT2DBM", "/nonexistent/httxt2dbm")
		if _, err := loadConfig(); err == nil {
			t.Fatal("want error when httxt2dbm is missing")
		}
	})

	t.Run("dbm with a resolvable tool is accepted", func(t *testing.T) {
		clearEnv(t)
		dir := t.TempDir()
		stub := filepath.Join(dir, "httxt2dbm")
		if err := os.WriteFile(stub, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("MAP_TYPE", "dbm")
		t.Setenv("HTTXT2DBM", stub)
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.mapType != "dbm" || cfg.httxt2dbm != stub {
			t.Fatalf("cfg: %+v", cfg)
		}
	})

	t.Run("REQUEST_TIMEOUT capped to STREAM_REQUEST_TIMEOUT", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("REQUEST_TIMEOUT", "30")
		t.Setenv("STREAM_REQUEST_TIMEOUT", "15")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.requestTimeout != 15*time.Second || cfg.streamRequestTimeout != 15*time.Second {
			t.Fatalf("want both 15s (REQUEST_TIMEOUT capped), got request=%s stream=%s", cfg.requestTimeout, cfg.streamRequestTimeout)
		}
	})

	t.Run("minimum clamps", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("UPDATE_FREQUENCY", "0")
		t.Setenv("EXPAND_MAX_HOSTS", "-5")
		t.Setenv("REQUEST_TIMEOUT", "0")
		t.Setenv("STREAM_REQUEST_TIMEOUT", "0")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.updateFrequency < time.Second || cfg.expandMaxHosts < 1 || cfg.requestTimeout < time.Second || cfg.streamRequestTimeout < time.Second {
			t.Fatalf("clamps not applied: %+v", cfg)
		}
	})

	// CUSTOM_LIST_DIR is the one setting where empty has to mean something other
	// than "unset", so that an operator can switch the local lists off.
	t.Run("an explicitly empty CUSTOM_LIST_DIR disables the local lists", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("CUSTOM_LIST_DIR", "")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.customListDir != "" {
			t.Fatalf("CUSTOM_LIST_DIR= should disable the lists, got %q", cfg.customListDir)
		}
		if b, err := newBouncer(cfg); err != nil || b.customLists != nil {
			t.Fatalf("disabled config still built lists (err=%v)", err)
		}
	})

	t.Run("CUSTOM_LIST_DIR is honoured and trimmed", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("CUSTOM_LIST_DIR", "  /etc/httpd/crowdsec  ")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.customListDir != "/etc/httpd/crowdsec" {
			t.Fatalf("customListDir = %q", cfg.customListDir)
		}
	})
}

func TestNewBouncerTLSConfig(t *testing.T) {
	t.Run("missing CA bundle file is an error", func(t *testing.T) {
		cfg := &config{lapiURL: "https://x", apiKey: "k", caBundle: "/nonexistent.pem"}
		if _, err := newBouncer(cfg); err == nil {
			t.Fatal("want error for missing CA_BUNDLE file")
		}
	})

	t.Run("CA bundle without certificates is an error", func(t *testing.T) {
		junk := filepath.Join(t.TempDir(), "junk.pem")
		if err := os.WriteFile(junk, []byte("not a pem"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := &config{lapiURL: "https://x", apiKey: "k", caBundle: junk}
		if _, err := newBouncer(cfg); err == nil {
			t.Fatal("want error for junk CA_BUNDLE")
		}
	})

	t.Run("plain http needs no TLS material", func(t *testing.T) {
		cfg := &config{lapiURL: "http://x", apiKey: "k", caBundle: "/nonexistent.pem"}
		if _, err := newBouncer(cfg); err != nil {
			t.Fatalf("http should ignore CA_BUNDLE: %v", err)
		}
	})
}

func TestBlocklistDirPrecedence(t *testing.T) {
	t.Run("BLOCKLIST_DIR env moves both files", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("BLOCKLIST_DIR", "/srv/lists")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.outputFile != "/srv/lists/blocklist.txt" || cfg.dbmFile != "/srv/lists/blocklist.dbm" {
			t.Fatalf("dir not applied: txt=%q dbm=%q", cfg.outputFile, cfg.dbmFile)
		}
	})

	t.Run("-dir flag beats BLOCKLIST_DIR", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("BLOCKLIST_DIR", "/srv/env-wins-not")
		if err := flag.Set("dir", "/srv/flag-wins"); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = flag.Set("dir", "") }()
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.outputFile != "/srv/flag-wins/blocklist.txt" {
			t.Fatalf("flag did not win: %q", cfg.outputFile)
		}
	})

	t.Run("explicit OUTPUT_FILE beats the directory", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("BLOCKLIST_DIR", "/srv/lists")
		t.Setenv("OUTPUT_FILE", "/exact/path/map.txt")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.outputFile != "/exact/path/map.txt" || cfg.dbmFile != "/exact/path/map.dbm" {
			t.Fatalf("explicit override lost: txt=%q dbm=%q", cfg.outputFile, cfg.dbmFile)
		}
	})
}
