package main

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// clearEnv blanks every config env var so ambient environment can't leak in.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"CROWDSEC_LAPI_URL", "CROWDSEC_API_KEY", "BLOCKLIST_DIR", "OUTPUT_FILE", "UPDATE_FREQUENCY",
		"EXPAND_MAX_HOSTS", "ONLY_BAN", "BOUNCING_ON_TYPE", "FALLBACK_REMEDIATION", "OVERRIDE_REMEDIATION",
		"RESYNC_INTERVAL", "REQUEST_TIMEOUT",
		"MAP_TYPE", "HTTXT2DBM", "DBM_FILE", "INSECURE", "CA_BUNDLE",
		"STREAM_REQUEST_TIMEOUT", "CAPTCHA_LISTEN", "CAPTCHA_VERIFY_URL", "CAPTCHA_SECRET",
		"CAPTCHA_API_ENDPOINT", "CAPTCHA_PASS_FILE", "CAPTCHA_WIDGET_JS", "CAPTCHA_WIDGET_SRI",
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
			cfg.updateFrequency != 60*time.Second ||
			cfg.expandMaxHosts != 65536 ||
			!slices.Equal(cfg.remediations, []string{"ban"}) ||
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
			!slices.Equal(cfg.remediations, []string{"ban", "captcha"}) ||
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

	// The DBM is built from the txt map, so one path for both makes the converter
	// destroy its own input and the two forms flap on every poll.
	t.Run("DBM_FILE equal to OUTPUT_FILE is rejected", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("OUTPUT_FILE", "/var/lib/crowdsec-apache2-bouncer/blocklist.txt")
		t.Setenv("DBM_FILE", "/var/lib/crowdsec-apache2-bouncer/blocklist.txt")
		if _, err := loadConfig(); err == nil {
			t.Fatal("want an error when DBM_FILE and OUTPUT_FILE are the same path")
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

// TestResolveRemediation pins the order the nginx bouncer uses: BOUNCING_ON_TYPE
// filters, then OVERRIDE_REMEDIATION replaces, then FALLBACK_REMEDIATION catches
// what is left. Getting the order wrong is not cosmetic - override-then-fallback
// is what makes "challenge everything" degrade to a block when no challenge is
// configured, instead of silently enforcing nothing.
func TestResolveRemediation(t *testing.T) {
	cfg := func(bounce, override, fallback string, captcha bool) *config {
		c := &config{bouncingOnType: bounce, overrideRemediation: override, fallbackRemediation: fallback}
		if captcha {
			c.captchaListen = "127.0.0.1:8125"
		}
		return c
	}
	cases := []struct {
		name                      string
		c                         *config
		ban, captcha, unsupported string
	}{
		{"default: ban only", cfg("ban", "", "ban", false), "ban", "", ""},
		{"all, no challenge configured: captcha degrades to the fallback",
			cfg("all", "", "ban", false), "ban", "ban", "ban"},
		{"all, challenge configured: captcha is honoured",
			cfg("all", "", "ban", true), "ban", "captcha", "ban"},
		{"override to captcha with a challenge: everything is challenged",
			cfg("all", "captcha", "ban", true), "captcha", "captcha", "captcha"},
		// The case the ordering exists for.
		{"override to captcha with NO challenge: degrades to the fallback, not silence",
			cfg("all", "captcha", "ban", false), "ban", "ban", "ban"},
		{"override to ban: everything is blocked",
			cfg("all", "ban", "ban", true), "ban", "ban", "ban"},
		{"no fallback: an unexpressible remediation is dropped",
			cfg("all", "", "", true), "ban", "captcha", ""},
		{"no fallback and no challenge: captcha is rendered but unenforced",
			cfg("all", "", "", false), "ban", "captcha", ""},
		// BOUNCING_ON_TYPE filters FIRST, so an unexpressible type is dropped before
		// the fallback is ever consulted.
		{"bouncing on captcha only: bans and throttles are filtered out",
			cfg("captcha", "", "ban", true), "", "captcha", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, got := range []struct{ in, want, actual string }{
				{"ban", c.ban, c.c.resolveRemediation("ban")},
				{"captcha", c.captcha, c.c.resolveRemediation("captcha")},
				{"throttle", c.unsupported, c.c.resolveRemediation("throttle")},
			} {
				if got.actual != got.want {
					t.Errorf("%s -> %q, want %q", got.in, got.actual, got.want)
				}
			}
		})
	}
}

// The maps rendered are derived from the routing, so a decision can never be sent
// to a map that was never built.
func TestMapsNeeded(t *testing.T) {
	cases := []struct {
		name string
		c    *config
		want []string
	}{
		{"default", &config{bouncingOnType: "ban", fallbackRemediation: "ban"}, []string{"ban"}},
		{"all without a challenge collapses to ban",
			&config{bouncingOnType: "all", fallbackRemediation: "ban"}, []string{"ban"}},
		{"all with a challenge needs both",
			&config{bouncingOnType: "all", fallbackRemediation: "ban", captchaListen: ":1"}, []string{"ban", "captcha"}},
		{"override to captcha still needs ban for the unexpressible",
			&config{bouncingOnType: "all", overrideRemediation: "captcha", fallbackRemediation: "ban", captchaListen: ":1"},
			[]string{"captcha"}},
		{"captcha only, no fallback",
			&config{bouncingOnType: "captcha", captchaListen: ":1"}, []string{"captcha"}},
		// Rendered but enforced by nothing - honest, and warned about at startup.
		{"captcha with no listener and no fallback", &config{bouncingOnType: "captcha"}, []string{"captcha"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.c.mapsNeeded(); !slices.Equal(got, c.want) {
				t.Fatalf("mapsNeeded = %v, want %v", got, c.want)
			}
		})
	}
}

func TestRemediationPolicyEnv(t *testing.T) {
	t.Run("an unknown BOUNCING_ON_TYPE is fatal", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("BOUNCING_ON_TYPE", "nonsense")
		if _, err := loadConfig(); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("an unknown FALLBACK_REMEDIATION is fatal", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("FALLBACK_REMEDIATION", "nonsense")
		if _, err := loadConfig(); err == nil {
			t.Fatal("want an error")
		}
	})
	// Empty is meaningful and must not fall back to the default: it switches the
	// degrade off entirely.
	t.Run("an explicitly empty FALLBACK_REMEDIATION switches the degrade off", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("BOUNCING_ON_TYPE", "all")
		t.Setenv("FALLBACK_REMEDIATION", "")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.fallbackRemediation != "" {
			t.Fatalf("fallback = %q, want empty", cfg.fallbackRemediation)
		}
		if got := cfg.resolveRemediation("throttle"); got != "" {
			t.Fatalf("throttle -> %q, want dropped", got)
		}
	})
	t.Run("ONLY_BAN=false maps onto BOUNCING_ON_TYPE=all", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("ONLY_BAN", "false")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.bouncingOnType != bouncingAll {
			t.Fatalf("bouncingOnType = %q, want %q", cfg.bouncingOnType, bouncingAll)
		}
	})
}

// TestMapPaths pins the back-compat guarantee: the ban map stays exactly where
// OUTPUT_FILE/DBM_FILE point, so an upgrade never moves the file the Apache
// config already names.
func TestMapPaths(t *testing.T) {
	c := &config{outputFile: "/var/lib/bouncer/blocklist.txt", dbmFile: "/var/lib/bouncer/blocklist.dbm"}
	if txt, dbm := c.mapPaths("ban"); txt != c.outputFile || dbm != c.dbmFile {
		t.Fatalf("ban map moved: txt=%q dbm=%q", txt, dbm)
	}
	txt, dbm := c.mapPaths("captcha")
	if txt != "/var/lib/bouncer/captcha.txt" || dbm != "/var/lib/bouncer/captcha.dbm" {
		t.Fatalf("captcha map = %q / %q", txt, dbm)
	}

	// An explicit DBM_FILE elsewhere must not drag the other maps with it - they
	// follow the txt map's directory, which is the one Apache traverses.
	c = &config{outputFile: "/var/lib/bouncer/blocklist.txt", dbmFile: "/somewhere/else.dbm"}
	if txt, _ = c.mapPaths("captcha"); txt != "/var/lib/bouncer/captcha.txt" {
		t.Fatalf("captcha txt followed DBM_FILE instead of OUTPUT_FILE: %q", txt)
	}
}

// RESYNC_INTERVAL is either off (0) or a real interval between an hour and a day -
// a full snapshot is the expensive query, so neither extreme is worth honouring.
func TestResyncEvery(t *testing.T) {
	for _, tc := range []struct {
		name string
		secs int
		want time.Duration
	}{
		{"0 disables", 0, 0},
		{"negative disables rather than clamping up", -21600, 0},
		{"the default is left alone", 21600, 6 * time.Hour},
		{"the lower bound is honoured exactly", 3600, time.Hour},
		{"the upper bound is honoured exactly", 86400, 24 * time.Hour},
		{"too frequent clamps up to an hour", 60, time.Hour},
		{"too rare clamps down to a day", 604800, 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resyncEvery(tc.secs); got != tc.want {
				t.Errorf("resyncEvery(%d) = %s, want %s", tc.secs, got, tc.want)
			}
		})
	}
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

// Blanking a line is how a setting is usually disabled in an env file, and systemd
// still sets it. Treating that as "present" made CAPTCHA_SECRET= a fatal startup
// error - and the fatal stops ban enforcement, not just the captcha.
func TestRemovedCaptchaSettingsOnlyRejectRealValues(t *testing.T) {
	for _, name := range []string{"CAPTCHA_PROVIDER", "CAPTCHA_VERIFY_URL", "CAPTCHA_SECRET", "CAPTCHA_API_ENDPOINT", "CAPTCHA_VERIFY_TIMEOUT"} {
		t.Run(name+" blank", func(t *testing.T) {
			clearEnv(t)
			t.Setenv("CAPTCHA_LISTEN", "127.0.0.1:8125")
			t.Setenv(name, "")
			c := &config{outputFile: "/var/lib/x/blocklist.txt"}
			if err := c.loadCaptcha(t.TempDir()); err != nil {
				t.Errorf("a blank %s must not be fatal: %v", name, err)
			}
		})
		t.Run(name+" set", func(t *testing.T) {
			clearEnv(t)
			t.Setenv("CAPTCHA_LISTEN", "127.0.0.1:8125")
			t.Setenv(name, "something")
			c := &config{outputFile: "/var/lib/x/blocklist.txt"}
			if err := c.loadCaptcha(t.TempDir()); err == nil {
				t.Errorf("%s=something was accepted; it should name what replaced it", name)
			}
		})
	}
}

// The built-in digest belongs to the built-in URL. Carrying it onto a widget an
// operator repointed would block that script in every browser - a challenge page
// nobody can solve, and one that looks fine from here.
func TestWidgetSRIFollowsTheWidgetURL(t *testing.T) {
	load := func(t *testing.T, env map[string]string) (*config, error) {
		t.Helper()
		clearEnv(t)
		t.Setenv("CAPTCHA_LISTEN", "127.0.0.1:8125")
		t.Setenv("CAPTCHA_WIDGET_JS", "")
		t.Setenv("CAPTCHA_WIDGET_SRI", "")
		for k, v := range env {
			t.Setenv(k, v)
		}
		c := &config{outputFile: "/var/lib/x/blocklist.txt"}
		return c, c.loadCaptcha(t.TempDir())
	}

	t.Run("the default URL carries the default digest", func(t *testing.T) {
		c, err := load(t, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.captchaWidgetSRI != altchaDefaultWidgetSRI {
			t.Errorf("captchaWidgetSRI = %q, want the pinned digest", c.captchaWidgetSRI)
		}
	})

	t.Run("a repointed widget with no digest gets none", func(t *testing.T) {
		c, err := load(t, map[string]string{"CAPTCHA_WIDGET_JS": "https://cdn.example.test/altcha.js"})
		if err != nil {
			t.Fatal(err)
		}
		if c.captchaWidgetSRI != "" {
			t.Errorf("captchaWidgetSRI = %q; the built-in digest cannot match another script", c.captchaWidgetSRI)
		}
	})

	t.Run("a repointed widget keeps the digest it was given", func(t *testing.T) {
		const own = "sha512-7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w=="
		c, err := load(t, map[string]string{
			"CAPTCHA_WIDGET_JS":  "https://cdn.example.test/altcha.js",
			"CAPTCHA_WIDGET_SRI": own,
		})
		if err != nil {
			t.Fatal(err)
		}
		if c.captchaWidgetSRI != own {
			t.Errorf("captchaWidgetSRI = %q, want %q", c.captchaWidgetSRI, own)
		}
	})

	// A digest names bytes, not a URL, so the built-in digest against another URL is
	// exactly right for an operator mirroring the pinned build onto their own origin
	// - the strongest answer to the threat this setting exists for. It warns, but it
	// must not refuse: a failed config kills the daemon, and that takes ban
	// enforcement down with the captcha it was complaining about.
	t.Run("the built-in digest against a repointed widget still starts", func(t *testing.T) {
		c, err := load(t, map[string]string{
			"CAPTCHA_WIDGET_JS":  "https://assets.example.test/vendor/altcha-3.2.1.js",
			"CAPTCHA_WIDGET_SRI": altchaDefaultWidgetSRI,
		})
		if err != nil {
			t.Fatalf("a byte-identical self-hosted mirror was refused: %v", err)
		}
		if c.captchaWidgetSRI != altchaDefaultWidgetSRI {
			t.Errorf("captchaWidgetSRI = %q, want the digest the operator set", c.captchaWidgetSRI)
		}
	})

	// Refused rather than dropped: a digest that cannot parse is a digest the
	// operator meant to work, and rendering the page without it silently would
	// leave them believing the widget is verified when it is not.
	t.Run("a malformed digest is fatal", func(t *testing.T) {
		bad := []string{
			"deadbeef", "md5-abc", "sha384-", "sha384-not base64!",
			// The likely real mistake: running the documented one-liner with
			// -sha256 while leaving the sha384- prefix in the env file. Parses
			// fine, is 32 bytes where 48 are required, and every browser refuses
			// it - so it has to die here rather than in the visitor's tab.
			"sha384-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
			"sha384-AAAA",
		}
		for _, b := range bad {
			if _, err := load(t, map[string]string{"CAPTCHA_WIDGET_SRI": b}); err == nil {
				t.Errorf("CAPTCHA_WIDGET_SRI=%q was accepted", b)
			}
		}
	})
}

func TestLoopbackListen(t *testing.T) {
	cases := []struct {
		addr     string
		loopback bool
	}{
		// Loopback: the only safe binds for the challenge listener.
		{"127.0.0.1:8125", true},
		{"127.0.0.5:8125", true}, // the whole 127/8 range is loopback
		{"[::1]:8125", true},
		{"localhost:8125", true},
		{"LocalHost:8125", true}, // hostname match is case-insensitive
		// Wildcard: binds every interface, so the listener is reachable off-box.
		{":8125", false},
		{"0.0.0.0:8125", false},
		{"[::]:8125", false},
		// A specific routable address - legitimate only for a cross-host Apache,
		// and the warning is meant to fire on it.
		{"192.168.1.10:8125", false},
		{"10.0.0.1:8125", false},
		{"example.internal:8125", false}, // a hostname we can't classify here
	}
	for _, c := range cases {
		if got := loopbackListen(c.addr); got != c.loopback {
			t.Errorf("loopbackListen(%q) = %v, want %v", c.addr, got, c.loopback)
		}
	}
}
