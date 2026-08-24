package main

import (
	"bytes"
	"context"
	"flag"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		// The rest of the captcha surface. Missing these made the ALTCHA tests fail on
		// a developer machine that happened to export one of them - the suite has to
		// describe the config it sets, not the shell it inherits.
		"CAPTCHA_PATH", "CAPTCHA_TOKEN_FIELD", "CAPTCHA_TEMPLATE", "CAPTCHA_READY_FILE",
		"CAPTCHA_PASS_TTL", "ALTCHA_ALGORITHM", "ALTCHA_COST", "ALTCHA_COMPLEXITY",
		"METRICS_LISTEN", "METRICS_PATH",
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
		// ONLY_BAN=false means BOUNCING_ON_TYPE=all, but with no CAPTCHA_LISTEN a
		// captcha cannot be served - so it degrades to the fallback and the ban map is
		// the only one rendered. Asserting ["ban","captcha"] here would be asserting a
		// captcha map that nothing enforces.
		if cfg.lapiURL != "https://crowdsec.example:8085" ||
			cfg.updateFrequency != 30*time.Second ||
			!slices.Equal(cfg.remediations, []string{"ban"}) ||
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
	// buildDBMFrom reads the txt map and renames its output to dbmFile+suffix, so any
	// of those names landing on the txt map makes the converter destroy its own input.
	// Textual equality is only the most obvious spelling of that: it misses the paths
	// samePath collapses, and it misses the three backend suffixes entirely.
	t.Run("a DBM that would be built onto OUTPUT_FILE is rejected", func(t *testing.T) {
		const dir = "/var/lib/crowdsec-apache2-bouncer/"
		for name, pair := range map[string]struct{ out, dbm string }{
			"the same path": {dir + "blocklist.txt", dir + "blocklist.txt"},
			// == misses these three; samePath collapses them.
			"a doubled separator": {dir + "blocklist.txt", dir + "/blocklist.txt"},
			"a dot segment":       {dir + "blocklist.txt", dir + "./blocklist.txt"},
			"a parent segment":    {dir + "blocklist.txt", dir + "../crowdsec-apache2-bouncer/blocklist.txt"},
			// The base alone misses these: OUTPUT_FILE is the suffixed name the
			// backend renames onto, so only dbmFilesFor sees the collision.
			"the Berkeley DB name": {dir + "map.db", dir + "map"},
			"the SDBM data name":   {dir + "map.pag", dir + "map"},
			"the SDBM index name":  {dir + "map.dir", dir + "map"},
		} {
			t.Run(name, func(t *testing.T) {
				clearEnv(t)
				t.Setenv("CROWDSEC_API_KEY", "k")
				t.Setenv("OUTPUT_FILE", pair.out)
				t.Setenv("DBM_FILE", pair.dbm)
				if _, err := loadConfig(); err == nil {
					t.Fatalf("OUTPUT_FILE %q with DBM_FILE %q must be refused: the converter would overwrite its own input",
						pair.out, pair.dbm)
				}
			})
		}
	})

	// And no overreach: the shipped default pair differs, and must load.
	t.Run("the default DBM/OUTPUT pair is accepted", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("the defaults must load: %v", err)
		}
		if cfg.dbmFile == cfg.outputFile {
			t.Fatal("the defaults should not collide")
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
		// There is no "no fallback" case any more: loadRemediationPolicy turns an
		// empty FALLBACK_REMEDIATION into ban, so nothing the hub decided can end up
		// enforced by nothing. These two pin that the fallback always catches - the
		// second is the state that used to render a captcha map with no listener
		// behind it.
		{"an unexpressible remediation always reaches the fallback",
			cfg("all", "", "ban", true), "ban", "captcha", "ban"},
		{"captcha with no challenge configured degrades rather than rendering unenforced",
			cfg("all", "", "ban", false), "ban", "ban", "ban"},
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
		{"captcha only, with a listener",
			&config{bouncingOnType: "captcha", fallbackRemediation: "ban", captchaListen: ":1"}, []string{"captcha"}},
		// Used to render a captcha map with nothing behind it. The fallback now
		// catches it, so the only map is the one that is actually enforced.
		{"captcha only, no listener: the fallback map is rendered instead",
			&config{bouncingOnType: "captcha", fallbackRemediation: "ban"}, []string{"ban"}},
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
	// Blanking the line used to switch the degrade OFF, which was the only way to
	// leave a decision the hub made enforced by nothing at all. Empty now means ban,
	// the same as unset, so a throttle - or a captcha with no listener - is blocked.
	t.Run("an explicitly empty FALLBACK_REMEDIATION means ban, not off", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("BOUNCING_ON_TYPE", "all")
		t.Setenv("FALLBACK_REMEDIATION", "")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.fallbackRemediation != remediationBan {
			t.Fatalf("fallback = %q, want %q", cfg.fallbackRemediation, remediationBan)
		}
		if got := cfg.resolveRemediation("throttle"); got != remediationBan {
			t.Fatalf("throttle -> %q, want %q - nothing may be left unenforced", got, remediationBan)
		}
		// And a captcha with no listener is blocked rather than written to a map
		// nothing reads.
		if got := cfg.resolveRemediation(remediationCaptcha); got != remediationBan {
			t.Fatalf("captcha with no listener -> %q, want %q", got, remediationBan)
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

	// A digest that cannot parse is one the operator meant to work, and rendering
	// the page without it would leave them believing the widget is verified when it
	// is not. There is nothing safe to substitute either - a digest names the bytes
	// of whatever CAPTCHA_WIDGET_JS points at. So the listener does not start, the
	// way an unusable CAPTCHA_TEMPLATE already behaves, and captcha decisions take
	// FALLBACK_REMEDIATION. Not fatal: that would take ban enforcement down too.
	t.Run("a malformed digest switches the listener off rather than killing the daemon", func(t *testing.T) {
		bad := []string{
			"deadbeef", "md5-abc", "sha384-", "sha384-not base64!",
			// The likely real mistake: running the documented one-liner with
			// -sha256 while leaving the sha384- prefix in the env file. Parses
			// fine, is 32 bytes where 48 are required, and every browser refuses
			// it - so it has to be caught here rather than in the visitor's tab.
			"sha384-n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
			"sha384-AAAA",
			// Every member of a list has to be valid: the browser picks the
			// strongest it recognises, so one broken entry is a broken attribute.
			"sha384-AAAA sha512-7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==",
		}
		for _, b := range bad {
			c, err := load(t, map[string]string{"CAPTCHA_WIDGET_SRI": b})
			if err != nil {
				t.Errorf("CAPTCHA_WIDGET_SRI=%q was fatal; it should switch the listener off: %v", b, err)
				continue
			}
			if c.captchaUsable() {
				t.Errorf("CAPTCHA_WIDGET_SRI=%q left the listener running; the widget would never load", b)
			}
		}
	})

	// The integrity attribute is a whitespace-separated LIST in the spec, and each
	// entry may carry a ?options suffix. Refusing those switched the listener off
	// over a value every browser accepts - an operator pinning two hashes across a
	// widget rollover is the obvious case.
	t.Run("spec-legal digest lists and options are accepted", func(t *testing.T) {
		const sha512 = "sha512-7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w=="
		for _, good := range []string{
			altchaDefaultWidgetSRI + " " + sha512,
			altchaDefaultWidgetSRI + "?foo=bar",
		} {
			c, err := load(t, map[string]string{
				"CAPTCHA_WIDGET_JS":  "https://cdn.example.test/altcha.js",
				"CAPTCHA_WIDGET_SRI": good,
			})
			if err != nil {
				t.Errorf("CAPTCHA_WIDGET_SRI=%q was refused: %v", good, err)
				continue
			}
			if !c.captchaUsable() {
				t.Errorf("CAPTCHA_WIDGET_SRI=%q switched the listener off; it is spec-legal", good)
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

// The pass map is reset (truncated) whenever the challenge listener starts, so a
// path collision with any file the daemon renders - or with an operator's custom
// list, which nothing would rebuild - has to be refused at load time, not
// discovered as an empty ban list after the next boot.
func TestPassFileCollisionGuard(t *testing.T) {
	load := func(t *testing.T, env map[string]string) error {
		t.Helper()
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		for k, v := range env {
			t.Setenv(k, v)
		}
		_, err := loadConfig()
		return err
	}

	// The guard only fires while the challenge listener is on (it is what resets the
	// pass file), so every refused case sets CAPTCHA_LISTEN and a policy that routes
	// captcha to keep it up.
	refused := map[string]map[string]string{
		// B2 regression: under a captcha-only policy the ban map is retired, so a
		// guard that looked only at the rendered set missed it - and the boot-time
		// pass reset then overwrote the ban list. The guard now checks every map the
		// daemon can write, retired or not.
		"the retired ban map under a captcha-only policy": {
			"BOUNCING_ON_TYPE":  "captcha",
			"CAPTCHA_LISTEN":    "127.0.0.1:0",
			"CAPTCHA_PASS_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.txt",
		},
		"the ban txt map": {
			"BOUNCING_ON_TYPE":  "all",
			"CAPTCHA_LISTEN":    "127.0.0.1:0",
			"CAPTCHA_PASS_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.txt",
		},
		// filepath.Clean has to see through a doubled separator, or the guard is
		// defeated by a spelling rather than a different path.
		"the ban txt map, unclean spelling": {
			"BOUNCING_ON_TYPE":  "all",
			"CAPTCHA_LISTEN":    "127.0.0.1:0",
			"CAPTCHA_PASS_FILE": "/var/lib/crowdsec-apache2-bouncer//blocklist.txt",
		},
		"the ban dbm map": {
			"BOUNCING_ON_TYPE":  "all",
			"CAPTCHA_LISTEN":    "127.0.0.1:0",
			"CAPTCHA_PASS_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.dbm",
		},
		"the captcha map, when one is rendered": {
			"BOUNCING_ON_TYPE":  "all",
			"CAPTCHA_LISTEN":    "127.0.0.1:0",
			"CAPTCHA_PASS_FILE": "/var/lib/crowdsec-apache2-bouncer/captcha.txt",
		},
		"a custom allowlist": {
			"BOUNCING_ON_TYPE":  "all",
			"CAPTCHA_LISTEN":    "127.0.0.1:0",
			"CUSTOM_LIST_DIR":   "/etc/apache2/crowdsec",
			"CAPTCHA_PASS_FILE": "/etc/apache2/crowdsec/allowlist.txt",
		},
		"a custom denylist dbm": {
			"BOUNCING_ON_TYPE":  "all",
			"CAPTCHA_LISTEN":    "127.0.0.1:0",
			"CUSTOM_LIST_DIR":   "/etc/apache2/crowdsec",
			"CAPTCHA_PASS_FILE": "/etc/apache2/crowdsec/denylist.dbm",
		},
		// The listener being off is no longer a reprieve. The pass map is pre-created
		// on every start, whatever the captcha is doing, so this empties the ban map
		// on a deployment that never serves a challenge at all.
		"the ban map with the challenge listener off": {
			"CAPTCHA_PASS_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.txt",
		},
		// A dbm path is a BASE name: what reaches disk is base+suffix, chosen by
		// whichever backend httxt2dbm's APR was built against. Comparing the base
		// alone matched nothing that ever exists, so every one of these slipped
		// through and truncated the ban map's real data file at boot.
		"a ban dbm under the Berkeley DB name": {
			"CAPTCHA_PASS_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.dbm.db",
		},
		"a ban dbm under the SDBM data name": {
			"CAPTCHA_PASS_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.dbm.pag",
		},
		"a ban dbm under the SDBM index name": {
			"CAPTCHA_PASS_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.dbm.dir",
		},
		"a custom list dbm sibling": {
			"BOUNCING_ON_TYPE":  "all",
			"CAPTCHA_LISTEN":    "127.0.0.1:0",
			"CUSTOM_LIST_DIR":   "/etc/apache2/crowdsec",
			"CAPTCHA_PASS_FILE": "/etc/apache2/crowdsec/denylist.dbm.db",
		},
		// The readiness file is worse than the pass map on the same path: clearReady
		// DELETES it, and Apache will not start with a RewriteMap file missing.
		"the ready file aimed at a ban dbm sibling": {
			"BOUNCING_ON_TYPE":   "all",
			"CAPTCHA_LISTEN":     "127.0.0.1:0",
			"CAPTCHA_READY_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.dbm.db",
		},
	}
	for name, env := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			if err := load(t, env); err == nil {
				t.Fatal("a pass file colliding with a file the daemon writes must be refused")
			}
		})
	}

	// And no overreach. The readiness file is the one that stays scoped to the
	// listener: unlike the pass map it is only ever written while the listener runs,
	// so refusing to start over it otherwise would take enforcement down for a
	// setting nothing is going to touch.
	allowed := map[string]map[string]string{
		"the default pass file": {
			"BOUNCING_ON_TYPE": "all",
			"CAPTCHA_LISTEN":   "127.0.0.1:0",
		},
		"a custom-list path with custom lists off": {
			"BOUNCING_ON_TYPE":  "all",
			"CAPTCHA_LISTEN":    "127.0.0.1:0",
			"CUSTOM_LIST_DIR":   "",
			"CAPTCHA_PASS_FILE": "/etc/apache2/crowdsec/allowlist.txt",
		},
		"the ready file aimed at the ban map while the listener is off": {
			"CAPTCHA_READY_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.txt",
		},
	}
	for name, env := range allowed {
		t.Run("allows "+name, func(t *testing.T) {
			if err := load(t, env); err != nil {
				t.Fatalf("must load: %v", err)
			}
		})
	}
}

// Uncommenting CAPTCHA_LISTEN alone - the single most obvious step for an operator
// enabling captcha - must not be fatal. It used to be: nothing routed captcha, so
// loadConfig refused, and the daemon that had been maintaining the ban map stopped
// starting at all. A captcha misconfiguration must never take ban enforcement down,
// which is the rule the rest of loadCaptcha follows.
func TestCaptchaListenWithNoRoutingDegradesInsteadOfFailing(t *testing.T) {
	clearEnv(t)
	t.Setenv("CROWDSEC_API_KEY", "k")
	t.Setenv("BOUNCING_ON_TYPE", "ban") // the shipped default
	t.Setenv("CAPTCHA_LISTEN", "127.0.0.1:8125")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("CAPTCHA_LISTEN with nothing routed to it must not be fatal: %v", err)
	}
	if cfg.captchaListen != "" {
		t.Errorf("the listener should be switched off, got %q", cfg.captchaListen)
	}
	if cfg.captchaUsable() {
		t.Error("captchaUsable() should be false once the listener is off")
	}
	// The ban map must still be produced - that is the whole point of degrading.
	if !slices.Contains(cfg.remediations, remediationBan) {
		t.Errorf("ban enforcement was lost: remediations = %v", cfg.remediations)
	}
}

// The collision guard compares files, not the strings naming them. A relative
// CAPTCHA_PASS_FILE only collides when the working directory happens to be the map
// directory - unreachable through the packaged unit, which sets no
// WorkingDirectory, but reachable for anyone running the binary by hand from
// /var/lib. Third-pass review finding N1.
func TestPassFileCollisionIsFoundByFileNotSpelling(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // what a hand-run from the data directory looks like

	clearEnv(t)
	t.Setenv("CROWDSEC_API_KEY", "k")
	t.Setenv("BLOCKLIST_DIR", dir)
	t.Setenv("BOUNCING_ON_TYPE", "all")
	t.Setenv("CAPTCHA_LISTEN", "127.0.0.1:8125")
	// Names the ban map, but relative - the same file under a different spelling.
	t.Setenv("CAPTCHA_PASS_FILE", "blocklist.txt")

	_, err := loadConfig()
	if err == nil {
		t.Fatal("a pass file naming the ban map relatively must be refused; it is emptied at boot, which would unban everyone")
	}
	if !strings.Contains(err.Error(), "ban map") {
		t.Errorf("wrong refusal: %v", err)
	}
}

// FALLBACK_REMEDIATION=captcha with no listener is the one routing the fallback
// cannot absorb, because the fallback IS the captcha. Before the guard, the loader
// accepted it, rendered captcha.txt, and sent every decision it caught - throttles
// included - into a map with nothing serving the challenge it points at. Third-pass
// review finding: this was the state the deleted "captcha map with no listener"
// warning would have named, and it is reachable from config alone.
func TestFallbackToCaptchaWithNoListenerDemotesToBan(t *testing.T) {
	for _, bouncingOn := range []string{"all", "ban", "captcha"} {
		t.Run(bouncingOn, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("CROWDSEC_API_KEY", "k")
			t.Setenv("BOUNCING_ON_TYPE", bouncingOn)
			t.Setenv("FALLBACK_REMEDIATION", remediationCaptcha)
			// deliberately no CAPTCHA_LISTEN

			cfg, err := loadConfig()
			if err != nil {
				t.Fatalf("must degrade, not refuse to start: %v", err)
			}
			if cfg.fallbackRemediation != remediationBan {
				t.Errorf("fallbackRemediation = %q, want %q", cfg.fallbackRemediation, remediationBan)
			}
			// The real defect: a map nothing can enforce.
			if slices.Contains(cfg.remediations, remediationCaptcha) && !cfg.captchaUsable() {
				t.Errorf("captcha map is rendered with no listener to serve it: remediations = %v", cfg.remediations)
			}
			// Every unexpressible remediation the bouncer is watching has to land
			// somewhere enforceable. BOUNCING_ON_TYPE filters first, so a throttle is
			// dropped outright unless we are bouncing on everything - that is step 1
			// of resolveRemediation, not the fallback failing.
			wantThrottle := ""
			if bouncingOn == bouncingAll {
				wantThrottle = remediationBan
			}
			if got := cfg.resolveRemediation("throttle"); got != wantThrottle {
				t.Errorf("resolveRemediation(throttle) = %q, want %q", got, wantThrottle)
			}
			if !slices.Contains(cfg.remediations, remediationBan) {
				t.Errorf("ban enforcement was lost: remediations = %v", cfg.remediations)
			}
		})
	}
}

// The three ALTCHA guards exist because each bad value produces a page that spins
// until the widget's 90s timeout with nothing logged on our side - the failure
// hardest to diagnose from the outside. They fall back to the shipped defaults
// with a warning rather than refusing to start: dying over a captcha dial would
// take ban enforcement down with it. None of this was covered before.
func TestAltchaSettingsFallBackToTheDefaults(t *testing.T) {
	base := func(t *testing.T) {
		t.Helper()
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("BOUNCING_ON_TYPE", "all")
		t.Setenv("CAPTCHA_LISTEN", "127.0.0.1:8125")
	}
	wantDefaults := func(t *testing.T, cfg *config) {
		t.Helper()
		if cfg.altchaAlgorithm != altchaDefaultAlgorithm ||
			cfg.altchaCost != altchaDefaultCost ||
			cfg.altchaComplexity != altchaDefaultComplexity {
			t.Fatalf("want the shipped defaults, got %s cost=%d complexity=%d",
				cfg.altchaAlgorithm, cfg.altchaCost, cfg.altchaComplexity)
		}
	}

	t.Run("an algorithm the widget cannot solve falls back", func(t *testing.T) {
		base(t)
		t.Setenv("ALTCHA_ALGORITHM", "argon2id")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("an unknown ALTCHA_ALGORITHM must not be fatal: %v", err)
		}
		if cfg.altchaAlgorithm != altchaDefaultAlgorithm {
			t.Fatalf("algorithm = %q, want the default %q", cfg.altchaAlgorithm, altchaDefaultAlgorithm)
		}
	})

	// The plain family spends one awaited crypto.subtle call per iteration, so cost
	// multiplies the CALL count - the dial that decides whether a browser can finish.
	// All THREE dials must reset, not just the offenders: the default cost and
	// complexity under plain SHA-256 still exceed the call budget on their own.
	t.Run("more WebCrypto calls than a browser can make resets every dial", func(t *testing.T) {
		base(t)
		t.Setenv("ALTCHA_ALGORITHM", "SHA-256")
		t.Setenv("ALTCHA_COMPLEXITY", "20000")
		t.Setenv("ALTCHA_COST", "1000")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("a combination past altchaMaxWebCryptoCalls must not be fatal: %v", err)
		}
		wantDefaults(t, cfg)
	})

	// PBKDF2 hides its cost inside one call, so the call count cannot see it: total
	// iterations have to be bounded separately, or ALTCHA_COST=100000 sails through
	// while asking for 500M iterations and raising every mint WE perform to ~16ms.
	t.Run("more total iterations than a browser can finish resets every dial", func(t *testing.T) {
		base(t)
		t.Setenv("ALTCHA_ALGORITHM", "PBKDF2/SHA-256")
		t.Setenv("ALTCHA_COMPLEXITY", "10000")
		t.Setenv("ALTCHA_COST", "100000")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("a combination past altchaMaxIterations must not be fatal: %v", err)
		}
		wantDefaults(t, cfg)
	})

	// The guard must not clobber values that are merely unusual. These are valid -
	// ~9,000 WebCrypto calls, ~24M iterations - so they have to survive untouched.
	t.Run("valid non-default dials are honoured", func(t *testing.T) {
		base(t)
		t.Setenv("ALTCHA_ALGORITHM", "pbkdf2/sha-512") // case-insensitive spelling too
		t.Setenv("ALTCHA_COMPLEXITY", "6000")
		t.Setenv("ALTCHA_COST", "8000")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.altchaAlgorithm != "PBKDF2/SHA-512" || cfg.altchaCost != 8000 || cfg.altchaComplexity != 6000 {
			t.Fatalf("valid dials were changed: %s cost=%d complexity=%d",
				cfg.altchaAlgorithm, cfg.altchaCost, cfg.altchaComplexity)
		}
	})

	// Past the ceiling the value is HELD, not treated as unsolvable: the budget
	// checks are what reject a combination a browser cannot finish, and this one it
	// can. Resetting all three dials here would throw away a deliberate algorithm
	// and cost over a complexity the daemon is willing to substitute for.
	t.Run("a complexity past the ceiling is held there, not reset", func(t *testing.T) {
		base(t)
		t.Setenv("ALTCHA_ALGORITHM", "SHA-256")
		t.Setenv("ALTCHA_COST", "1")
		t.Setenv("ALTCHA_COMPLEXITY", "5000000")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("a complexity past the ceiling must not be fatal: %v", err)
		}
		if cfg.altchaComplexity != 1_000_000 {
			t.Fatalf("complexity = %d, want it held at the 1,000,000 ceiling", cfg.altchaComplexity)
		}
		if cfg.altchaAlgorithm != "SHA-256" || cfg.altchaCost != 1 {
			t.Fatalf("holding the complexity must not disturb the other dials: %s cost=%d",
				cfg.altchaAlgorithm, cfg.altchaCost)
		}
	})

	// A typo in the NAME must reset the dials too, or substituting only the name
	// silently changes what the dials mean. This combination is the trap: a plain
	// SHA name with the cost=1 that family wants, at a complexity sized for it. Land
	// it on PBKDF2 and every candidate costs three WebCrypto calls instead of one -
	// 1.5M against the 500k asked for - which is still under the 5M budget, so the
	// check below would never fire and the visitor silently pays triple. The
	// complexity here is the ceiling exactly, so it is a value that reaches the
	// budget checks unclamped: a higher one would be held at the ceiling first and
	// the arithmetic above would no longer be what this test exercises.
	t.Run("an unknown algorithm resets the cost and complexity too", func(t *testing.T) {
		base(t)
		t.Setenv("ALTCHA_ALGORITHM", "SHA-2566") // a plausible typo, not a wild value
		t.Setenv("ALTCHA_COST", "1")
		t.Setenv("ALTCHA_COMPLEXITY", "1000000")
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("a typo'd algorithm must not be fatal: %v", err)
		}
		wantDefaults(t, cfg)
	})

	t.Run("the shipped defaults are accepted", func(t *testing.T) {
		base(t)
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("the defaults must load: %v", err)
		}
		wantDefaults(t, cfg)
	})
}

// METRICS_PATH is the daemon's only operator-controlled ServeMux pattern, and
// ServeMux answers a pattern it cannot parse with a PANIC. serveMetrics runs in its
// own goroutine, so that panic is not recoverable by any caller and takes the whole
// process - the one holding the ban maps current - down with it, on a five-second
// restart loop that never reaches a poll.
//
// The last case is the one that matters most: rather than listing shapes somebody
// thought of, it asserts the property, that whatever loadMetrics produces is
// something ServeMux will actually accept. A new bad shape fails there even if
// nobody adds a case for it.
func TestMetricsPathIsHeldToSomethingServeMuxAccepts(t *testing.T) {
	load := func(t *testing.T, value string) *config {
		t.Helper()
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("METRICS_LISTEN", "127.0.0.1:0")
		t.Setenv("METRICS_PATH", value)
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("METRICS_PATH %q must never be fatal - metrics are not enforcement: %v", value, err)
		}
		return cfg
	}

	hostile := []string{
		"metrics", "/metrics ", " /metrics", "/met rics", "/metrics{", "/m{id}", "   ", "\tmetrics\t",
		// Unclean paths register without complaint and are then unreachable, because
		// ServeMux canonicalises the request path before matching. Registering is the
		// weaker property; these are the cases that separate it from being reachable.
		"//metrics", "/a/../metrics", "/./metrics", "//metrics//",
	}

	t.Run("a missing leading slash is honoured rather than discarded", func(t *testing.T) {
		if got := load(t, "metrics").metricsPath; got != "/metrics" {
			t.Fatalf("metricsPath = %q, want %q", got, "/metrics")
		}
	})

	t.Run("surrounding whitespace is trimmed, not refused", func(t *testing.T) {
		if got := load(t, "/metrics ").metricsPath; got != "/metrics" {
			t.Fatalf("metricsPath = %q, want %q", got, "/metrics")
		}
	})

	t.Run("pattern syntax falls back to the default rather than being guessed at", func(t *testing.T) {
		for _, v := range []string{"/met rics", "/metrics{", "/m{id}"} {
			if got := load(t, v).metricsPath; got != metricsDefaultPath {
				t.Fatalf("METRICS_PATH %q: metricsPath = %q, want the default %q", v, got, metricsDefaultPath)
			}
		}
	})

	// The property that matters is NOT "ServeMux accepts it" - that is satisfied by
	// patterns no request can ever reach, which is the whole of the unclean-path bug.
	// It is "a GET for the path the daemon prints at startup lands on the handler".
	t.Run("every value it can produce is one a scrape can actually reach", func(t *testing.T) {
		for _, v := range append(hostile, "/metrics", "/metrics/", "/x/y", "") {
			cfg := load(t, v)
			mux := http.NewServeMux()
			reached := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("METRICS_PATH %q produced %q, which ServeMux panics on: %v", v, cfg.metricsPath, r)
					}
				}()
				mux.HandleFunc(cfg.metricsPath, func(http.ResponseWriter, *http.Request) { reached = true })
			}()

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, cfg.metricsPath, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if !reached || rec.Code != http.StatusOK {
				t.Errorf("METRICS_PATH %q produced %q: a GET for that path returned %d and did not reach the handler - registered but unreachable",
					v, cfg.metricsPath, rec.Code)
			}
		}
	})
}

// captureLog redirects the standard logger for one test and returns what it wrote.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// A clamp that says nothing is the whole defect here. These settings are held to a
// range where they are READ, so the value the operator wrote is gone by the time
// anything else runs - and every later line, including the solvability warning,
// then quotes the number in force, sending them after a line they never wrote.
//
// Driven through loadConfig rather than clampEnvInt directly, so this also pins
// that the three call sites are wired to it: a future edit that inlines a min/max
// back into one of them fails here rather than going quiet again.
func TestClampedSettingsSaySoInTheLog(t *testing.T) {
	setup := func(t *testing.T, name, value string) {
		t.Helper()
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("BOUNCING_ON_TYPE", "all")
		t.Setenv("CAPTCHA_LISTEN", "127.0.0.1:8125")
		t.Setenv(name, value)
	}

	for _, tc := range []struct{ name, env, set, want string }{
		{
			name: "a complexity past the ceiling",
			env:  "ALTCHA_COMPLEXITY", set: "5000000",
			want: "ALTCHA_COMPLEXITY (5000000) out of range; using 1000000 (accepted: 1000-1000000)",
		},
		{
			name: "a cost past the ceiling",
			env:  "ALTCHA_COST", set: "500000",
			want: "ALTCHA_COST (500000) out of range; using 100000 (accepted: 1-100000)",
		},
		{
			name: "a pass TTL under the floor",
			env:  "CAPTCHA_PASS_TTL", set: "30",
			want: "CAPTCHA_PASS_TTL (30) out of range; using 60 (accepted: 60-315360000)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup(t, tc.env, tc.set)
			logged := captureLog(t)
			if _, err := loadConfig(); err != nil {
				t.Fatalf("a clamped setting must not be fatal: %v", err)
			}
			if !strings.Contains(logged.String(), tc.want) {
				t.Fatalf("the log must name the value that was set AND the one in force\n want substring: %s\n got: %s",
					tc.want, logged.String())
			}
		})
	}

	// And the quiet case, or the warning stops carrying information: the shipped
	// defaults are all in range, so a clean start must say nothing about a clamp.
	t.Run("in-range settings are silent", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("BOUNCING_ON_TYPE", "all")
		t.Setenv("CAPTCHA_LISTEN", "127.0.0.1:8125")
		logged := captureLog(t)
		if _, err := loadConfig(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(logged.String(), "out of range") {
			t.Fatalf("the defaults must not report a clamp: %s", logged.String())
		}
	})
}

// CAPTCHA_READY_FILE is created when the listener comes up and DELETED when it
// goes down, so a path aimed at something the daemon maintains is destroyed twice
// over: truncated to zero bytes at boot, removed at shutdown. The pass file was
// guarded and this one was not - pointed at the ban map it emptied the ban list on
// every start and deleted it on every stop, with the daemon reporting nothing.
func TestReadyFileCollisionGuard(t *testing.T) {
	load := func(t *testing.T, env map[string]string) error {
		t.Helper()
		clearEnv(t)
		t.Setenv("CROWDSEC_API_KEY", "k")
		t.Setenv("BOUNCING_ON_TYPE", "all")
		t.Setenv("CAPTCHA_LISTEN", "127.0.0.1:0")
		for k, v := range env {
			t.Setenv(k, v)
		}
		_, err := loadConfig()
		return err
	}

	refused := map[string]map[string]string{
		"the ban map":     {"CAPTCHA_READY_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.txt"},
		"the ban dbm":     {"CAPTCHA_READY_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.dbm"},
		"the captcha map": {"CAPTCHA_READY_FILE": "/var/lib/crowdsec-apache2-bouncer/captcha.txt"},
		// Retired maps are still written - retireUnusedMaps empties them - so the
		// guard has to cover the whole known set, not just what this policy renders.
		"the retired ban map under a captcha-only policy": {
			"BOUNCING_ON_TYPE":   "captcha",
			"CAPTCHA_READY_FILE": "/var/lib/crowdsec-apache2-bouncer/blocklist.txt",
		},
		"a custom allowlist nothing would rebuild": {
			"CUSTOM_LIST_DIR":    "/etc/apache2/crowdsec",
			"CAPTCHA_READY_FILE": "/etc/apache2/crowdsec/allowlist.txt",
		},
		// Deleting the readiness file at shutdown would take every pass with it.
		"the pass map": {"CAPTCHA_READY_FILE": "/var/lib/crowdsec-apache2-bouncer/captcha_passed.txt"},
	}
	for name, env := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			if err := load(t, env); err == nil {
				t.Fatal("a readiness file aimed at a file the daemon destroys must be refused")
			}
		})
	}

	allowed := map[string]map[string]string{
		"the shipped default under /run": {},
		"a path of its own":              {"CAPTCHA_READY_FILE": "/run/crowdsec-apache2-bouncer/up"},
		// Empty switches the readiness signal off entirely; there is nothing to clash.
		"the signal switched off": {"CAPTCHA_READY_FILE": ""},
	}
	for name, env := range allowed {
		t.Run("allows "+name, func(t *testing.T) {
			if err := load(t, env); err != nil {
				t.Fatalf("must load: %v", err)
			}
		})
	}
}
