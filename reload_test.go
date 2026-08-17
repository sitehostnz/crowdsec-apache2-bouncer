package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeConf writes an env file with the given KEY=VALUE lines, in no particular
// order, plus a comment to prove those are skipped.
func writeConf(t *testing.T, path string, kv map[string]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# managed by the test\n")
	for k, v := range kv {
		b.WriteString(k + "=" + v + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParseEnvFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.conf")
	content := "" +
		"# a comment\n" +
		"; another comment\n" +
		"\n" +
		"FOO=bar\n" +
		"  SPACED = value with spaces  \n" +
		"QUOTED=\"quoted value\"\n" +
		"SQUOTED='single'\n" +
		"EMPTY=\n" +
		"NOEQUALS\n" +
		"KEY=has=equals=signs\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := parseEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"FOO":     "bar",
		"SPACED":  "value with spaces",
		"QUOTED":  "quoted value",
		"SQUOTED": "single",
		"EMPTY":   "",
		"KEY":     "has=equals=signs",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["NOEQUALS"]; ok {
		t.Errorf("a line with no '=' should be skipped, got %q", got["NOEQUALS"])
	}

	if _, err := parseEnvFile(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Error("parseEnvFile on a missing file should error")
	}
}

func TestLoadConfigFromFileOverlaysEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.conf")
	// The key is only in the environment; the frequency is in both, and the file
	// must win.
	t.Setenv("CROWDSEC_API_KEY", "from-env")
	t.Setenv("UPDATE_FREQUENCY", "30")
	t.Setenv("CUSTOM_LIST_DIR", "") // keep the loader off /etc in the test env
	writeConf(t, path, map[string]string{
		"BLOCKLIST_DIR":    dir,
		"MAP_TYPE":         "txt",
		"UPDATE_FREQUENCY": "90",
	})

	cfg, err := loadConfigFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.updateFrequency != 90*time.Second {
		t.Errorf("file should win for UPDATE_FREQUENCY: got %s, want 90s", cfg.updateFrequency)
	}
	if cfg.apiKey != "from-env" {
		t.Errorf("key absent from the file should fall back to the environment: got %q", cfg.apiKey)
	}

	// envLookup must be restored: a plain loadConfig now reads the environment
	// again, where UPDATE_FREQUENCY is 30, not the file's 90.
	cfg2, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.updateFrequency != 30*time.Second {
		t.Errorf("envLookup was not restored: loadConfig read %s, want the env's 30s", cfg2.updateFrequency)
	}
}

// reloadBouncer builds a running bouncer from an initial conf file and points its
// reload at that same file. The challenge listener is wired up (without actually
// serving) when the config asks for it, so the dial/TTL paths can be exercised.
func reloadBouncer(t *testing.T, path string) *bouncer {
	t.Helper()
	cfg, err := loadConfigFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.configFile = path // loadConfig defaults this to the packaged path; aim it at ours
	b, err := newBouncer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.captchaUsable() {
		b.passes = newPassStore(cfg.captchaPassFile, cfg.captchaPassTTL)
		srv, err := newChallengeServer(cfg, b.passes, b.metrics)
		if err != nil {
			t.Fatal(err)
		}
		b.challenge = srv
	}
	return b
}

func TestReloadAppliesRuntimeKnobs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.conf")
	base := map[string]string{
		"CROWDSEC_API_KEY": "k", "BLOCKLIST_DIR": dir, "MAP_TYPE": "txt", "CUSTOM_LIST_DIR": "",
	}
	v1 := map[string]string{"UPDATE_FREQUENCY": "60", "RESYNC_INTERVAL": "21600", "EXPAND_MAX_HOSTS": "65536", "STREAM_REQUEST_TIMEOUT": "15"}
	for k, v := range base {
		v1[k] = v
	}
	writeConf(t, path, v1)
	b := reloadBouncer(t, path)

	v2 := map[string]string{"UPDATE_FREQUENCY": "120", "RESYNC_INTERVAL": "7200", "EXPAND_MAX_HOSTS": "1024", "STREAM_REQUEST_TIMEOUT": "30"}
	for k, v := range base {
		v2[k] = v
	}
	writeConf(t, path, v2)

	if !b.reload() {
		t.Error("reload should report the poll frequency changed")
	}
	if b.cfg.updateFrequency != 120*time.Second {
		t.Errorf("UPDATE_FREQUENCY not applied: got %s", b.cfg.updateFrequency)
	}
	if b.cfg.resyncInterval != 7200*time.Second {
		t.Errorf("RESYNC_INTERVAL not applied: got %s", b.cfg.resyncInterval)
	}
	if b.cfg.expandMaxHosts != 1024 {
		t.Errorf("EXPAND_MAX_HOSTS not applied: got %d", b.cfg.expandMaxHosts)
	}
	if b.cfg.streamRequestTimeout != 30*time.Second {
		t.Errorf("STREAM_REQUEST_TIMEOUT not applied: got %s", b.cfg.streamRequestTimeout)
	}
}

func TestReloadDefersStructuralSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.conf")
	base := map[string]string{"CROWDSEC_API_KEY": "k", "MAP_TYPE": "txt", "CUSTOM_LIST_DIR": ""}
	v1 := map[string]string{"BLOCKLIST_DIR": dir, "CROWDSEC_LAPI_URL": "http://127.0.0.1:8080"}
	for k, v := range base {
		v1[k] = v
	}
	writeConf(t, path, v1)
	b := reloadBouncer(t, path)
	origOut, origLAPI := b.cfg.outputFile, b.cfg.lapiURL

	// A new output directory and LAPI URL are structural: they must be detected but
	// NOT applied, because the map paths and HTTP client are built once at start.
	otherDir := t.TempDir()
	v2 := map[string]string{"BLOCKLIST_DIR": otherDir, "CROWDSEC_LAPI_URL": "http://10.0.0.1:9000"}
	for k, v := range base {
		v2[k] = v
	}
	writeConf(t, path, v2)
	b.reload()

	if b.cfg.outputFile != origOut {
		t.Errorf("OUTPUT_FILE must not change on reload: got %q, want %q", b.cfg.outputFile, origOut)
	}
	if b.cfg.lapiURL != origLAPI {
		t.Errorf("CROWDSEC_LAPI_URL must not change on reload: got %q, want %q", b.cfg.lapiURL, origLAPI)
	}
}

func TestReloadAppliesChallengeDials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.conf")
	base := map[string]string{
		"CROWDSEC_API_KEY": "k", "BLOCKLIST_DIR": dir, "MAP_TYPE": "txt", "CUSTOM_LIST_DIR": "",
		"BOUNCING_ON_TYPE": "all", "CAPTCHA_LISTEN": "127.0.0.1:0",
	}
	v1 := map[string]string{
		"ALTCHA_ALGORITHM": "PBKDF2/SHA-256", "ALTCHA_COST": "5000",
		"ALTCHA_COMPLEXITY": "5000", "CAPTCHA_PASS_TTL": "3600",
	}
	for k, v := range base {
		v1[k] = v
	}
	writeConf(t, path, v1)
	b := reloadBouncer(t, path)
	if b.challenge == nil || b.passes == nil {
		t.Fatal("challenge listener should be wired for this config")
	}

	v2 := map[string]string{
		"ALTCHA_ALGORITHM": "PBKDF2/SHA-512", "ALTCHA_COST": "8000",
		"ALTCHA_COMPLEXITY": "6000", "CAPTCHA_PASS_TTL": "1800",
	}
	for k, v := range base {
		v2[k] = v
	}
	writeConf(t, path, v2)
	b.reload()

	d := b.challenge.dials.Load()
	if d.algorithm != "PBKDF2/SHA-512" || d.cost != 8000 || d.complexity != 6000 {
		t.Errorf("ALTCHA dials not applied: got %s/cost=%d/complexity=%d", d.algorithm, d.cost, d.complexity)
	}
	if ttl := b.passes.ttlOf(); ttl != 1800*time.Second {
		t.Errorf("CAPTCHA_PASS_TTL not applied: got %s", ttl)
	}
}

// TestReloadRaceWithChallengeReads models production: the poll goroutine reloads
// the ALTCHA dials and pass TTL while request goroutines read them. It exists to
// be run under -race - a plain cfg write for these would be flagged here, which is
// why they go through the atomic snapshot and the passStore mutex instead.
func TestReloadRaceWithChallengeReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncer.conf")
	base := map[string]string{
		"CROWDSEC_API_KEY": "k", "BLOCKLIST_DIR": dir, "MAP_TYPE": "txt", "CUSTOM_LIST_DIR": "",
		"BOUNCING_ON_TYPE": "all", "CAPTCHA_LISTEN": "127.0.0.1:0",
	}
	write := func(cost string) {
		kv := map[string]string{"ALTCHA_COST": cost, "ALTCHA_COMPLEXITY": "5000", "CAPTCHA_PASS_TTL": "3600"}
		for k, v := range base {
			kv[k] = v
		}
		writeConf(t, path, kv)
	}
	write("5000")
	b := reloadBouncer(t, path)

	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					_ = b.challenge.dials.Load()
					_ = b.passes.ttlOf()
				}
			}
		}()
	}
	for i := 0; i < 30; i++ {
		if i%2 == 0 {
			write("6000")
		} else {
			write("5000")
		}
		b.reload()
	}
	close(done)
	wg.Wait()
}

func TestReloadWithoutConfigFileIsANoOp(t *testing.T) {
	b := testBouncer(t, nil)
	b.cfg.configFile = "" // no file configured
	freq := b.cfg.updateFrequency
	if b.reload() {
		t.Error("reload with no config file should report no frequency change")
	}
	if b.cfg.updateFrequency != freq {
		t.Error("reload with no config file must not change anything")
	}
}
