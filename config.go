package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// maxDurationSecs caps the seconds-valued env vars so a wildly large value can't
// overflow time.Duration (int64 ns). 10 years is far beyond any real setting.
const maxDurationSecs = 315360000

// config holds the runtime configuration, populated from the environment and the
// -dir flag by loadConfig.
type config struct {
	lapiURL              string
	apiKey               string
	outputFile           string
	updateFrequency      time.Duration
	expandMaxHosts       uint64
	onlyBan              bool
	resyncInterval       time.Duration
	requestTimeout       time.Duration
	streamRequestTimeout time.Duration
	mapType              string // "txt" | "dbm"
	httxt2dbm            string
	dbmFile              string
	insecure             bool
	caBundle             string
	// customListDir holds the operator-maintained allowlist/denylist the daemon
	// creates and keeps DBMs for; empty switches that off.
	customListDir string
}

// envStr returns environment variable name, or def when it is unset or empty.
func envStr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// envInt returns environment variable name parsed as an int, falling back to def
// when it is unset, empty or unparseable.
func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

// envBool returns environment variable name as a bool (1/true/yes/on are true;
// anything else is false), or def when it is unset.
func envBool(name string, def bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// envOptional returns environment variable name, or def when it is *unset*.
// Unlike envStr, an explicitly empty value comes back empty rather than falling
// back to def - which lets an operator write "VAR=" to turn a feature off.
func envOptional(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return strings.TrimSpace(v)
	}
	return def
}

// loadConfig assembles a config from the -dir flag and environment variables,
// applying defaults. It errors if CROWDSEC_API_KEY is unset, or if MAP_TYPE=dbm
// but httxt2dbm can't be found.
func loadConfig() (*config, error) {
	// Blocklist directory: -dir flag > BLOCKLIST_DIR env > default. The txt map,
	// the DBM, and every temp file live here (same-dir keeps renames atomic).
	// Explicit OUTPUT_FILE / DBM_FILE env vars trump the directory entirely.
	dir := *flagDir
	if dir == "" {
		dir = envStr("BLOCKLIST_DIR", "/var/lib/crowdsec-apache2-bouncer")
	}
	cfg := &config{
		lapiURL:         strings.TrimRight(envStr("CROWDSEC_LAPI_URL", "http://127.0.0.1:8080"), "/"),
		apiKey:          envStr("CROWDSEC_API_KEY", ""),
		outputFile:      envStr("OUTPUT_FILE", filepath.Join(dir, "blocklist.txt")),
		updateFrequency: time.Duration(min(maxDurationSecs, max(1, envInt("UPDATE_FREQUENCY", 10)))) * time.Second,
		expandMaxHosts:  uint64(min(1<<20, max(1, envInt("EXPAND_MAX_HOSTS", 65536)))),
		onlyBan:         envBool("ONLY_BAN", true),
		resyncInterval:  time.Duration(min(maxDurationSecs, envInt("RESYNC_INTERVAL", 21600))) * time.Second,
		requestTimeout:  time.Duration(min(maxDurationSecs, max(1, envInt("REQUEST_TIMEOUT", 10)))) * time.Second,
		// STREAM_REQUEST_TIMEOUT: the whole-query deadline for the decision stream
		// (the startup snapshot can be large), separate from the connect timeout.
		streamRequestTimeout: time.Duration(min(maxDurationSecs, max(1, envInt("STREAM_REQUEST_TIMEOUT", 15)))) * time.Second,
		mapType:              strings.ToLower(envStr("MAP_TYPE", "txt")),
		httxt2dbm:            envStr("HTTXT2DBM", "httxt2dbm"),
		insecure:             envBool("INSECURE", false),
		caBundle:             envStr("CA_BUNDLE", ""),
		// The daemon creates allowlist.txt/denylist.txt here and, in dbm mode,
		// rebuilds their DBMs when they change. Set CUSTOM_LIST_DIR= (empty) to
		// leave them alone entirely, or point it elsewhere on RHEL-family layouts
		// where Apache config lives under /etc/httpd.
		customListDir: envOptional("CUSTOM_LIST_DIR", "/etc/apache2/crowdsec"),
	}
	if cfg.apiKey == "" {
		return nil, fmt.Errorf("CROWDSEC_API_KEY is required (cscli bouncers add <name>)")
	}
	cfg.dbmFile = envStr("DBM_FILE", defaultDBMPath(cfg.outputFile))
	if cfg.mapType == "dbm" {
		if _, err := exec.LookPath(cfg.httxt2dbm); err != nil {
			return nil, fmt.Errorf("MAP_TYPE=dbm but %q not found (install apache2-utils / httpd-tools, or set HTTXT2DBM)", cfg.httxt2dbm)
		}
	}
	// REQUEST_TIMEOUT is a per-phase bound nested inside the overall
	// STREAM_REQUEST_TIMEOUT deadline, so a larger value would be masked by the
	// stream deadline and never fire. Cap it so it always stays effective.
	if cfg.requestTimeout > cfg.streamRequestTimeout {
		log.Printf("REQUEST_TIMEOUT (%s) > STREAM_REQUEST_TIMEOUT (%s); capping REQUEST_TIMEOUT to the stream timeout",
			cfg.requestTimeout, cfg.streamRequestTimeout)
		cfg.requestTimeout = cfg.streamRequestTimeout
	}
	return cfg, nil
}

// defaultDBMPath derives the DBM path from the txt output path, swapping a
// trailing .txt for .dbm.
func defaultDBMPath(outputFile string) string {
	return strings.TrimSuffix(outputFile, ".txt") + ".dbm"
}
