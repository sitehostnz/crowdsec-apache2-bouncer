// Command crowdsec-apache2-bouncer is a stream-mode CrowdSec bouncer that
// renders the active ban list to an Apache RewriteMap file, for cPanel / Plesk
// Apache2 origins.
//
// Flow (CrowdSec stream API):
//   - on start: GET /v1/decisions/stream?startup=true  -> full snapshot
//   - then:     GET /v1/decisions/stream?startup=false -> deltas (new + deleted)
//     every UPDATE_FREQUENCY seconds, to maintain the list.
//
// Output is a RewriteMap "txt" file ("<ip> 1" per line); with MAP_TYPE=dbm it
// also builds a DBM hash map via httxt2dbm (O(1) Apache lookups):
//
//	RewriteMap  crowdsec dbm:/var/lib/crowdsec-apache2-bouncer/blocklist.dbm
//	RewriteCond ${crowdsec:%{REMOTE_ADDR}|0} =1
//	RewriteRule ^ - [F]
//
// Range/CIDR decisions are EXPANDED to individual IPs (a RewriteMap is exact
// match only), capped by EXPAND_MAX_HOSTS; larger ranges (and any large IPv6
// range) are skipped and logged rather than exploding the file. IPs are
// canonicalised (RFC 5952, IPv4-mapped unwrapped) to byte-match %{REMOTE_ADDR}.
//
// Config via environment - see crowdsec-apache2-bouncer.conf. Stdlib only.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"
)

// -dir overrides BLOCKLIST_DIR; explicit OUTPUT_FILE/DBM_FILE override both.
var flagDir = flag.String("dir", "", "directory for blocklist.txt/.dbm (default /var/lib/crowdsec-apache2-bouncer, or BLOCKLIST_DIR)")

// -version answers the question you ask standing on the box: which build is this?
// Until now the only way to tell was to scrape the metrics endpoint, which needs
// the daemon running and METRICS_LISTEN set - no use when it will not start, which
// is exactly when the question comes up.
var flagVersion = flag.Bool("version", false, "print the version and exit")

// -config names the env file SIGHUP re-reads (see reload). It defaults to the
// path the packaged unit uses as its EnvironmentFile, so the shipped install
// reloads with no extra flag; CONFIG_FILE overrides it too, the flag winning.
var flagConfig = flag.String("config", "", "env file to re-read on SIGHUP (default the packaged unit's EnvironmentFile, or CONFIG_FILE)")

// main loads the config, builds the bouncer, and runs it until SIGINT/SIGTERM.
func main() {
	log.SetFlags(log.LstdFlags) // local date+time on each line (journald adds its own too)
	flag.Parse()
	if *flagVersion {
		// Straight to stdout, not the log, so it can be captured without a
		// timestamp in front of it.
		fmt.Println(userAgent)
		return
	}
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	b, err := newBouncer(cfg)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	b.run(ctx)
}
