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
	"log"
	"os/signal"
	"syscall"
)

// -dir overrides BLOCKLIST_DIR; explicit OUTPUT_FILE/DBM_FILE override both.
var flagDir = flag.String("dir", "", "directory for blocklist.txt/.dbm (default /var/lib/crowdsec-apache2-bouncer, or BLOCKLIST_DIR)")

// main loads the config, builds the bouncer, and runs it until SIGINT/SIGTERM.
func main() {
	log.SetFlags(log.LstdFlags) // local date+time on each line (journald adds its own too)
	flag.Parse()
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
