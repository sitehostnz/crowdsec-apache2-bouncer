package main

import (
	"encoding/json"
	"log"
	"net/netip"
	"strings"
)

// decision is one CrowdSec LAPI decision (e.g. a ban) scoped to an IP or range.
type decision struct {
	ID    json.Number `json:"id"`
	Scope string      `json:"scope"`
	Value string      `json:"value"`
	Type  string      `json:"type"`
}

// streamResponse is the LAPI /v1/decisions/stream payload: the decisions added
// and removed since the last pull.
type streamResponse struct {
	New     []decision `json:"new"`
	Deleted []decision `json:"deleted"`
}

// included reports whether a decision should be enforced: it must be IP- or
// range-scoped, and (unless ONLY_BAN is disabled) of type=ban.
func (b *bouncer) included(d decision) bool {
	if b.cfg.onlyBan && !strings.EqualFold(d.Type, "ban") {
		return false
	}
	scope := strings.ToLower(d.Scope)
	return scope == "ip" || scope == "range"
}

// expand turns one decision into the set of RewriteMap keys it contributes.
// Single IPs are canonicalised (RFC 5952, IPv4-mapped unwrapped) so the key
// byte-matches Apache's %{REMOTE_ADDR}. Ranges are enumerated up to the cap.
func (b *bouncer) expand(d decision) map[string]struct{} {
	value := strings.TrimSpace(d.Value)
	if value == "" {
		return nil
	}
	switch strings.ToLower(d.Scope) {
	case "ip":
		addr, err := netip.ParseAddr(value)
		if err != nil {
			log.Printf("skip invalid ip %q: %v", value, err)
			return nil
		}
		return map[string]struct{}{addr.Unmap().String(): {}}
	case "range":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			log.Printf("skip invalid range %q: %v", value, err)
			return nil
		}
		prefix = prefix.Masked()
		hostBits := prefix.Addr().BitLen() - prefix.Bits()
		if hostBits >= 63 || uint64(1)<<hostBits > b.cfg.expandMaxHosts {
			b.skippedRanges++
			log.Printf("skip large range %s (2^%d addrs > EXPAND_MAX_HOSTS=%d) - use ipset for this",
				value, hostBits, b.cfg.expandMaxHosts)
			return nil
		}
		ips := make(map[string]struct{}, uint64(1)<<hostBits)
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			ips[addr.Unmap().String()] = struct{}{}
		}
		return ips
	}
	return nil // country / as / username scopes can't map to IPs
}
