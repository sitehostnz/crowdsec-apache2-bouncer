package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxStreamBytes bounds the decoded decision-stream body as defence-in-depth
// against a buggy or compromised LAPI; a real stream is far smaller.
const maxStreamBytes = 256 << 20 // 256 MiB

// fetch GETs the decision stream (startup=true for a full snapshot, false for
// deltas) and decodes it. An empty 200 body means "no changes".
func (b *bouncer) fetch(ctx context.Context, startup bool) (*streamResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, b.cfg.streamRequestTimeout)
	defer cancel()
	url := fmt.Sprintf("%s/v1/decisions/stream?startup=%t", b.cfg.lapiURL, startup)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", b.cfg.apiKey)
	req.Header.Set("User-Agent", "crowdsec-apache2-bouncer/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("LAPI returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var sr streamResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxStreamBytes)).Decode(&sr); err != nil {
		if errors.Is(err, io.EOF) {
			return &streamResponse{}, nil // empty body = no changes
		}
		return nil, fmt.Errorf("decoding stream response: %w", err)
	}
	return &sr, nil
}
