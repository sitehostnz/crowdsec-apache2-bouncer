package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
)

// solveAltcha is the work the BROWSER does. It lives here only so the tests can act
// as a client; nothing in the daemon calls it. The real widget grinds until its own
// timeout rather than to a bound.
func solveAltcha(ch altchaChallenge, maxCounter int64) (string, bool) {
	if maxCounter > math.MaxUint32 {
		maxCounter = math.MaxUint32
	}
	for n := int64(0); n <= maxCounter; n++ {
		derived, err := altchaDeriveKey(ch.Parameters, uint32(n))
		if err != nil {
			return "", false
		}
		if got := hex.EncodeToString(derived); strings.HasPrefix(got, ch.Parameters.KeyPrefix) {
			return got, true
		}
	}
	return "", false
}

// encodeAltchaPayload builds what the widget would submit. Test-side only.
func encodeAltchaPayload(derivedKey string) string {
	blob, _ := json.Marshal(altchaPayload{Solution: altchaSolution{DerivedKey: derivedKey}})
	return base64.StdEncoding.EncodeToString(blob)
}
