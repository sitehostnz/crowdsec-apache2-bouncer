package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// directiveRE recognises a line that is an Apache directive rather than prose. The
// distinction matters: this file is mostly commentary, and the commentary quotes
// wrong forms on purpose in order to warn against them. A test that greps the whole
// text fires on its own documentation, so everything structural below runs over
// directives only.
var directiveRE = regexp.MustCompile(`^(RewriteCond|RewriteRule|RewriteMap|RewriteEngine|</?Location|</?LocationMatch|</?IfModule|</?Directory|ProxyPass|ProxyPassReverse|SecRuleEngine|Alias|Require|ErrorDocument|Header|CustomLog|LogFormat)\b`)

// apacheDirectives returns the shipped config's directive lines, with the template's
// comment prefix stripped. Operators uncomment what they need, so the directives live
// behind a "#" and some indentation.
func apacheDirectives(t *testing.T, raw string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(line)
		s = strings.TrimPrefix(s, "#")
		s = strings.TrimSpace(s)
		if directiveRE.MatchString(s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		t.Fatal("no directives recognised at all - has the file's comment style changed?")
	}
	return out
}

// apache/blocklist.conf is the enforcement half of this feature: the daemon only
// writes map files, and Apache is what acts on them. Nothing in the suite read it
// until now, so every value it hand-copies from the daemon could drift silently -
// and the anchoring on its exemptions has been corrected in three consecutive
// commits with no test behind any of them. The file's own header calls the loose
// form a measured, reproduced enforcement bypass.
//
// Built from the daemon's own defaults rather than typed again, so renaming a
// default fails here instead of leaving the shipped config quietly stale.
func TestApacheConfMatchesTheDaemonsDefaults(t *testing.T) {
	raw, err := os.ReadFile("apache/blocklist.conf")
	if err != nil {
		t.Fatalf("the shipped Apache config must be readable from the package dir: %v", err)
	}
	text := string(raw)
	directives := apacheDirectives(t, text)

	clearEnv(t)
	t.Setenv("CROWDSEC_API_KEY", "k")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	challengeEndpoint := cfg.captchaPath + altchaChallengePath

	t.Run("the paths it names are the ones the daemon uses", func(t *testing.T) {
		for what, want := range map[string]string{
			"readiness file":     cfg.captchaReadyFile,
			"pass map":           cfg.captchaPassFile,
			"ban map (txt)":      cfg.outputFile,
			"ban map (dbm)":      cfg.dbmFile,
			"challenge endpoint": challengeEndpoint,
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: the config never mentions %q, so it has drifted from the daemon", what, want)
			}
		}
	})

	// The exemption is the line three rounds of fixes kept landing on. Rather than
	// assert its spelling, pull every prefix exemption out and check what it actually
	// MATCHES - so a fourth way of spelling it loosely fails here too.
	t.Run("every challenge-path exemption is anchored at a segment boundary", func(t *testing.T) {
		exempt := regexp.MustCompile(`RewriteCond %\{REQUEST_URI\} !\^(\S+)`)
		checked := 0
		for _, d := range directives {
			m := exempt.FindStringSubmatch(d)
			if m == nil {
				continue
			}
			re, err := regexp.Compile("^" + m[1])
			if err != nil {
				t.Errorf("exemption %q is not a valid regex: %v", m[1], err)
				continue
			}
			// Only prefix exemptions are in scope. A cond that does not exempt the
			// bare prefix is doing something else - the whitelist rule's
			// !^<path>/altcha-challenge$ narrows rather than exempts.
			if !re.MatchString(cfg.captchaPath) {
				continue
			}
			checked++
			for _, uri := range []string{cfg.captchaPath, cfg.captchaPath + "/", challengeEndpoint} {
				if !re.MatchString(uri) {
					t.Errorf("exemption %q fails to exempt %q, which ProxyPass does answer", m[1], uri)
				}
			}
			// These skip the rules AND miss the proxy, landing on the customer's app.
			for _, uri := range []string{cfg.captchaPath + "XYZ", cfg.captchaPath + ".php", cfg.captchaPath + "-evil"} {
				if re.MatchString(uri) {
					t.Errorf("exemption %q also exempts %q, which ProxyPass does NOT answer", m[1], uri)
				}
			}
		}
		if checked == 0 {
			t.Fatal("no challenge-path prefix exemption found at all - has the rule shape changed?")
		}
	})

	// Same class, and the directive the anchoring lesson was never applied to: a
	// plain <Location> is a string prefix, so it would disable ModSecurity for
	// /crowdsec-verifyXYZ as well, for any client at all.
	t.Run("the WAF exemption is a LocationMatch, not a bare Location", func(t *testing.T) {
		for _, d := range directives {
			if strings.HasPrefix(d, "<Location ") {
				t.Errorf("bare %q disables the WAF beyond what ProxyPass answers; use <LocationMatch> with an anchored regex", d)
			}
		}
		loc := regexp.MustCompile(`<LocationMatch\s+"([^"]+)"`).FindStringSubmatch(strings.Join(directives, "\n"))
		if loc == nil {
			t.Fatal("no <LocationMatch> found - the WAF exemption should be one")
		}
		re, err := regexp.Compile(loc[1])
		if err != nil {
			t.Fatalf("LocationMatch %q is not a valid regex: %v", loc[1], err)
		}
		if !re.MatchString(cfg.captchaPath) || !re.MatchString(challengeEndpoint) {
			t.Errorf("LocationMatch %q does not cover the challenge path itself", loc[1])
		}
		if re.MatchString(cfg.captchaPath + "XYZ") {
			t.Errorf("LocationMatch %q also switches the WAF off for %q", loc[1], cfg.captchaPath+"XYZ")
		}
	})

	// A banned client has no business on the mint endpoint - it is the one thing an
	// unauthenticated caller can make the daemon spend real CPU on. Documentation has
	// re-granted that exemption twice, so the shipped rules assert it instead of
	// describing it.
	//
	// Matched by BEHAVIOUR, not by spelling. A substring test for "!^" + captchaPath
	// is what the first version of this did, and it cannot see the one form the defect
	// has actually taken: folded into an alternation as
	// !^/crowdsec-(verify(/|$)|assets/), where the character after the prefix is "(".
	// One commit before this test existed, the file's own optional extra 5 instructed
	// operators to put exactly that cond on the block rule. Compiling each exemption
	// and asking whether it matches the challenge path catches the literal, the
	// alternation, and any spelling nobody has thought of yet.
	//
	// Covers the two replacement block rules in optional extra 4. It does NOT cover
	// extras 1 and 3: both are quoted with no RewriteCond above them, so their groups
	// are empty and onBanMap is false - the flag spelling is not what excludes them.
	t.Run("no ban rule exempts the challenge path", func(t *testing.T) {
		exempt := regexp.MustCompile(`RewriteCond %\{REQUEST_URI\} !\^(\S+)`)
		var conds []string
		bans := 0
		for _, d := range directives {
			if strings.HasPrefix(d, "RewriteCond") {
				conds = append(conds, d)
				continue
			}
			if !strings.HasPrefix(d, "RewriteRule") {
				conds = nil
				continue
			}
			group := strings.Join(conds, "\n")
			// A ban rule refuses outright on a ban-ish map. "[F" rather than "[F]" so a
			// flag-decorated variant - [F,E=CROWDSEC_BLOCK:1] - is still recognised as a
			// refusal.
			//
			// Deliberately NOT filtered on whether the rule also consults the captcha
			// maps. That was this test's previous shape and it was an escape hatch:
			// pasting `${solved:...} !=1` onto the block rule stopped it counting as a
			// ban rule at all, so the exemption check below never ran on it and the suite
			// stayed green. That cond is the literal spelling of "a solved captcha clears
			// a ban", which is what the block rule's own comment forbids - so it belongs
			// in an assertion, not in the filter deciding what gets asserted on. The 403
			// refuse rule stays excluded on its own merits: it consults no ban map.
			refuses := strings.Contains(d, "[F")
			onBanMap := strings.Contains(group, "${crowdsec:") || strings.Contains(group, "${local_deny:")
			if refuses && onBanMap {
				bans++
				for _, m := range []string{"${solved:", "${captcha:"} {
					if strings.Contains(group, m) {
						t.Errorf("a ban rule consults %s, so solving a captcha would clear a ban:\n%s\n%s", m, group, d)
					}
				}
				for _, m := range exempt.FindAllStringSubmatch(group, -1) {
					re, err := regexp.Compile("^" + m[1])
					if err != nil {
						t.Errorf("ban rule carries an exemption that is not a valid regex (%q): %v", m[1], err)
						continue
					}
					if re.MatchString(cfg.captchaPath) {
						t.Errorf("a ban rule exemption %q matches %s, which reopens the mint path to banned clients:\n%s\n%s",
							m[1], cfg.captchaPath, group, d)
					}
				}
			}
			conds = nil
		}
		if bans == 0 {
			t.Fatal("no ban rule recognised - has the rule shape changed?")
		}
	})
}
