package rules

import "testing"

func TestRuleIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Default() {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %q", r.ID)
		}
		seen[r.ID] = true
		if r.Pattern == nil {
			t.Errorf("rule %q has no pattern", r.ID)
		}
		if r.Desc == "" {
			t.Errorf("rule %q has no description", r.ID)
		}
	}
}

func TestByScope(t *testing.T) {
	all := Default()
	total := 0
	for _, s := range []Scope{ScopeMessage, ScopeAdded, ScopeRemoved, ScopePath} {
		got := ByScope(all, s)
		total += len(got)
		for _, r := range got {
			if r.Scope != s {
				t.Errorf("rule %q in scope %q bucket", r.ID, s)
			}
		}
	}
	if total != len(all) {
		t.Errorf("scopes cover %d rules, want %d", total, len(all))
	}
}

// fires reports whether the named rule matches text.
func fires(t *testing.T, id, text string) bool {
	t.Helper()
	for _, r := range Default() {
		if r.ID == id {
			return r.Pattern.MatchString(text)
		}
	}
	t.Fatalf("no rule named %q", id)
	return false
}

func TestMessageRulesMatch(t *testing.T) {
	cases := []struct {
		rule string
		text string
		want bool
	}{
		{"advisory-id", "bump deps for RUSTSEC-2024-0003", true},
		{"advisory-id", "bump deps to latest", false},
		{"security-advisory", "upgrade h2 due to security advisory", true},
		{"security-labeled-update", "chore(deps): [security] bump lodash", true},
		{"security-explicit", "security fix: clamp reader length", true},
		{"security-explicit", "raw indexing opens attack vectors", true},
		{"external-security-report", "https://hackerone.com/reports/991106", true},
		{"external-security-report", "https://github.com/org/repo/security/dependabot/349", true},
		{"external-security-report", "ordinary GitHub pull request", false},
		{"denial-of-service", "potential DDoS against validators", true},
		{"denial-of-service", "fix deploy command in transaction-dos", false},
		{"memory-overflow", "prevent u64 overflow in fee calculation", true},
		{"memory-overflow", "handle balance underflows", true},
		{"out-of-bounds", "fix index out of range in header parser", true},
		{"out-of-bounds", "add index to the readme", false},
		{"use-after-free", "fix use-after-free in buffer pool", true},
		{"undefined-behaviour", "fix unsoundness in the arena allocator", true},
		{"panic", "avoid panic on truncated message", true},
		{"denial-of-service", "prevent DoS vector in the gossip handler", true},
		{"resource-exhaustion", "cap unbounded allocation from untrusted length", true},
		{"hang", "fix infinite loop when peer sends zero-length chunk", true},
		{"hostile-input", "handle malformed payload without aborting", true},
		{"hostile-input", "packets arrive from an untrusted source", true},
		{"hostile-input", "do not panic on malformed gossip votes", true},
		{"hostile-input", "handle payload", false},
		{"attacker-context", "add protection against attackers", true},
		{"fuzz-crash", "fix crash found by the fuzzer", true},
		{"fuzz-crash", "add fuzz targets for the codec", false},
		{"fuzz-mention", "add fuzz targets for the codec", true},
		{"malleability", "reject non-canonical varint encodings", true},
		{"malleability", "harden against second pre-image attacks", true},
		{"crypto-side-channel", "use constant-time comparison for MACs", true},
		{"crypto-key-handling", "zeroize key material on drop", true},
		{"crypto-proof-bounds", "forbid 0-bit range proof verification", true},
		{"authz", "fix authorization bypass in the admin route", true},
		{"privilege-validation", "add missing owner check", true},
		{"privilege-validation", "transaction not signed by authority", true},
		{"privilege-validation", "improve missing default signer error", false},
		{"race", "fix data race on the shared counter", true},
		{"injection", "fix path traversal in the archive extractor", true},
		{"neg-docs", "docs: explain the codec", true},
		{"neg-revert", "Revert \"fix panic in parser\"", true},
		{"neg-feature", "add support for BLS12-381", true},
		{"fix-shaped", "runtime: fixes overflow handling", true},
		{"fix-shaped", "cleanly handle balance underflow", true},
		{"fix-shaped", "strictly sanitize snapshot contents", true},
		{"fix-shaped", "bank: don't panic on malformed state", true},
		{"fix-shaped", "epoch calculation resulting in duration underflow", true},
		{"neg-mechanical-subject", "clippy: fix format strings", true},
		{"neg-mechanical-subject", "resolve conflict", true},
		{"neg-mechanical-subject", "reject proofs with merkle root conflicts", false},
		{"neg-maintenance-subject", "CI: fix build", true},
		{"neg-maintenance-subject", "fix overflow and add regression tests", false},
		{"neg-advisory-suppression", "Add exception for RUSTSEC-2023-0001", true},
		{"neg-advisory-suppression", "Remove ignore for RUSTSEC-2023-0001", false},
	}
	for _, tc := range cases {
		if got := fires(t, tc.rule, tc.text); got != tc.want {
			t.Errorf("rule %s on %q = %v, want %v", tc.rule, tc.text, got, tc.want)
		}
	}
}

func TestSubjectOnlyNegativeRulesIgnoreFixBody(t *testing.T) {
	text := "Fix panic when decoding a packet\nRefactor the helper and add tests for the fix"
	if fires(t, "neg-refactor", text) {
		t.Error("neg-refactor should only classify the subject")
	}
	if fires(t, "neg-test-only", text) {
		t.Error("neg-test-only should only classify the subject")
	}
}

func TestDiffRulesMatch(t *testing.T) {
	cases := []struct {
		rule string
		text string
		want bool
	}{
		{"add-checked-arithmetic", "let n = a.checked_add(b).ok_or(Error::Overflow)?;", true},
		{"add-checked-arithmetic", "let n = a + b;", false},
		{"add-rejection", "return Err(Error::InvalidLength(len));", true},
		{"add-safe-indexing", "let item = values.get(index)?;", true},
		{"add-constant-time", "if a.ct_eq(&b).into() {", true},
		{"remove-panic", "let value = map.get(k).unwrap();", true},
		{"remove-unsafe", "unsafe { ptr::copy(src, dst, n) }", true},
		{"add-ordering-check", "// keys must ascend", true},
	}
	for _, tc := range cases {
		if got := fires(t, tc.rule, tc.text); got != tc.want {
			t.Errorf("rule %s on %q = %v, want %v", tc.rule, tc.text, got, tc.want)
		}
	}
}

func TestPathRulesMatch(t *testing.T) {
	if !fires(t, "path-parsing", "codec/src/types/net.rs") {
		t.Error("path-parsing should match a codec path")
	}
	if !fires(t, "path-crypto", "cryptography/src/bls12381/mod.rs") {
		t.Error("path-crypto should match a crypto path")
	}
	if fires(t, "path-crypto", "docs/index.md") {
		t.Error("path-crypto should not match a docs path")
	}
}
