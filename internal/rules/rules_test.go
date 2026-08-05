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
		{"security-explicit", "security fix: clamp reader length", true},
		{"out-of-bounds", "fix index out of range in header parser", true},
		{"out-of-bounds", "add index to the readme", false},
		{"use-after-free", "fix use-after-free in buffer pool", true},
		{"undefined-behaviour", "fix unsoundness in the arena allocator", true},
		{"panic", "avoid panic on truncated message", true},
		{"denial-of-service", "prevent DoS vector in the gossip handler", true},
		{"resource-exhaustion", "cap unbounded allocation from untrusted length", true},
		{"hang", "fix infinite loop when peer sends zero-length chunk", true},
		{"hostile-input", "handle malformed payload without aborting", true},
		{"hostile-input", "handle payload", false},
		{"fuzz-crash", "fix crash found by the fuzzer", true},
		{"fuzz-crash", "add fuzz targets for the codec", false},
		{"fuzz-mention", "add fuzz targets for the codec", true},
		{"malleability", "reject non-canonical varint encodings", true},
		{"crypto-side-channel", "use constant-time comparison for MACs", true},
		{"crypto-key-handling", "zeroize key material on drop", true},
		{"authz", "fix authorization bypass in the admin route", true},
		{"race", "fix data race on the shared counter", true},
		{"injection", "fix path traversal in the archive extractor", true},
		{"neg-docs", "docs: explain the codec", true},
		{"neg-revert", "Revert \"fix panic in parser\"", true},
		{"neg-feature", "add support for BLS12-381", true},
	}
	for _, tc := range cases {
		if got := fires(t, tc.rule, tc.text); got != tc.want {
			t.Errorf("rule %s on %q = %v, want %v", tc.rule, tc.text, got, tc.want)
		}
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
