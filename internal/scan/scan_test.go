package scan

import (
	"strings"
	"testing"

	"gitsecscan/internal/gitlog"
)

const securityPatch = `diff --git a/codec/src/types/vec.rs b/codec/src/types/vec.rs
index 1111111..2222222 100644
--- a/codec/src/types/vec.rs
+++ b/codec/src/types/vec.rs
@@ -60,7 +60,10 @@ impl<T: Read> Read for Vec<T> {
     fn read_cfg(buf: &mut impl Buf, (range, cfg): &Self::Cfg) -> Result<Self, Error> {
         let len = usize::read_cfg(buf, range)?;
-        let mut out = Vec::with_capacity(len);
+        if len > buf.remaining() {
+            return Err(Error::InvalidLength(len));
+        }
+        let mut out = Vec::with_capacity(len.min(buf.remaining()));
         for _ in 0..len {
             out.push(T::read_cfg(buf, cfg)?);
         }
`

func TestScoreSecurityFix(t *testing.T) {
	s := New(DefaultConfig())
	c := gitlog.Commit{
		Hash:    "0123456789abcdef0123456789abcdef01234567",
		Author:  "Ada",
		Subject: "fix: reject malformed length prefix that caused unbounded allocation",
		Body:    "A malicious peer could send a huge length and trigger an OOM. Found by the fuzzer.",
		Patch:   securityPatch,
	}

	f, ok := s.Score(c, gitlog.ModeFull)
	if !ok {
		t.Fatalf("security fix was not reported (score %d)", f.Score)
	}
	if f.Tier != TierHigh {
		t.Errorf("tier = %s (score %d), want HIGH", f.Tier, f.Score)
	}
	if len(f.Categories) == 0 {
		t.Fatal("no categories assigned")
	}

	want := map[string]bool{"hostile-input": false, "resource-exhaustion": false, "fuzz-crash": false, "add-rejection": false}
	for _, h := range f.Hits {
		if _, ok := want[h.RuleID]; ok {
			want[h.RuleID] = true
		}
	}
	for id, fired := range want {
		if !fired {
			t.Errorf("expected rule %q to fire", id)
		}
	}

	// Diff evidence should point at a real file and line.
	var found bool
	for _, h := range f.Hits {
		if h.RuleID != "add-rejection" {
			continue
		}
		for _, e := range h.Evidence {
			if strings.HasPrefix(e, "codec/src/types/vec.rs:") && strings.Contains(e, "return Err") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("add-rejection evidence missing file:line, hits = %+v", f.Hits)
	}
}

func TestScoreIgnoresRoutineCommits(t *testing.T) {
	s := New(DefaultConfig())
	for _, c := range []gitlog.Commit{
		{Hash: "a", Subject: "docs: describe the codec module"},
		{Hash: "b", Subject: "add support for BLS12-381 aggregation"},
		{Hash: "c", Subject: "refactor: rename Reader to Decoder"},
		{Hash: "d", Subject: "bump serde to 1.0.200"},
	} {
		if f, ok := s.Score(c, gitlog.ModeNone); ok {
			t.Errorf("%q reported with score %d", c.Subject, f.Score)
		}
	}
}

func TestTestOnlyChangesArePenalised(t *testing.T) {
	s := New(DefaultConfig())
	c := gitlog.Commit{
		Hash:    "e",
		Subject: "fix panic in fuzz harness on malformed input",
		Patch:   "codec/fuzz/fuzz_targets/codec_roundtrip.rs\ncodec/tests/roundtrip.rs\n",
	}
	f, _ := s.Score(c, gitlog.ModeNames)
	var penalised bool
	for _, h := range f.Hits {
		if h.RuleID == "neg-test-only-paths" {
			penalised = true
		}
	}
	if !penalised {
		t.Errorf("test-only commit was not penalised, hits = %+v", f.Hits)
	}
}

func TestMinScoreIsRespected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinScore = 100
	s := New(cfg)
	c := gitlog.Commit{Hash: "f", Subject: "fix use-after-free in the buffer pool"}
	if _, ok := s.Score(c, gitlog.ModeNone); ok {
		t.Error("finding reported below the configured threshold")
	}
}

func TestPathSignalAloneIsNotAFinding(t *testing.T) {
	s := New(DefaultConfig())
	c := gitlog.Commit{
		Hash:    "g",
		Subject: "tidy imports",
		Patch:   "codec/src/lib.rs\ncryptography/src/lib.rs\n",
	}
	if _, ok := s.Score(c, gitlog.ModeNames); ok {
		t.Error("path signals alone should not produce a finding")
	}
}
