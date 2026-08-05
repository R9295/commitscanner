package gitlog

import (
	"context"
	"strings"
	"testing"
)

func TestSplitRecords(t *testing.T) {
	in := "\x1eone\x1etwo\x1ethree"
	var got []string
	err := splitRecords(strings.NewReader(in), 1024, func(rec []byte, truncated bool) error {
		if truncated {
			t.Fatalf("unexpected truncation of %q", rec)
		}
		got = append(got, string(rec))
		return nil
	})
	if err != nil {
		t.Fatalf("splitRecords: %v", err)
	}
	want := []string{"one", "two", "three"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("record %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitRecordsTruncates(t *testing.T) {
	in := "\x1e" + strings.Repeat("a", 5000) + "\x1eshort"
	var got []string
	var truncatedFlags []bool
	err := splitRecords(strings.NewReader(in), 100, func(rec []byte, truncated bool) error {
		got = append(got, string(rec))
		truncatedFlags = append(truncatedFlags, truncated)
		return nil
	})
	if err != nil {
		t.Fatalf("splitRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if len(got[0]) != 100 || !truncatedFlags[0] {
		t.Errorf("first record: len=%d truncated=%v, want len=100 truncated=true", len(got[0]), truncatedFlags[0])
	}
	if got[1] != "short" || truncatedFlags[1] {
		t.Errorf("second record = %q truncated=%v, want %q false", got[1], truncatedFlags[1], "short")
	}
}

func TestParseRecord(t *testing.T) {
	rec := strings.Join([]string{
		"abc123def456789",
		"Ada Lovelace",
		"2024-05-06T10:00:00+00:00",
		"fix: reject oversized frames",
		"Found by the fuzzer.\n",
	}, fieldSep) + fieldSep + "\ndiff --git a/x.rs b/x.rs\n"

	c, ok := parseRecord(rec, false)
	if !ok {
		t.Fatal("parseRecord returned !ok")
	}
	if c.Hash != "abc123def456789" {
		t.Errorf("hash = %q", c.Hash)
	}
	if c.Short() != "abc123def456" {
		t.Errorf("short = %q", c.Short())
	}
	if c.Author != "Ada Lovelace" {
		t.Errorf("author = %q", c.Author)
	}
	if c.Date.Year() != 2024 || c.Date.Month() != 5 {
		t.Errorf("date = %v", c.Date)
	}
	if c.Subject != "fix: reject oversized frames" {
		t.Errorf("subject = %q", c.Subject)
	}
	if c.Body != "Found by the fuzzer." {
		t.Errorf("body = %q", c.Body)
	}
	if !strings.HasPrefix(c.Patch, "diff --git") {
		t.Errorf("patch = %q", c.Patch)
	}
	if want := "fix: reject oversized frames\nFound by the fuzzer."; c.Message() != want {
		t.Errorf("message = %q, want %q", c.Message(), want)
	}
}

func TestParseRecordRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "   \n", "not-a-record"} {
		if _, ok := parseRecord(in, false); ok {
			t.Errorf("parseRecord(%q) = ok, want !ok", in)
		}
	}
}

func TestArgs(t *testing.T) {
	got := strings.Join(Args(Options{
		Repo: "/tmp/repo", Rev: "main", Mode: ModeFull, Max: 10,
		Excludes: []string{"*.lock"},
	}), " ")
	for _, want := range []string{"-C /tmp/repo", "main", "--no-merges", "-n10", "--patch", ":(exclude)*.lock"} {
		if !strings.Contains(got, want) {
			t.Errorf("args %q missing %q", got, want)
		}
	}

	// Excludes only trim diff noise, so they are dropped when there is no diff.
	none := strings.Join(Args(Options{Repo: ".", Mode: ModeNone, Excludes: []string{"*.lock"}}), " ")
	if strings.Contains(none, "exclude") {
		t.Errorf("ModeNone args should not carry excludes: %q", none)
	}

	// Paths restrict which commits are considered, so they apply in every mode.
	scoped := strings.Join(Args(Options{Repo: ".", Mode: ModeNone, Paths: []string{"codec", "p2p/src"}}), " ")
	if !strings.Contains(scoped, "-- codec p2p/src") {
		t.Errorf("paths missing from ModeNone args: %q", scoped)
	}

	// Merge commits are included unless explicitly excluded.
	merged := strings.Join(Args(Options{Repo: ".", Mode: ModeNone, IncludeMerges: true}), " ")
	if strings.Contains(merged, "--no-merges") {
		t.Errorf("IncludeMerges should drop --no-merges: %q", merged)
	}
}

func TestParseMode(t *testing.T) {
	for _, s := range []string{"full", "names", "none"} {
		if _, err := ParseMode(s); err != nil {
			t.Errorf("ParseMode(%q) failed: %v", s, err)
		}
	}
	if _, err := ParseMode("patch"); err == nil {
		t.Error("ParseMode(\"patch\") should fail")
	}
}

func TestInspectRejectsNonRepo(t *testing.T) {
	if _, _, err := Inspect(context.Background(), t.TempDir()); err == nil {
		t.Error("Inspect on a non-repository should fail")
	}
}
