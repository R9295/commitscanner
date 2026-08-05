package report

import (
	"bytes"
	"strings"
	"testing"

	"gitsecscan/internal/scan"
)

func TestSimple(t *testing.T) {
	findings := []scan.Finding{
		{
			Hash:       "a68f75ec78bab93e551637f4799acc7b539f4f1a",
			Subject:    "prevent overflow on conversion",
			Message:    "prevent overflow on conversion\n\nA large value wrapped and skipped the bounds check.",
			Categories: []string{"memory-safety", "dos"},
		},
		{
			Hash:    "0000000000000000000000000000000000000001",
			Subject: "reject malformed frames",
			Message: "reject malformed frames\nCo-authored-by: Someone <a@b.c>\nSigned-off-by: Someone <a@b.c>",
		},
	}

	var buf bytes.Buffer
	if err := Simple(&buf, findings, Summary{}); err != nil {
		t.Fatalf("Simple: %v", err)
	}

	want := "a68f75ec78bab93e551637f4799acc7b539f4f1a,memory-safety\n" +
		"prevent overflow on conversion\n\nA large value wrapped and skipped the bounds check.\n\n" +
		"0000000000000000000000000000000000000001,unclassified\n" +
		"reject malformed frames\n\n"
	if got := buf.String(); got != want {
		t.Errorf("Simple output:\n%q\nwant:\n%q", got, want)
	}
}

func TestSimpleEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Simple(&buf, nil, Summary{}); err != nil {
		t.Fatalf("Simple: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("no findings should produce no output, got %q", buf.String())
	}
}

func TestThreatFlagsHarnessOnlyFixes(t *testing.T) {
	f := scan.Finding{
		Hash:       "abc",
		Subject:    "fix panic in fuzz test",
		Message:    "fix panic in fuzz test",
		Categories: []string{"dos"},
		Tier:       scan.TierMedium,
		Hits:       []scan.Hit{{RuleID: scan.RuleTestOnly, Weight: -8}},
	}
	var buf bytes.Buffer
	if err := Threat(&buf, []scan.Finding{f}, Summary{Repo: "r", Revision: "HEAD"}); err != nil {
		t.Fatalf("Threat: %v", err)
	}
	if !strings.Contains(buf.String(), "never shipped") {
		t.Errorf("harness-only fix was not flagged:\n%s", buf.String())
	}
}
