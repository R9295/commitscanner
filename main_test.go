package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gitsecscan/internal/gitlog"
	"gitsecscan/internal/scan"
)

func TestSubdirPathspecs(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"codec", "codec"},
		{"codec,p2p/src", "codec p2p/src"},
		{"codec/, storage/src/mmr/ ,", "codec storage/src/mmr"},
	}
	for _, tc := range cases {
		got := strings.Join(subdirPathspecs(tc.in), " ")
		if got != tc.want {
			t.Errorf("subdirPathspecs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSplitList(t *testing.T) {
	if got := splitList(" a , ,b "); strings.Join(got, "|") != "a|b" {
		t.Errorf("splitList = %v", got)
	}
	if got := splitList("   "); got != nil {
		t.Errorf("splitList(blank) = %v, want nil", got)
	}
}

func TestScanHistoryRecoversExcludedOnlyCommitMessages(t *testing.T) {
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")
	runGit(t, repo, "config", "user.name", "Test Author")
	runGit(t, repo, "config", "user.email", "test@example.com")

	if err := os.WriteFile(filepath.Join(repo, "code.rs"), []byte("fn main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", "code.rs")
	runGit(t, repo, "commit", "-q", "-m", "initial source")

	if err := os.WriteFile(filepath.Join(repo, "Cargo.lock"), []byte("security-update = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", "Cargo.lock")
	runGit(t, repo, "commit", "-q", "-m", "Fix security vulnerability in dependency")

	walkOpts := gitlog.Options{
		Repo:          repo,
		Rev:           "HEAD",
		IncludeMerges: true,
		Mode:          gitlog.ModeFull,
		Excludes:      []string{"*.lock"},
	}
	findings, scanned, err := scanHistory(context.Background(), scan.New(scan.DefaultConfig()), walkOpts, options{workers: 1, quiet: true})
	if err != nil {
		t.Fatalf("scanHistory: %v", err)
	}
	if scanned != 2 {
		t.Fatalf("scanned = %d, want both commits", scanned)
	}
	if len(findings) != 1 || findings[0].Subject != "Fix security vulnerability in dependency" {
		t.Fatalf("findings = %+v, want excluded-only security commit", findings)
	}
	if findings[0].FileCount != 0 {
		t.Errorf("excluded-only commit retained diff files: %+v", findings[0].Files)
	}
}

func runGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
}
