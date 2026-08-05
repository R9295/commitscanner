// Package report renders findings as text, JSON, or Markdown.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"gitsecscan/internal/scan"
)

// Summary describes a completed scan.
type Summary struct {
	Repo       string         `json:"repo"`
	Revision   string         `json:"revision"`
	Mode       string         `json:"diff_mode"`
	Paths      []string       `json:"paths,omitempty"`
	Scanned    int            `json:"commits_scanned"`
	Reported   int            `json:"commits_reported"`
	MinScore   int            `json:"min_score"`
	Elapsed    string         `json:"elapsed"`
	ByTier     map[string]int `json:"by_tier"`
	ByCategory map[string]int `json:"by_category"`
	FirstDate  time.Time      `json:"first_commit_date,omitempty"`
	LastDate   time.Time      `json:"last_commit_date,omitempty"`
}

// Build computes summary counters from the findings.
func Build(base Summary, findings []scan.Finding) Summary {
	base.Reported = len(findings)
	base.ByTier = map[string]int{}
	base.ByCategory = map[string]int{}
	for _, f := range findings {
		base.ByTier[string(f.Tier)]++
		for _, c := range f.Categories {
			base.ByCategory[c]++
		}
	}
	return base
}

// Text writes a human-readable report.
func Text(w io.Writer, findings []scan.Finding, sum Summary) error {
	fmt.Fprintf(w, "gitsecscan: %s (%s)\n", sum.Repo, sum.Revision)
	if len(sum.Paths) > 0 {
		fmt.Fprintf(w, "paths: %s\n", strings.Join(sum.Paths, ", "))
	}
	fmt.Fprintf(w, "scanned %d commits in %s, %d above score %d\n\n",
		sum.Scanned, sum.Elapsed, sum.Reported, sum.MinScore)

	for i, f := range findings {
		fmt.Fprintf(w, "%s\n", strings.Repeat("-", 78))
		fmt.Fprintf(w, "#%-3d score %-3d %-6s  %s  %s  %s\n",
			i+1, f.Score, f.Tier, f.Short, f.Date.Format("2006-01-02"), f.Author)
		fmt.Fprintf(w, "     %s\n", f.Subject)
		for _, line := range bodyLines(f, 12) {
			fmt.Fprintf(w, "     | %s\n", line)
		}
		if len(f.Categories) > 0 {
			fmt.Fprintf(w, "     categories: %s\n", strings.Join(f.Categories, ", "))
		}
		fmt.Fprintf(w, "     signals:\n")
		for _, h := range f.Hits {
			fmt.Fprintf(w, "       %+d %-24s %-8s %s", h.Weight, h.RuleID, h.Scope, h.Desc)
			if h.Count > 1 {
				fmt.Fprintf(w, " (x%d)", h.Count)
			}
			fmt.Fprintln(w)
			for _, e := range h.Evidence {
				fmt.Fprintf(w, "           %s\n", e)
			}
		}
		if len(f.Files) > 0 {
			fmt.Fprintf(w, "     files: %s\n", strings.Join(f.Files, " "))
		}
		if f.Truncated {
			fmt.Fprintf(w, "     note: diff truncated, signals may be incomplete\n")
		}
		fmt.Fprintf(w, "     git -C %s show %s\n", sum.Repo, f.Short)
	}

	fmt.Fprintf(w, "%s\n", strings.Repeat("=", 78))
	fmt.Fprintf(w, "summary\n")
	writeCounts(w, "  by tier    ", sum.ByTier, []string{"HIGH", "MEDIUM", "LOW"})
	writeCounts(w, "  by category", sum.ByCategory, nil)
	return nil
}

// trailerPrefixes are git message trailers: provenance, not bug description.
var trailerPrefixes = []string{
	"Co-authored-by:", "Signed-off-by:", "Reviewed-by:", "Acked-by:",
	"Tested-by:", "Cc:", "Change-Id:",
}

// cleanMessage strips trailers so the text that reaches a reader (or a model)
// is only the author's description of the change.
func cleanMessage(msg string) string {
	lines := strings.Split(msg, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if isTrailer(line) {
			continue
		}
		kept = append(kept, strings.TrimRight(line, " \t"))
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

func isTrailer(line string) bool {
	trimmed := strings.TrimSpace(line)
	for _, p := range trailerPrefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// bodyLines returns the commit message body (everything after the subject),
// which is where an author usually explains what could go wrong.
func bodyLines(f scan.Finding, max int) []string {
	body := strings.TrimSpace(strings.TrimPrefix(f.Message, f.Subject))
	if body == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, " \t")
		if isTrailer(line) {
			continue
		}
		out = append(out, line)
		if len(out) == max {
			out = append(out, "...")
			break
		}
	}
	return out
}

func writeCounts(w io.Writer, label string, counts map[string]int, order []string) {
	if len(counts) == 0 {
		return
	}
	keys := order
	if keys == nil {
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if counts[keys[i]] != counts[keys[j]] {
				return counts[keys[i]] > counts[keys[j]]
			}
			return keys[i] < keys[j]
		})
	}
	var parts []string
	for _, k := range keys {
		if counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
		}
	}
	fmt.Fprintf(w, "%s: %s\n", label, strings.Join(parts, "  "))
}

// Simple writes the barest useful form: one line of `hash,category`, then the
// commit message, then a blank line. No header, no scores, no evidence.
//
// The category is the highest-weighted one for that commit; a commit can carry
// several, but a single label is what makes the stream easy to group on.
func Simple(w io.Writer, findings []scan.Finding, _ Summary) error {
	for _, f := range findings {
		category := "unclassified"
		if len(f.Categories) > 0 {
			category = f.Categories[0]
		}
		if _, err := fmt.Fprintf(w, "%s,%s\n%s\n\n", f.Hash, category, cleanMessage(f.Message)); err != nil {
			return err
		}
	}
	return nil
}

// Threat writes a corpus of fixed bugs, each described in the words of the
// engineer who fixed it, for use as input to threat modelling.
//
// Rule weights and scores are deliberately de-emphasised here: what matters
// downstream is what broke, where it lived, and how it was reached. The
// commit hash is kept so any claim can be traced back to the diff.
func Threat(w io.Writer, findings []scan.Finding, sum Summary) error {
	fmt.Fprintf(w, "# Fixed bugs with security relevance: %s\n\n", sum.Repo)
	fmt.Fprintf(w, "Extracted from %d commits of git history at revision `%s`", sum.Scanned, sum.Revision)
	if len(sum.Paths) > 0 {
		fmt.Fprintf(w, ", limited to %s", "`"+strings.Join(sum.Paths, "`, `")+"`")
	}
	fmt.Fprintf(w, ".\n%d commits matched. Each entry below is a real defect that shipped and was\n", sum.Reported)
	fmt.Fprintf(w, "later fixed, described by the author. Entries are evidence of failure modes\n")
	fmt.Fprintf(w, "this system actually has; they are not a list of open vulnerabilities.\n\n")
	fmt.Fprintf(w, "Selection is heuristic. Confirm any entry with `git show <hash>` before relying on it.\n\n")

	if len(sum.ByCategory) > 0 {
		fmt.Fprintf(w, "## Bug classes observed\n\n")
		writeMarkdownCounts(w, sum.ByCategory)
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "## Bugs\n\n")
	for i, f := range findings {
		fmt.Fprintf(w, "### %d. %s\n\n", i+1, f.Subject)
		fmt.Fprintf(w, "- commit: `%s` (%s)\n", f.Hash, f.Date.Format("2006-01-02"))
		if len(f.Categories) > 0 {
			fmt.Fprintf(w, "- bug class: %s\n", strings.Join(f.Categories, ", "))
		}
		if len(f.Subsystems) > 0 {
			fmt.Fprintf(w, "- subsystem: %s\n", strings.Join(f.Subsystems, ", "))
		}
		fmt.Fprintf(w, "- confidence: %s (score %d)\n", f.Tier, f.Score)
		if testOnly(f) {
			fmt.Fprintf(w, "- scope: test/fuzz code only, so this defect never shipped\n")
		}
		if len(f.Files) > 0 {
			files := strings.Join(f.Files, ", ")
			if f.FileCount > len(f.Files) {
				files += fmt.Sprintf(", ... (%d files total)", f.FileCount)
			}
			fmt.Fprintf(w, "- files: %s\n", files)
		}

		fmt.Fprintf(w, "\n**What the author said:**\n\n")
		fmt.Fprintf(w, "```\n%s\n```\n", cleanMessage(f.Message))

		if ev := codeEvidence(f); len(ev) > 0 {
			fmt.Fprintf(w, "\n**Change that fixed it:**\n\n")
			for _, e := range ev {
				fmt.Fprintf(w, "- `%s`\n", strings.ReplaceAll(e, "`", "'"))
			}
		}
		fmt.Fprintln(w)
	}
	return nil
}

// testOnly reports whether the fix landed entirely in test or harness code.
func testOnly(f scan.Finding) bool {
	for _, h := range f.Hits {
		if h.RuleID == scan.RuleTestOnly {
			return true
		}
	}
	return false
}

// codeEvidence pulls the diff-level evidence out of a finding, which describes
// the mechanism of the fix rather than the vocabulary of the commit message.
func codeEvidence(f scan.Finding) []string {
	var out []string
	for _, h := range f.Hits {
		if h.Scope != "added" && h.Scope != "removed" {
			continue
		}
		for _, e := range h.Evidence {
			out = append(out, e)
			if len(out) >= 6 {
				return out
			}
		}
	}
	return out
}

func writeMarkdownCounts(w io.Writer, counts map[string]int) {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		fmt.Fprintf(w, "- %s: %d\n", k, counts[k])
	}
}

// JSON writes a machine-readable report.
func JSON(w io.Writer, findings []scan.Finding, sum Summary) error {
	if findings == nil {
		findings = []scan.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Summary  Summary        `json:"summary"`
		Findings []scan.Finding `json:"findings"`
	}{sum, findings})
}

// Markdown writes a report suitable for pasting into an issue or a PR.
func Markdown(w io.Writer, findings []scan.Finding, sum Summary) error {
	fmt.Fprintf(w, "# Security fix scan: `%s`\n\n", sum.Repo)
	fmt.Fprintf(w, "- revision: `%s`\n- commits scanned: %d\n- findings: %d (score >= %d)\n- elapsed: %s\n",
		sum.Revision, sum.Scanned, sum.Reported, sum.MinScore, sum.Elapsed)
	if len(sum.Paths) > 0 {
		fmt.Fprintf(w, "- paths: `%s`\n", strings.Join(sum.Paths, "`, `"))
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "| # | score | tier | commit | date | categories | subject |\n")
	fmt.Fprintf(w, "|---|-------|------|--------|------|------------|---------|\n")
	for i, f := range findings {
		fmt.Fprintf(w, "| %d | %d | %s | `%s` | %s | %s | %s |\n",
			i+1, f.Score, f.Tier, f.Short, f.Date.Format("2006-01-02"),
			strings.Join(f.Categories, ", "), escapePipes(f.Subject))
	}

	fmt.Fprintf(w, "\n## Details\n\n")
	for i, f := range findings {
		fmt.Fprintf(w, "### %d. `%s` — %s\n\n", i+1, f.Short, escapePipes(f.Subject))
		fmt.Fprintf(w, "score %d (%s), %s, %s\n\n", f.Score, f.Tier, f.Date.Format("2006-01-02"), f.Author)
		for _, h := range f.Hits {
			fmt.Fprintf(w, "- `%+d` **%s** (%s) — %s\n", h.Weight, h.RuleID, h.Scope, h.Desc)
			for _, e := range h.Evidence {
				fmt.Fprintf(w, "  - `%s`\n", strings.ReplaceAll(e, "`", "'"))
			}
		}
		if len(f.Files) > 0 {
			fmt.Fprintf(w, "\nFiles: %s\n", "`"+strings.Join(f.Files, "`, `")+"`")
		}
		fmt.Fprintln(w)
	}
	return nil
}

func escapePipes(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
