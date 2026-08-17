// Command gitsecscan scans the git history of a repository for commits that
// look like they fixed a security bug.
//
// It reads commit messages and diffs, scores them against a set of weighted
// heuristics, and reports the commits that clear a threshold along with the
// evidence behind each score. The output is a starting point for review, not a
// verdict: confirm every finding with `git show`.
//
// Usage:
//
//	gitsecscan [flags] [repo]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"gitsecscan/internal/gitlog"
	"gitsecscan/internal/report"
	"gitsecscan/internal/rules"
	"gitsecscan/internal/scan"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gitsecscan: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	repo          string
	rev           string
	since         string
	until         string
	author        string
	max           int
	top           int
	minScore      int
	highScore     int
	mediumScore   int
	diffMode      string
	format        string
	simple        bool
	out           string
	workers       int
	includeMerges bool
	subdir        string
	paths         string
	excludes      string
	maxRecord     int
	listRules     bool
	quiet         bool
}

func run() error {
	var opts options
	flag.StringVar(&opts.repo, "repo", ".", "repository to scan")
	flag.StringVar(&opts.rev, "rev", "HEAD", "revision or range to scan (e.g. HEAD, v1.0..HEAD)")
	flag.StringVar(&opts.since, "since", "", "only commits after this date (git date format)")
	flag.StringVar(&opts.until, "until", "", "only commits before this date")
	flag.StringVar(&opts.author, "author", "", "only commits from authors matching this pattern")
	flag.IntVar(&opts.max, "max", 0, "stop after this many commits (0 = all)")
	flag.IntVar(&opts.top, "top", 0, "report at most this many findings (0 = all)")
	flag.IntVar(&opts.minScore, "min-score", 0, "reporting threshold (0 = use default)")
	flag.IntVar(&opts.highScore, "high-score", 0, "score at or above which a finding is HIGH")
	flag.IntVar(&opts.mediumScore, "medium-score", 0, "score at or above which a finding is MEDIUM")
	flag.StringVar(&opts.diffMode, "diff", "full", "how much diff to read: full, names, or none")
	flag.StringVar(&opts.format, "format", "text", "output format: text, json, md, threat, or simple")
	flag.BoolVar(&opts.simple, "simple", false, "shorthand for -format=simple: hash,category then the commit message")
	flag.StringVar(&opts.out, "out", "", "write the report to this file instead of stdout")
	flag.IntVar(&opts.workers, "workers", runtime.NumCPU(), "number of scoring workers")
	flag.BoolVar(&opts.includeMerges, "merges", true, "include merge commits (-merges=false to skip them)")
	flag.StringVar(&opts.subdir, "subdir", "", "comma-separated subdirectories to scan (e.g. codec,p2p/src)")
	flag.StringVar(&opts.paths, "paths", "", "comma-separated pathspecs to limit the scan to")
	flag.StringVar(&opts.excludes, "exclude", strings.Join(gitlog.DefaultExcludes, ","),
		"comma-separated pathspecs to exclude from diffs")
	flag.IntVar(&opts.maxRecord, "max-commit-bytes", gitlog.DefaultMaxRecordBytes,
		"per-commit cap on diff bytes read")
	flag.BoolVar(&opts.listRules, "list-rules", false, "print the rule set and exit")
	flag.BoolVar(&opts.quiet, "quiet", false, "suppress progress output")
	flag.Usage = usage
	flag.Parse()

	if opts.listRules {
		return listRules(os.Stdout)
	}
	if flag.NArg() > 0 {
		opts.repo = flag.Arg(0)
	}
	if opts.simple {
		opts.format = "simple"
	}

	mode, err := gitlog.ParseMode(opts.diffMode)
	if err != nil {
		return err
	}
	if err := checkRepo(opts.repo); err != nil {
		return err
	}

	cfg := scan.DefaultConfig()
	if opts.minScore > 0 {
		cfg.MinScore = opts.minScore
	}
	if opts.highScore > 0 {
		cfg.HighScore = opts.highScore
	}
	if opts.mediumScore > 0 {
		cfg.MediumScore = opts.mediumScore
	}
	scanner := scan.New(cfg)

	paths := append(splitList(opts.paths), subdirPathspecs(opts.subdir)...)
	walkOpts := gitlog.Options{
		Repo:           opts.repo,
		Rev:            opts.rev,
		Since:          opts.since,
		Until:          opts.until,
		Author:         opts.author,
		Max:            opts.max,
		IncludeMerges:  opts.includeMerges,
		Mode:           mode,
		Excludes:       splitList(opts.excludes),
		Paths:          paths,
		MaxRecordBytes: opts.maxRecord,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A shallow clone holds only the commits that were fetched, so a scan of
	// one finds nothing and says nothing. Warn before doing the work.
	shallow, commits, err := gitlog.Inspect(ctx, opts.repo)
	if err != nil {
		return err
	}
	if shallow && !opts.quiet {
		fmt.Fprintf(os.Stderr,
			"warning: %s is a shallow clone (%d commit(s) reachable); there is almost no history to scan.\n"+
				"         run `git -C %s fetch --unshallow` first, or scan a full clone.\n",
			opts.repo, commits, opts.repo)
	}

	start := time.Now()
	findings, scanned, err := scanHistory(ctx, scanner, walkOpts, opts)
	if err != nil {
		return err
	}

	// Formats like `simple` print findings and nothing else, so an empty result
	// is indistinguishable from a broken invocation. Say so on stderr, which
	// keeps stdout clean for piping.
	if !opts.quiet && len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "no findings: scanned %d commit(s), none scored %d or above\n",
			scanned, cfg.MinScore)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Score != findings[j].Score {
			return findings[i].Score > findings[j].Score
		}
		return findings[i].Date.After(findings[j].Date)
	})

	sum := report.Build(report.Summary{
		Repo:     opts.repo,
		Revision: opts.rev,
		Mode:     string(mode),
		Paths:    paths,
		Scanned:  scanned,
		MinScore: cfg.MinScore,
		Elapsed:  time.Since(start).Round(time.Millisecond).String(),
	}, findings)

	if opts.top > 0 && len(findings) > opts.top {
		findings = findings[:opts.top]
	}

	w := os.Stdout
	if opts.out != "" {
		f, err := os.Create(opts.out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}

	switch opts.format {
	case "text":
		return report.Text(w, findings, sum)
	case "json":
		return report.JSON(w, findings, sum)
	case "md", "markdown":
		return report.Markdown(w, findings, sum)
	case "threat":
		return report.Threat(w, findings, sum)
	case "simple":
		return report.Simple(w, findings, sum)
	default:
		return fmt.Errorf("unknown format %q (want text, json, md, threat, or simple)", opts.format)
	}
}

// scanHistory streams commits from git and scores them on a pool of workers.
// Parsing is sequential because it comes off a single git pipe, scoring is not.
func scanHistory(ctx context.Context, scanner *scan.Scanner, walkOpts gitlog.Options, opts options) ([]scan.Finding, int, error) {
	workers := opts.workers
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan gitlog.Commit, workers*4)
	results := make(chan scan.Finding, workers*4)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				if f, ok := scanner.Score(c, walkOpts.Mode); ok {
					results <- f
				}
			}
		}()
	}

	var (
		scanned int
		walkErr error
	)
	go func() {
		defer close(jobs)
		seen := make(map[string]struct{})
		emit := func(c gitlog.Commit) error {
			if _, ok := seen[c.Hash]; ok {
				return nil
			}
			seen[c.Hash] = struct{}{}
			scanned++
			if !opts.quiet && scanned%500 == 0 {
				fmt.Fprintf(os.Stderr, "\rscanned %d commits...", scanned)
			}
			select {
			case jobs <- c:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		primary := walkOpts
		// Git implements excludes as history pathspecs, so a commit that only
		// changes an excluded lockfile disappears from this diff walk entirely.
		// With -max, that also changes which commits the limit selects; retain
		// exact -max semantics by accepting noisy diffs for that bounded scan.
		if primary.Max > 0 {
			primary.Excludes = nil
		}
		walkErr = gitlog.Walk(ctx, primary, emit)
		if walkErr != nil || walkOpts.Mode == gitlog.ModeNone || len(walkOpts.Excludes) == 0 || walkOpts.Max > 0 {
			return
		}

		// Recover message-only commits hidden by the primary walk's exclude
		// pathspecs. Scoring them without a patch preserves security advisories
		// that only update lockfiles while still avoiding enormous lock diffs.
		metadata := walkOpts
		metadata.Mode = gitlog.ModeNone
		metadata.Excludes = nil
		walkErr = gitlog.Walk(ctx, metadata, emit)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []scan.Finding
	for f := range results {
		findings = append(findings, f)
	}
	if !opts.quiet && scanned >= 500 {
		fmt.Fprintf(os.Stderr, "\r\033[K")
	}
	if walkErr != nil && ctx.Err() == nil {
		return nil, scanned, walkErr
	}
	return findings, scanned, nil
}

func checkRepo(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("repo %q: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("repo %q is not a directory", path)
	}
	return nil
}

// subdirPathspecs turns a comma-separated list of directories into git
// pathspecs. A bare directory name already matches everything beneath it, so
// only trailing slashes need trimming.
func subdirPathspecs(s string) []string {
	dirs := splitList(s)
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d = strings.TrimRight(d, "/"); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func listRules(w *os.File) error {
	all := rules.Default()
	fmt.Fprintf(w, "%-26s %-9s %-16s %6s  %s\n", "RULE", "SCOPE", "CATEGORY", "WEIGHT", "DESCRIPTION")
	for _, r := range all {
		fmt.Fprintf(w, "%-26s %-9s %-16s %+6d  %s\n", r.ID, r.Scope, r.Category, r.Weight, r.Desc)
	}
	fmt.Fprintf(w, "\n%d rules\n", len(all))
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `gitsecscan scans git history for commits that fixed security bugs.

usage: gitsecscan [flags] [repo]

examples:
  gitsecscan /path/to/repo
  gitsecscan -subdir=codec,p2p/src /path/to/repo
  gitsecscan -format=threat -top=0 -out=bugs.md /path/to/repo
  gitsecscan --simple -top=0 /path/to/repo
  gitsecscan -since=2024-01-01 -format=md -out=report.md /path/to/repo
  gitsecscan -diff=none -min-score=8 -top=0 -merges=false /path/to/repo
  gitsecscan -list-rules

flags:
`)
	flag.PrintDefaults()
}
