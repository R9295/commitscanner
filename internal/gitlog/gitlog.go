// Package gitlog streams commits (metadata and, optionally, patches) out of a
// git repository.
//
// Commits are emitted through a callback as they are parsed so that history of
// any size can be scanned without holding it all in memory. Records are read
// from a single `git log` invocation rather than one `git show` per commit,
// which is roughly an order of magnitude faster on large repositories.
package gitlog

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	// recordSep and fieldSep are control characters that do not appear in
	// commit metadata, so they can delimit records without escaping.
	recordSep = 0x1e
	fieldSep  = "\x1f"

	// DefaultMaxRecordBytes bounds how much of a single commit is retained.
	// Oversized records are truncated rather than dropped so that a giant
	// generated-file commit cannot exhaust memory.
	DefaultMaxRecordBytes = 4 << 20
)

// Mode selects how much of each commit's diff is requested from git.
type Mode string

const (
	// ModeFull requests the full patch. Required for diff-based signals.
	ModeFull Mode = "full"
	// ModeNames requests changed file names only.
	ModeNames Mode = "names"
	// ModeNone requests commit metadata only, which is the fastest mode.
	ModeNone Mode = "none"
)

// ParseMode validates a mode name.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeFull, ModeNames, ModeNone:
		return Mode(s), nil
	default:
		return "", fmt.Errorf("unknown diff mode %q (want full, names, or none)", s)
	}
}

// DefaultExcludes are paths whose diffs carry no security signal but are large
// enough to slow a scan down considerably.
var DefaultExcludes = []string{
	"*.lock",
	"go.sum",
	"*.min.js",
	"*.svg",
	"*.png",
	"*.jpg",
	"*.pdf",
	"vendor/**",
	"**/testdata/**",
	"**/fixtures/**",
}

// Options configures a history scan.
type Options struct {
	Repo           string   // repository path
	Rev            string   // revision range (default HEAD)
	Since          string   // only commits after this date
	Until          string   // only commits before this date
	Author         string   // only commits from a matching author
	Max            int      // stop after this many commits (0 = no limit)
	IncludeMerges  bool     // include merge commits (they carry no diff of their own)
	Mode           Mode     // how much diff to request
	Excludes       []string // pathspecs to exclude
	Paths          []string // limit history to these paths
	MaxRecordBytes int      // per-commit cap, defaults to DefaultMaxRecordBytes
}

// Commit is a single commit with the parts of its diff that were requested.
type Commit struct {
	Hash      string
	Author    string
	Date      time.Time
	Subject   string
	Body      string
	Patch     string // patch text (ModeFull) or file list (ModeNames)
	Truncated bool   // the record hit MaxRecordBytes and was cut short
}

// Short returns the abbreviated commit hash.
func (c Commit) Short() string {
	if len(c.Hash) > 12 {
		return c.Hash[:12]
	}
	return c.Hash
}

// Message returns the subject and body joined as they appear in git.
func (c Commit) Message() string {
	if c.Body == "" {
		return c.Subject
	}
	return c.Subject + "\n" + c.Body
}

// Args builds the git command line for the given options. It is exported so
// callers can log exactly what was run.
func Args(opts Options) []string {
	rev := opts.Rev
	if rev == "" {
		rev = "HEAD"
	}
	args := []string{
		"-C", opts.Repo,
		"log",
		rev,
		"--no-color",
		// %x1e starts a record, %x1f separates fields.
		"--format=%x1e%H%x1f%an%x1f%aI%x1f%s%x1f%b%x1f",
	}
	if !opts.IncludeMerges {
		args = append(args, "--no-merges")
	}
	if opts.Since != "" {
		args = append(args, "--since="+opts.Since)
	}
	if opts.Until != "" {
		args = append(args, "--until="+opts.Until)
	}
	if opts.Author != "" {
		args = append(args, "--author="+opts.Author)
	}
	if opts.Max > 0 {
		args = append(args, fmt.Sprintf("-n%d", opts.Max))
	}
	switch opts.Mode {
	case ModeFull:
		args = append(args, "--patch", "--unified=3", "--no-textconv", "--find-renames")
	case ModeNames:
		args = append(args, "--name-only")
	}

	// Pathspecs must come last, after a `--` separator. Paths restrict which
	// commits are considered at all, so they apply in every mode. Excludes
	// only trim diff noise, so they are pointless without a diff.
	useExcludes := opts.Mode != ModeNone && len(opts.Excludes) > 0
	if len(opts.Paths) > 0 || useExcludes {
		args = append(args, "--")
		if len(opts.Paths) > 0 {
			args = append(args, opts.Paths...)
		} else {
			args = append(args, ".")
		}
		if useExcludes {
			for _, ex := range opts.Excludes {
				args = append(args, ":(exclude)"+ex)
			}
		}
	}
	return args
}

// Inspect checks that path is a git repository and reports whether it is a
// shallow clone. A shallow clone only contains the commits that were fetched,
// so a scan of one silently sees almost no history.
func Inspect(ctx context.Context, path string) (shallow bool, commits int, err error) {
	out, err := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "--is-shallow-repository").Output()
	if err != nil {
		return false, 0, fmt.Errorf("%q is not a git repository", path)
	}
	shallow = strings.TrimSpace(string(out)) == "true"

	if out, err := exec.CommandContext(ctx, "git", "-C", path, "rev-list", "--count", "HEAD").Output(); err == nil {
		if n, convErr := strconv.Atoi(strings.TrimSpace(string(out))); convErr == nil {
			commits = n
		}
	}
	return shallow, commits, nil
}

// Walk runs git log and calls fn once per commit, in history order. If fn
// returns an error the walk stops and that error is returned.
func Walk(ctx context.Context, opts Options, fn func(Commit) error) error {
	max := opts.MaxRecordBytes
	if max <= 0 {
		max = DefaultMaxRecordBytes
	}

	cmd := exec.CommandContext(ctx, "git", Args(opts)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git log: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("git log: %w", err)
	}

	walkErr := splitRecords(stdout, max, func(rec []byte, truncated bool) error {
		commit, ok := parseRecord(string(rec), truncated)
		if !ok {
			return nil
		}
		return fn(commit)
	})

	// Drain any remaining output so git does not block on a full pipe.
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if walkErr != nil {
		return walkErr
	}
	if waitErr != nil {
		return fmt.Errorf("git log: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// parseRecord splits one record into its fields. The trailing field separator
// written by the format string means the patch starts at index 5.
func parseRecord(rec string, truncated bool) (Commit, bool) {
	if strings.TrimSpace(rec) == "" {
		return Commit{}, false
	}
	parts := strings.SplitN(rec, fieldSep, 6)
	if len(parts) < 5 {
		return Commit{}, false
	}
	c := Commit{
		Hash:      strings.TrimSpace(parts[0]),
		Author:    parts[1],
		Subject:   parts[3],
		Body:      strings.TrimRight(parts[4], "\n"),
		Truncated: truncated,
	}
	if c.Hash == "" {
		return Commit{}, false
	}
	if t, err := time.Parse(time.RFC3339, parts[2]); err == nil {
		c.Date = t
	}
	if len(parts) == 6 {
		c.Patch = strings.TrimLeft(parts[5], "\n")
	}
	return c, true
}

// splitRecords reads recordSep-delimited records, capping each at max bytes.
// Bytes past the cap are discarded and the record is flagged as truncated,
// which keeps memory bounded regardless of commit size.
func splitRecords(r io.Reader, max int, emit func(rec []byte, truncated bool) error) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var cur []byte
	truncated := false

	appendCapped := func(b []byte) {
		if len(cur) >= max {
			if len(b) > 0 {
				truncated = true
			}
			return
		}
		if room := max - len(cur); len(b) > room {
			cur = append(cur, b[:room]...)
			truncated = true
			return
		}
		cur = append(cur, b...)
	}
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		err := emit(cur, truncated)
		cur = cur[:0]
		truncated = false
		return err
	}

	for {
		slice, err := br.ReadSlice(recordSep)
		switch err {
		case nil:
			appendCapped(slice[:len(slice)-1]) // drop the separator
			if ferr := flush(); ferr != nil {
				return ferr
			}
		case bufio.ErrBufferFull:
			appendCapped(slice)
		case io.EOF:
			appendCapped(slice)
			return flush()
		default:
			return err
		}
	}
}
