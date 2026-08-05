// Package scan turns commits into scored findings.
//
// A finding is a commit that looks like it fixed a security bug, together with
// the evidence that made it look that way. The evidence matters as much as the
// score: these are heuristics, and every hit is meant to be checked by a human
// with `git show`.
package scan

import (
	"sort"
	"strings"
	"time"

	"gitsecscan/internal/gitlog"
	"gitsecscan/internal/rules"
)

// Tier is a coarse confidence bucket.
type Tier string

const (
	TierHigh   Tier = "HIGH"
	TierMedium Tier = "MEDIUM"
	TierLow    Tier = "LOW"
)

// Hit records that one rule matched, and what it matched on.
type Hit struct {
	RuleID   string         `json:"rule"`
	Scope    rules.Scope    `json:"scope"`
	Category rules.Category `json:"category"`
	Weight   int            `json:"weight"`
	Count    int            `json:"count"`
	Desc     string         `json:"description"`
	Evidence []string       `json:"evidence,omitempty"`
}

// Finding is a scored commit.
//
// Message carries the commit message verbatim: it is the author's own
// description of the bug they fixed, and it is the part of a finding worth
// feeding into a threat model. Everything else is provenance.
type Finding struct {
	Hash       string    `json:"hash"`
	Short      string    `json:"short"`
	Author     string    `json:"author"`
	Date       time.Time `json:"date"`
	Subject    string    `json:"subject"`
	Message    string    `json:"message"`
	Score      int       `json:"score"`
	Tier       Tier      `json:"tier"`
	Categories []string  `json:"categories"`
	Subsystems []string  `json:"subsystems,omitempty"`
	Hits       []Hit     `json:"hits"`
	Files      []string  `json:"files,omitempty"`
	FileCount  int       `json:"file_count,omitempty"`
	Truncated  bool      `json:"truncated,omitempty"`
}

// Config tunes scoring.
type Config struct {
	Rules []rules.Rule

	// MinScore is the reporting threshold.
	MinScore int
	// HighScore and MediumScore are the tier boundaries.
	HighScore   int
	MediumScore int

	// PathCap and DiffCap bound how much weight the weaker path and diff
	// signals can contribute, so message evidence stays dominant.
	PathCap int
	DiffCap int

	// MaxEvidence is the number of samples kept per rule.
	MaxEvidence int
	// MaxFiles is the number of file names kept per finding.
	MaxFiles int
}

// DefaultConfig returns the tuned defaults.
func DefaultConfig() Config {
	return Config{
		Rules:       rules.Default(),
		MinScore:    8,
		HighScore:   14,
		MediumScore: 10,
		PathCap:     3,
		DiffCap:     9,
		MaxEvidence: 3,
		MaxFiles:    12,
	}
}

// Scanner scores commits against a rule set.
type Scanner struct {
	cfg      Config
	message  []rules.Rule
	added    []rules.Rule
	removed  []rules.Rule
	paths    []rules.Rule
	testOnly *testOnlyRule
}

// New builds a Scanner. Rules are partitioned by scope once, up front.
func New(cfg Config) *Scanner {
	if len(cfg.Rules) == 0 {
		cfg.Rules = rules.Default()
	}
	if cfg.MaxEvidence <= 0 {
		cfg.MaxEvidence = 3
	}
	return &Scanner{
		cfg:      cfg,
		message:  rules.ByScope(cfg.Rules, rules.ScopeMessage),
		added:    rules.ByScope(cfg.Rules, rules.ScopeAdded),
		removed:  rules.ByScope(cfg.Rules, rules.ScopeRemoved),
		paths:    rules.ByScope(cfg.Rules, rules.ScopePath),
		testOnly: newTestOnlyRule(),
	}
}

// Score evaluates one commit. It returns the finding and whether it cleared the
// reporting threshold.
func (s *Scanner) Score(c gitlog.Commit, mode gitlog.Mode) (Finding, bool) {
	f := Finding{
		Hash:      c.Hash,
		Short:     c.Short(),
		Author:    c.Author,
		Date:      c.Date,
		Subject:   c.Subject,
		Message:   strings.TrimSpace(c.Message()),
		Truncated: c.Truncated,
	}

	var (
		total       int
		msgPositive bool
		fixShaped   bool
		catWeight   = map[rules.Category]int{}
	)

	record := func(h Hit) {
		f.Hits = append(f.Hits, h)
		if h.Category != rules.CatMeta && h.Weight > 0 {
			catWeight[h.Category] += h.Weight
		}
	}

	// Message scope.
	message := c.Message()
	for _, r := range s.message {
		locs := r.Pattern.FindAllStringIndex(message, s.cfg.MaxEvidence)
		if len(locs) == 0 {
			continue
		}
		total += r.Weight
		if r.Weight > 0 && r.Category != rules.CatMeta {
			msgPositive = true
		}
		if r.ID == rules.RuleFixShaped {
			fixShaped = true
		}
		hit := Hit{RuleID: r.ID, Scope: r.Scope, Category: r.Category, Weight: r.Weight, Count: len(locs), Desc: r.Desc}
		for _, loc := range locs {
			hit.Evidence = append(hit.Evidence, truncate(strings.TrimSpace(message[loc[0]:loc[1]]), 120))
		}
		record(hit)
	}

	// Diff and path scopes.
	var files []string
	var diffPositive bool
	switch mode {
	case gitlog.ModeFull:
		p := parsePatch(c.Patch)
		files = p.files
		diffScore := 0
		for _, set := range []struct {
			rs []rules.Rule
			b  *blob
		}{{s.added, &p.added}, {s.removed, &p.removed}} {
			text := set.b.String()
			if text == "" {
				continue
			}
			for _, r := range set.rs {
				locs := r.Pattern.FindAllStringIndex(text, s.cfg.MaxEvidence)
				if len(locs) == 0 {
					continue
				}
				diffScore += r.Weight
				diffPositive = true
				hit := Hit{RuleID: r.ID, Scope: r.Scope, Category: r.Category, Weight: r.Weight, Count: len(locs), Desc: r.Desc}
				for _, loc := range locs {
					hit.Evidence = append(hit.Evidence, set.b.locate(loc[0]))
				}
				record(hit)
			}
		}
		if diffScore > s.cfg.DiffCap {
			diffScore = s.cfg.DiffCap
		}
		total += diffScore
	case gitlog.ModeNames:
		files = parseFileList(c.Patch)
	}

	if len(files) > 0 {
		joined := strings.Join(files, "\n")
		pathScore := 0
		for _, r := range s.paths {
			locs := r.Pattern.FindAllStringIndex(joined, s.cfg.MaxEvidence)
			if len(locs) == 0 {
				continue
			}
			pathScore += r.Weight
			hit := Hit{RuleID: r.ID, Scope: r.Scope, Category: r.Category, Weight: r.Weight, Count: len(locs), Desc: r.Desc}
			for _, loc := range locs {
				hit.Evidence = append(hit.Evidence, lineAround(joined, loc[0]))
			}
			record(hit)
		}
		if pathScore > s.cfg.PathCap {
			pathScore = s.cfg.PathCap
		}
		total += pathScore

		if h, ok := s.testOnly.apply(files); ok {
			total += h.Weight
			record(h)
		}
	}

	f.Score = total
	f.Files = files
	f.FileCount = len(files)
	f.Subsystems = subsystems(files)
	if len(f.Files) > s.cfg.MaxFiles {
		f.Files = f.Files[:s.cfg.MaxFiles]
	}
	f.Categories = rankCategories(catWeight)
	f.Tier = tierFor(total, s.cfg)

	sort.SliceStable(f.Hits, func(i, j int) bool { return f.Hits[i].Weight > f.Hits[j].Weight })

	// A commit qualifies only if its message says something security-relevant,
	// or it is phrased as a fix and its diff carries defensive changes. Diff
	// and path signals on their own describe ordinary code: nearly every
	// feature commit adds a `checked_add` or an error return somewhere.
	if !msgPositive && !(fixShaped && diffPositive) {
		return f, false
	}
	return f, total >= s.cfg.MinScore
}

func tierFor(score int, cfg Config) Tier {
	switch {
	case score >= cfg.HighScore:
		return TierHigh
	case score >= cfg.MediumScore:
		return TierMedium
	default:
		return TierLow
	}
}

func rankCategories(weights map[rules.Category]int) []string {
	type kv struct {
		cat rules.Category
		w   int
	}
	list := make([]kv, 0, len(weights))
	for c, w := range weights {
		list = append(list, kv{c, w})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].w != list[j].w {
			return list[i].w > list[j].w
		}
		return list[i].cat < list[j].cat
	})
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, string(e.cat))
	}
	return out
}

// subsystems names the components a commit touched, taken from the top-level
// directory of each file. It answers "where in the system did this bug live",
// which is the axis a threat model is organised along.
func subsystems(files []string) []string {
	counts := map[string]int{}
	for _, f := range files {
		part := f
		if i := strings.IndexByte(f, '/'); i > 0 {
			part = f[:i]
		}
		if part == "" || strings.HasPrefix(part, ".") {
			continue
		}
		counts[part]++
	}
	out := make([]string, 0, len(counts))
	for name := range counts {
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool {
		if counts[out[i]] != counts[out[j]] {
			return counts[out[i]] > counts[out[j]]
		}
		return out[i] < out[j]
	})
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

func lineAround(text string, offset int) string {
	start := strings.LastIndexByte(text[:offset], '\n') + 1
	end := strings.IndexByte(text[offset:], '\n')
	if end < 0 {
		end = len(text)
	} else {
		end += offset
	}
	return truncate(strings.TrimSpace(text[start:end]), 160)
}

// testOnlyRule penalises commits that are dominated by tests, benchmarks, or
// fuzz harnesses. A defect that only ever existed in a harness never shipped,
// so it is weak evidence of a real failure mode, even when the message reads
// exactly like a security fix ("fix panic in fuzz test"). The
// threshold is a ratio rather than "all files" because harness commits
// routinely carry along a manifest or a module declaration.
type testOnlyRule struct {
	weight int
	ratio  float64
}

func newTestOnlyRule() *testOnlyRule { return &testOnlyRule{weight: -8, ratio: 0.8} }

func (t *testOnlyRule) apply(files []string) (Hit, bool) {
	if len(files) == 0 {
		return Hit{}, false
	}
	tests, sources := 0, 0
	var sample []string
	for _, f := range files {
		switch classifyPath(f) {
		case pathTest:
			tests++
			if len(sample) < 3 {
				sample = append(sample, f)
			}
		case pathSource:
			sources++
		}
	}
	// Manifests, CI config, and docs are ignored on both sides: a harness
	// commit routinely carries a Cargo.toml or a workflow file along with it,
	// and counting those would hide it behind the ratio.
	if tests == 0 || float64(tests)/float64(tests+sources) < t.ratio {
		return Hit{}, false
	}
	return Hit{
		RuleID:   RuleTestOnly,
		Scope:    rules.ScopePath,
		Category: rules.CatMeta,
		Weight:   t.weight,
		Count:    tests,
		Desc:     "mostly tests, benches, or fuzz harnesses",
		Evidence: sample,
	}, true
}

// RuleTestOnly is the ID of the synthetic rule that fires when a commit only
// touched test, bench, or fuzz code. Consumers use it to tell a shipped defect
// apart from a harness defect.
const RuleTestOnly = "neg-test-only-paths"

// pathKind classifies a file for the test-only heuristic.
type pathKind int

const (
	pathSource pathKind = iota
	pathTest
	pathNeutral // manifests, CI config, docs: evidence either way
)

func classifyPath(path string) pathKind {
	lower := strings.ToLower(path)
	base := lower
	if i := strings.LastIndexByte(lower, '/'); i >= 0 {
		base = lower[i+1:]
	}

	switch {
	case strings.HasSuffix(base, "_test.go"), strings.HasSuffix(base, ".test.ts"),
		strings.HasSuffix(base, "_test.py"), strings.HasSuffix(base, "_test.rs"):
		return pathTest
	}
	for _, seg := range []string{"/tests/", "/test/", "/fuzz/", "/benches/", "/benchmarks/", "/testdata/"} {
		if strings.Contains("/"+lower, seg) {
			return pathTest
		}
	}

	switch base {
	case "cargo.toml", "cargo.lock", "go.mod", "go.sum", "package.json", "package-lock.json",
		"makefile", "justfile", "license", "dockerfile":
		return pathNeutral
	}
	switch {
	case strings.HasPrefix(lower, ".github/"), strings.HasPrefix(lower, ".circleci/"):
		return pathNeutral
	case strings.HasSuffix(base, ".md"), strings.HasSuffix(base, ".yml"),
		strings.HasSuffix(base, ".yaml"), strings.HasSuffix(base, ".txt"):
		return pathNeutral
	}
	return pathSource
}
