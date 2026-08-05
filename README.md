# gitsecscan

Scans the git history of any repository for commits that fixed security-relevant
bugs, and emits each one as a described defect — the author's own words about what
broke — so the set can be fed into a threat model.

The premise: a project's history is the only honest record of how it actually
fails. What broke before is what will break again.

## Build

```
make build          # native binary
make dist           # dist/gitsecscan-linux-amd64 and dist/gitsecscan-darwin-arm64
make test           # go vet + go test
```

Go 1.26, standard library only, `CGO_ENABLED=0`, so cross-compiling needs no
toolchain beyond Go itself. `git` must be on the host's `PATH`; the repository is
read through a single streaming `git log`, never modified.

## Use

```
gitsecscan /path/to/repo                                  # ranked report
gitsecscan --simple -top=0 /path/to/repo                   # hash,category + message, nothing else
gitsecscan -format=threat -top=0 -out=bugs.md /path/repo   # corpus for threat modelling
gitsecscan -subdir=codec,p2p/src /path/to/repo             # one part of a monorepo
gitsecscan -since=2025-01-01 -format=json /path/to/repo    # machine-readable
gitsecscan -list-rules                                     # what it looks for
```

Notable flags:

| flag | default | meaning |
|---|---|---|
| `-subdir` | — | comma-separated inner directories to scan (`codec,p2p/src`) |
| `-merges` | `true` | include merge commits; `-merges=false` to skip them |
| `-diff` | `full` | `full` reads patches, `names` reads file lists, `none` is message-only and fastest |
| `-min-score` | 8 | reporting threshold |
| `-top` | 40 | cap on reported findings, `0` for all |
| `-format` | `text` | `text`, `json`, `md`, `threat`, or `simple` |
| `--simple` | off | shorthand for `-format=simple` |
| `-since` / `-until` / `-author` / `-rev` | — | passed through to `git log` |
| `-exclude` | lockfiles, vendor, fixtures | pathspecs whose diffs are skipped |

Shallow clones only contain the commits they fetched. Run `git fetch --unshallow`
(or clone afresh) before scanning one, or the scan will see a single commit.

## How it scores

Each commit is matched against weighted regular expressions in four scopes:

- **message** — the strongest signal. An engineer fixing a security bug usually
  says so: `use-after-free`, `unbounded allocation`, `constant-time`, `RUSTSEC-…`.
- **added lines** — defensive code appearing in the diff: `checked_add`,
  `return Err(Error::InvalidLength…)`, `ct_eq`, capacity clamps.
- **removed lines** — panicking or unsafe code disappearing: `.unwrap()`,
  `unsafe {`, `get_unchecked`.
- **paths** — whether the commit touched parsing, networking, crypto, or
  consensus code.

Scores are additive, and negative rules pull down docs, refactors, reverts, and
feature work. Two structural rules matter more than any single weight:

1. **A commit must say something.** Diff and path signals alone never qualify a
   commit — almost every feature commit adds a `checked_add` somewhere. A finding
   needs a security-relevant message, or a fix-shaped message plus defensive diff.
2. **Harness fixes are demoted.** A panic fixed inside `fuzz/` or `tests/` never
   shipped, so it is weak evidence of a real failure mode even when the subject
   line reads exactly like a security fix. Those entries are penalised and
   labelled `scope: test/fuzz code only`.

Path and diff contributions are capped so message evidence stays dominant.
Tiers are `HIGH` (>= 14), `MEDIUM` (>= 10), `LOW` (>= 8) by default.

## Output

`-format=threat` is the one built for feeding a model. Per commit it emits the
bug class, the subsystem, the commit message verbatim, and the diff lines that
implemented the fix:

```markdown
### 1. [storage] Prevent overflow on `Location` to `Position` conversion (#1832)

- commit: `a68f75ec78bab93e551637f4799acc7b539f4f1a` (2025-10-09)
- bug class: memory-safety, input-validation, dos
- subsystem: storage, examples
- confidence: HIGH (score 19)

**What the author said:**
...
**Change that fixed it:**
- `storage/src/adb/current.rs:515: let Some(end_loc) = start_loc.checked_add(...)`
```

`--simple` is the same corpus stripped to the bone — one `hash,category` line
followed by the commit message, blank line between entries:

```
a68f75ec78bab93e551637f4799acc7b539f4f1a,memory-safety
[storage] Prevent overflow on `Location` to `Position` conversion (#1832)

d62e3270a3970b2c1c0ab5863e0e04e844873b23,crypto
[cryptography] Always Implement and Drop `Zeroize` (#796)
```

The category is the highest-weighted one for that commit. Message trailers
(`Co-authored-by:` and friends) are stripped from both `simple` and `threat`.

`-format=json` carries the same data plus every rule hit, for filtering and
downstream tooling. `text` and `md` are for humans.

## Limitations

These are heuristics over English prose. They are worth stating plainly:

- **Squash-merge repositories lose the story.** If a project squashes PRs, the
  commit message is one line and the real explanation lives in the PR body on the
  forge, which git does not have. The scanner reports what git knows.
- **Silent fixes are invisible.** A bug fixed without saying so scores on diff
  signals alone, which are deliberately not enough to qualify a commit. Recall is
  bounded by how candidly the project writes commit messages.
- **A high score is not a verdict.** Every finding is a claim to check with
  `git show <hash>`.
- **Fixed does not mean absent.** The corpus describes failure modes that were
  found, not the ones still present.

## Layout

```
main.go               CLI, worker pool
internal/gitlog       streaming git log reader (record framing, size caps)
internal/rules        the heuristics: pattern, weight, category, scope
internal/scan         patch parsing, scoring, evidence collection
internal/report       text, json, md, and threat renderers
```

`go test ./...` covers record framing and truncation, hunk-header and rename
parsing, every rule's match and counter-example, and end-to-end scoring.
