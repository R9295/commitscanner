package scan

import (
	"sort"
	"strconv"
	"strings"
)

// maxBlobBytes caps how much added or removed text is kept per commit. Regex
// evaluation is linear in the text size, so this bounds the cost of the rare
// enormous commit.
const maxBlobBytes = 1 << 20

// blob is a concatenation of diff lines plus enough bookkeeping to map a match
// offset back to the file and line it came from.
type blob struct {
	text    strings.Builder
	starts  []int    // byte offset where each line begins
	files   []string // file each line belongs to
	lineNos []int    // line number within that file
	size    int
	full    bool
}

func (b *blob) add(file, line string, lineNo int) {
	if b.full || b.size+len(line)+1 > maxBlobBytes {
		b.full = true
		return
	}
	b.starts = append(b.starts, b.size)
	b.files = append(b.files, file)
	b.lineNos = append(b.lineNos, lineNo)
	b.text.WriteString(line)
	b.text.WriteByte('\n')
	b.size += len(line) + 1
}

func (b *blob) String() string { return b.text.String() }

// locate maps a byte offset in the blob back to "file:line: content".
func (b *blob) locate(offset int) string {
	if len(b.starts) == 0 {
		return ""
	}
	i := sort.Search(len(b.starts), func(i int) bool { return b.starts[i] > offset }) - 1
	if i < 0 {
		i = 0
	}
	text := b.text.String()
	end := len(text)
	if i+1 < len(b.starts) {
		end = b.starts[i+1] - 1
	}
	line := strings.TrimSpace(text[b.starts[i]:end])
	return b.files[i] + ":" + strconv.Itoa(b.lineNos[i]) + ": " + truncate(line, 160)
}

// patch holds the parsed form of one commit's diff.
type patch struct {
	files   []string
	added   blob
	removed blob
}

// parsePatch parses unified diff output. It is tolerant of malformed input:
// anything it does not recognise is skipped rather than treated as an error,
// because git output can contain binary-file markers, mode changes, and
// submodule updates interleaved with ordinary hunks.
func parsePatch(text string) *patch {
	p := &patch{}
	if text == "" {
		return p
	}
	seen := make(map[string]struct{})
	file := ""
	oldLine, newLine := 0, 0

	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			file = pathFromDiffHeader(line)
			if file != "" {
				if _, ok := seen[file]; !ok {
					seen[file] = struct{}{}
					p.files = append(p.files, file)
				}
			}
			oldLine, newLine = 0, 0
		case strings.HasPrefix(line, "+++ b/"):
			// Prefer the post-image name, which is correct across renames.
			if name := strings.TrimPrefix(line, "+++ b/"); name != "" && name != "/dev/null" {
				file = name
				if _, ok := seen[file]; !ok {
					seen[file] = struct{}{}
					p.files = append(p.files, file)
				}
			}
		case strings.HasPrefix(line, "--- "), strings.HasPrefix(line, "index "),
			strings.HasPrefix(line, "new file"), strings.HasPrefix(line, "deleted file"),
			strings.HasPrefix(line, "similarity "), strings.HasPrefix(line, "rename "),
			strings.HasPrefix(line, "old mode"), strings.HasPrefix(line, "new mode"),
			strings.HasPrefix(line, "Binary files"), strings.HasPrefix(line, "\\ No newline"):
			// Header noise.
		case strings.HasPrefix(line, "@@"):
			oldLine, newLine = parseHunkHeader(line)
		case strings.HasPrefix(line, "+"):
			if newLine > 0 {
				p.added.add(file, line[1:], newLine)
				newLine++
			}
		case strings.HasPrefix(line, "-"):
			if oldLine > 0 {
				p.removed.add(file, line[1:], oldLine)
				oldLine++
			}
		case strings.HasPrefix(line, " "):
			oldLine++
			newLine++
		}
	}
	return p
}

// parseFileList reads `git log --name-only` output.
func parseFileList(text string) []string {
	var files []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "commit ") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		files = append(files, line)
	}
	return files
}

// pathFromDiffHeader extracts the post-image path from a `diff --git` line.
// Paths containing spaces make this ambiguous, so fall back to the b/ half.
func pathFromDiffHeader(line string) string {
	rest := strings.TrimPrefix(line, "diff --git ")
	if i := strings.Index(rest, " b/"); i >= 0 {
		return rest[i+3:]
	}
	return ""
}

// parseHunkHeader returns the starting old and new line numbers of a hunk.
func parseHunkHeader(line string) (oldStart, newStart int) {
	// Format: @@ -12,7 +12,9 @@ optional context
	rest := strings.TrimPrefix(line, "@@")
	end := strings.Index(rest, "@@")
	if end < 0 {
		return 0, 0
	}
	for _, field := range strings.Fields(rest[:end]) {
		if len(field) < 2 {
			continue
		}
		sign, nums := field[0], field[1:]
		if i := strings.Index(nums, ","); i >= 0 {
			nums = nums[:i]
		}
		n, err := strconv.Atoi(nums)
		if err != nil {
			continue
		}
		switch sign {
		case '-':
			oldStart = n
		case '+':
			newStart = n
		}
	}
	return oldStart, newStart
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
