package scan

import (
	"strings"
	"testing"
)

func TestParsePatchTracksFilesAndLines(t *testing.T) {
	p := parsePatch(securityPatch)
	if len(p.files) != 1 || p.files[0] != "codec/src/types/vec.rs" {
		t.Fatalf("files = %v", p.files)
	}

	added := p.added.String()
	if !strings.Contains(added, "return Err(Error::InvalidLength(len));") {
		t.Errorf("added lines missing the new guard:\n%s", added)
	}
	if strings.Contains(added, "let mut out = Vec::with_capacity(len);") {
		t.Error("removed line leaked into the added blob")
	}

	removed := p.removed.String()
	if !strings.Contains(removed, "Vec::with_capacity(len)") {
		t.Errorf("removed lines missing the old code:\n%s", removed)
	}

	// The hunk starts at line 60 with three context lines before the change.
	idx := strings.Index(added, "if len > buf.remaining()")
	loc := p.added.locate(idx)
	if !strings.HasPrefix(loc, "codec/src/types/vec.rs:62: ") {
		t.Errorf("locate = %q, want line 62 of the new file", loc)
	}
}

func TestParseHunkHeader(t *testing.T) {
	cases := []struct {
		in       string
		old, new int
	}{
		{"@@ -60,7 +60,10 @@ impl Read for Vec<T> {", 60, 60},
		{"@@ -1 +1 @@", 1, 1},
		{"@@ -0,0 +1,5 @@", 0, 1},
		{"not a hunk", 0, 0},
	}
	for _, tc := range cases {
		gotOld, gotNew := parseHunkHeader(tc.in)
		if gotOld != tc.old || gotNew != tc.new {
			t.Errorf("parseHunkHeader(%q) = (%d, %d), want (%d, %d)", tc.in, gotOld, gotNew, tc.old, tc.new)
		}
	}
}

func TestParsePatchHandlesRenamesAndBinaries(t *testing.T) {
	patch := `diff --git a/old/name.rs b/new/name.rs
similarity index 98%
rename from old/name.rs
rename to new/name.rs
--- a/old/name.rs
+++ b/new/name.rs
@@ -1,3 +1,3 @@
 fn main() {
-    let x = 1;
+    let x = 2;
 }
diff --git a/logo.png b/logo.png
Binary files a/logo.png and b/logo.png differ
`
	p := parsePatch(patch)
	if len(p.files) != 2 {
		t.Fatalf("files = %v, want 2 entries", p.files)
	}
	if p.files[0] != "new/name.rs" {
		t.Errorf("renamed file recorded as %q, want the post-image name", p.files[0])
	}
	if !strings.Contains(p.added.String(), "let x = 2;") {
		t.Errorf("added = %q", p.added.String())
	}
}

func TestParsePatchEmpty(t *testing.T) {
	p := parsePatch("")
	if len(p.files) != 0 || p.added.String() != "" || p.removed.String() != "" {
		t.Error("empty patch should parse to nothing")
	}
}

func TestParseFileList(t *testing.T) {
	files := parseFileList("codec/src/lib.rs\ncodec/src/lib.rs\n\np2p/src/lib.rs\n")
	if len(files) != 2 || files[0] != "codec/src/lib.rs" || files[1] != "p2p/src/lib.rs" {
		t.Errorf("files = %v", files)
	}
}

func TestBlobCap(t *testing.T) {
	var b blob
	line := strings.Repeat("x", 4096)
	for i := 0; i < 1000; i++ {
		b.add("f.rs", line, i+1)
	}
	if !b.full {
		t.Error("blob should have hit its cap")
	}
	if b.size > maxBlobBytes {
		t.Errorf("blob size %d exceeds cap %d", b.size, maxBlobBytes)
	}
}
