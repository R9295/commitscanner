package main

import (
	"strings"
	"testing"
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
