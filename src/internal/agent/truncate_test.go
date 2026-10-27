package agent

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateKeepsUTF8Valid(t *testing.T) {
	// Transcripts and tool arguments are frequently Chinese, so a byte slice at
	// the limit would emit invalid UTF-8 into the audit trail.
	value := strings.Repeat("目标", 100)
	got := truncate(value, 51)

	if !utf8.ValidString(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
	if len(got) > 51+len("...") {
		t.Fatalf("truncated length = %d, want at most %d", len(got), 51+3)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("truncated value has no marker: %q", got)
	}
}

func TestTruncateLeavesShortValuesAlone(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Fatalf("truncate = %q", got)
	}
}

func TestTruncateHandlesExactBoundary(t *testing.T) {
	value := "abcdef"
	if got := truncate(value, 6); got != value {
		t.Fatalf("truncate at exact length = %q, want %q", got, value)
	}
}
