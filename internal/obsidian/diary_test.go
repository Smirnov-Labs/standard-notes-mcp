package obsidian

import (
	"strings"
	"testing"
	"time"
)

func d(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestDiaryRelPath(t *testing.T) {
	cases := map[string]string{
		"2024-03-09": "diary/2024/03/09.md", // zero-pad month and day
		"2026-12-31": "diary/2026/12/31.md",
		"2023-01-01": "diary/2023/01/01.md",
	}
	for in, want := range cases {
		if got := DiaryRelPath(d(in)); got != want {
			t.Errorf("DiaryRelPath(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestNewFileContents_matchesTemplate(t *testing.T) {
	got := NewFileContents(d("2024-03-15"), "", "Woke early. Wrote.")
	for _, want := range []string{"---\nprivate: true\ntags:\n  - diary\n---", "## 2024-03-15", "Woke early. Wrote."} {
		if !strings.Contains(got, want) {
			t.Errorf("new file missing %q in:\n%s", want, got)
		}
	}
}

func TestNewFileContents_keepsMeaningfulTitle(t *testing.T) {
	got := NewFileContents(d("2024-03-15"), "Trip to Kyoto", "body")
	if !strings.Contains(got, "**Trip to Kyoto**") {
		t.Errorf("expected title lead, got:\n%s", got)
	}
	// a title that is just the date adds nothing, so it is omitted
	got2 := NewFileContents(d("2024-03-15"), "2024-03-15", "body")
	if strings.Contains(got2, "**2024-03-15**") {
		t.Errorf("date-only title should be omitted, got:\n%s", got2)
	}
}

// The critical data-loss guard: appending to an existing day-file must keep every
// byte of the original and only add.
func TestAppendedContents_neverLosesExisting(t *testing.T) {
	existing := "---\nprivate: true\ntags:\n  - diary\n---\n\n## 2024-03-15\n\nMy own entry.\n"
	got := AppendedContents(existing, d("2024-03-15"), "", "Imported entry.")
	if !strings.Contains(got, "My own entry.") {
		t.Fatalf("append DROPPED existing content:\n%s", got)
	}
	if !strings.Contains(got, "Imported entry.") {
		t.Errorf("append missing new content:\n%s", got)
	}
	if !strings.Contains(got, "(imported from Standard Notes)") {
		t.Errorf("append missing import marker:\n%s", got)
	}
	if len(got) <= len(existing) {
		t.Errorf("appended file did not grow: %d <= %d", len(got), len(existing))
	}
	if !strings.HasPrefix(got, strings.TrimRight(existing, "\n")) {
		t.Errorf("original not preserved verbatim as prefix:\n%s", got)
	}
}
