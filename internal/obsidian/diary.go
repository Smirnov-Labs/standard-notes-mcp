// Package obsidian renders Standard Notes content into the user's Obsidian vault,
// matching the conventions observed there. It is pure (no I/O): callers decide
// whether a target file exists and read/write it. The one hard rule lives here —
// AppendedContents only ever grows an existing file, so an import can never
// overwrite an existing diary entry.
package obsidian

import (
	"fmt"
	"strings"
	"time"
)

const heading = "2006-01-02" // the H2 date heading format, matching the diary template

// DiaryRelPath returns the vault-relative path for a diary entry on date, matching
// the user's pattern diary/YYYY/MM/DD.md (month and day zero-padded).
func DiaryRelPath(date time.Time) string {
	return fmt.Sprintf("diary/%04d/%02d/%02d.md", date.Year(), int(date.Month()), date.Day())
}

// NewFileContents renders a brand-new diary day-file matching the user's template:
// frontmatter (private: true, tags: [diary]), then a dated H2 heading and the body.
// A meaningful title is kept as a bold lead line so a titled note never loses it.
func NewFileContents(date time.Time, title, body string) string {
	var b strings.Builder
	b.WriteString("---\nprivate: true\ntags:\n  - diary\n---\n\n")
	b.WriteString("## " + date.Format(heading) + "\n\n")
	if lead := titleLead(date, title); lead != "" {
		b.WriteString(lead + "\n\n")
	}
	b.WriteString(strings.TrimRight(body, "\n") + "\n")
	return b.String()
}

// AppendedContents returns existing with an imported entry appended under its own
// dated heading. It NEVER removes or rewrites existing content: the original is kept
// verbatim as a prefix (only trailing blank lines are normalized), so a day-file can
// only grow. The import marker makes the appended block easy to find or undo.
func AppendedContents(existing string, date time.Time, title, body string) string {
	var b strings.Builder
	b.WriteString(strings.TrimRight(existing, "\n"))
	b.WriteString("\n\n## " + date.Format(heading) + " (imported from Standard Notes)\n\n")
	if lead := titleLead(date, title); lead != "" {
		b.WriteString(lead + "\n\n")
	}
	b.WriteString(strings.TrimRight(body, "\n") + "\n")
	return b.String()
}

// titleLead returns the bold title line, or "" when the title adds nothing (empty, or
// identical to the date heading).
func titleLead(date time.Time, title string) string {
	t := strings.TrimSpace(title)
	if t == "" || t == date.Format(heading) {
		return ""
	}
	return "**" + t + "**"
}
