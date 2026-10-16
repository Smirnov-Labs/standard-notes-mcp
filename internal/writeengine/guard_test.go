package writeengine_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// forbiddenDelete lists every way non-test source can set the permanent deleted
// flag on an item envelope. The engine's only delete is Trash. Trash sets the
// reversible trashed flag inside the note content, and an official app can
// restore the note. The envelope flag is permanent, so non-test source must
// never set it, whatever the value.
//
//   - SetDeleted with any argument. A variable that holds true deletes as surely
//     as the literal true.
//   - A direct assignment to a .Deleted field, such as n.raw.Deleted = true. Any
//     assignment counts, for the same reason. Reads (!it.Deleted) and
//     comparisons (it.Deleted == true) do not match.
//   - DeleteContent(...), the gosn-v2 one-call vault wipe that sets Deleted on
//     every item, and a keyed Deleted:true struct literal.
var forbiddenDelete = []struct {
	what string
	re   *regexp.Regexp
}{
	{"SetDeleted call", regexp.MustCompile(`\bSetDeleted\s*\(`)},
	{"assignment to a .Deleted field", regexp.MustCompile(`\.Deleted\s*=[^=]`)},
	{"DeleteContent call (vault wipe)", regexp.MustCompile(`\bDeleteContent\s*\(`)},
	{"keyed Deleted:true literal", regexp.MustCompile(`\bDeleted:\s*true\b`)},
}

// Non-test source must never perform a permanent delete, anywhere in the repo.
// This file is a _test.go file, so the scan skips it and its own patterns do not
// trip it.
func TestNoPermanentDeleteInCodebase(t *testing.T) {
	root := "../.."
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		if strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err // fail closed: a file the guard cannot read is a file it cannot vouch for
		}
		src := string(b)
		for _, f := range forbiddenDelete {
			for _, loc := range f.re.FindAllStringIndex(src, -1) {
				line := 1 + strings.Count(src[:loc[0]], "\n")
				t.Errorf("forbidden permanent delete (%s) at %s:%d", f.what, p, line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
