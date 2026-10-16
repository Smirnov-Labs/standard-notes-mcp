package writeengine

import (
	"errors"
	"strings"
)

// ErrCoverage means the consolidated body does not contain every source body
// verbatim, so the merge would lose content.
var ErrCoverage = errors.New("merge body does not cover all source content")

// PlanMerge builds a new consolidated note from synthesizedBody, which MUST
// contain each source note's body verbatim (typically as an appendix). Coverage
// is checked before anything is written, so a lossy synthesis is rejected and
// no source is touched. The merge is additive: it reuses PlanCreateNote (so the
// consolidated note inherits the engine's reconcile), and NEVER modifies or
// deletes the sources. Tagging the sources cleanup/merged-source is a separate
// batched TagApply the caller runs after this commits (Task 11). Trashing the
// sources is also the caller's job. The caller runs PlanTrashNote for each
// source. That goes through the surgical path, so a source keeps every field it
// has.
func (e *Engine) PlanMerge(sourceUUIDs []string, title, synthesizedBody string) (*Change, error) {
	for _, id := range sourceUUIDs {
		nv, err := e.cl.FetchOne(id)
		if err != nil {
			return nil, err
		}
		if nv == nil {
			return nil, errors.New("merge source not found: " + id)
		}
		if body := strings.TrimSpace(nv.Text); body != "" && !strings.Contains(synthesizedBody, body) {
			return nil, ErrCoverage
		}
	}
	create, err := e.PlanCreateNote(title, synthesizedBody, nil)
	if err != nil {
		return nil, err
	}
	create.Kind = "merge"
	create.OpID = "merge:" + create.NoteUUID // apply/reconcile capture the Change pointer, so relabeling OpID is safe
	return create, nil
}
