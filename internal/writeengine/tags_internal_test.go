package writeengine

// Tests for applyTagEdit, the one function that every change to an existing tag
// goes through. They live in the package so they can hand it an edit of their own.
// They need the Docker SN server (see ops/docker).

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/smirnov-labs/standard-notes-mcp/internal/snclient"
)

const (
	lossyA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	lossyB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

	lossySeed = `{"title":"t","references":[` +
		`{"uuid":"` + lossyA + `","content_type":"Note"},` +
		`{"uuid":"` + lossyB + `","content_type":"Note"}],` +
		`"future_tag_key":"must survive"}`
)

// rawTagObject returns the content that the server holds for a tag, as top-level raw values.
func rawTagObject(t *testing.T, c *snclient.Client, id string) map[string]json.RawMessage {
	t.Helper()
	r, err := c.FetchRawTag(id)
	if err != nil {
		t.Fatalf("FetchRawTag(%s): %v", id, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.Content()), &m); err != nil {
		t.Fatalf("content of %s is not a JSON object: %v", id, err)
	}
	return m
}

// A write can land and still lose data. A bug in a mutation can drop a reference
// that it never meant to touch. applyTagEdit reads the tag back after the push.
// It fails unless the end state holds. It fails too if a reference that the edit
// did not mean to remove is gone. The hook accepts every note, so the read-back
// is what stops the fault. The control edit does only what it says, and it passes.
func TestApplyTagEditCatchesALostReference(t *testing.T) {
	e, c := liveEngine(t)
	titleIsRenamed := func(s tagState) bool { return s.Title == "renamed" }

	id, err := c.SeedRawTag(t, lossySeed)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	lossy := tagEdit{
		mutate: func(m map[string]json.RawMessage) error {
			m["title"] = json.RawMessage(`"renamed"`)
			m["references"] = json.RawMessage(`[]`) // the bug: it drops both references
			return nil
		},
		done: titleIsRenamed,
	}
	ch := &Change{OpID: "tag-rename:lossy", Kind: "tag-rename", TagUUID: id}
	if err := e.applyTagEdit(ch, lossy); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("an edit that lost both references returned %v, want ErrVerifyFailed", err)
	}

	id2, err := c.SeedRawTag(t, lossySeed)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	honest := tagEdit{
		mutate: func(m map[string]json.RawMessage) error {
			m["title"] = json.RawMessage(`"renamed"`)
			return nil
		},
		done: titleIsRenamed,
	}
	ch2 := &Change{OpID: "tag-rename:honest", Kind: "tag-rename", TagUUID: id2}
	if err := e.applyTagEdit(ch2, honest); err != nil {
		t.Fatalf("an edit that changed only the title returned %v, want nil", err)
	}
	if got := string(rawTagObject(t, c, id2)["future_tag_key"]); got != `"must survive"` {
		t.Errorf("future_tag_key = %s, want it kept", got)
	}
}

// An edit that names references to drop can lose exactly those, and no others.
func TestApplyTagEditAllowsOnlyTheDeclaredLoss(t *testing.T) {
	e, c := liveEngine(t)
	aIsGone := func(s tagState) bool { return !containsAny(s.Refs, []string{lossyA}) }

	// It declares a, and it removes both. The loss of b is not declared.
	id, err := c.SeedRawTag(t, lossySeed)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	greedy := tagEdit{
		mutate: func(m map[string]json.RawMessage) error { m["references"] = json.RawMessage(`[]`); return nil },
		done:   aIsGone,
		drops:  []string{lossyA},
	}
	ch := &Change{OpID: "detach:greedy", Kind: "detach", TagUUID: id}
	if err := e.applyTagEdit(ch, greedy); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("an edit that lost an undeclared reference returned %v, want ErrVerifyFailed", err)
	}

	// It declares a, and it removes a only.
	id2, err := c.SeedRawTag(t, lossySeed)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	exact := tagEdit{
		mutate: func(m map[string]json.RawMessage) error {
			m["references"] = json.RawMessage(`[{"uuid":"` + lossyB + `","content_type":"Note"}]`)
			return nil
		},
		done:  aIsGone,
		drops: []string{lossyA},
	}
	ch2 := &Change{OpID: "detach:exact", Kind: "detach", TagUUID: id2}
	if err := e.applyTagEdit(ch2, exact); err != nil {
		t.Fatalf("an edit that lost only the declared reference returned %v, want nil", err)
	}
}
