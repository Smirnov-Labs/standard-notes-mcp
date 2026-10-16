package main

import (
	"reflect"
	"testing"
)

// selectTargets is the one correctness-sensitive piece of the bulk tagger: it
// decides which notes get the tag. It must tag only live, non-trashed notes
// (trashed diaries were never exported), and must never double-tag.

func TestSelectTargets_keepsOnlyLiveNotes(t *testing.T) {
	status := map[string]noteStatus{
		"live1":    statusLive,
		"live2":    statusLive,
		"trashed1": statusTrashed,
		// "missing1" is absent from the map -> statusMissing (zero value).
	}
	ids, st := selectTargets([][]string{{"live1", "trashed1", "missing1", "live2"}}, status)

	wantIDs := []string{"live1", "live2"}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Errorf("ids = %v, want %v (only live notes)", ids, wantIDs)
	}
	if st.Kept != 2 {
		t.Errorf("Kept = %d, want 2", st.Kept)
	}
	if st.SkippedTrashed != 1 {
		t.Errorf("SkippedTrashed = %d, want 1", st.SkippedTrashed)
	}
	if st.SkippedMissing != 1 {
		t.Errorf("SkippedMissing = %d, want 1", st.SkippedMissing)
	}
}

func TestSelectTargets_dedupsAcrossAndWithinSources(t *testing.T) {
	status := map[string]noteStatus{"a": statusLive, "b": statusLive, "c": statusLive}
	// "a" repeats within the first source; "c" repeats across the two sources.
	ids, st := selectTargets([][]string{{"a", "a", "c"}, {"b", "c"}}, status)

	wantIDs := []string{"a", "b", "c"}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Errorf("ids = %v, want %v (each uuid once)", ids, wantIDs)
	}
	if st.Kept != 3 {
		t.Errorf("Kept = %d, want 3", st.Kept)
	}
	if st.Duplicates != 2 {
		t.Errorf("Duplicates = %d, want 2 (a within, c across)", st.Duplicates)
	}
}

func TestSelectTargets_sortsOutput(t *testing.T) {
	status := map[string]noteStatus{"x": statusLive, "a": statusLive, "m": statusLive}
	ids, _ := selectTargets([][]string{{"x", "a", "m"}}, status)

	want := []string{"a", "m", "x"}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("ids = %v, want sorted %v", ids, want)
	}
}

func TestSelectTargets_emptyInput(t *testing.T) {
	ids, st := selectTargets(nil, map[string]noteStatus{})
	if len(ids) != 0 {
		t.Errorf("ids = %v, want empty", ids)
	}
	if (st != selectStats{}) {
		t.Errorf("stats = %+v, want zero", st)
	}
}
