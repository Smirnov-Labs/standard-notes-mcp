package main

import "sort"

// noteStatus is the state of a note in the live vault, from the point of view of
// the bulk tagger.
type noteStatus int

const (
	// statusMissing is the zero value: the uuid names no note in the live vault
	// (it was trashed-and-purged or changed since the triage that produced the
	// source list). It must not be tagged.
	statusMissing noteStatus = iota
	// statusLive: the note exists and is not trashed. Only these get the tag.
	statusLive
	// statusTrashed: the note exists but is in the trash. A trashed diary was never
	// exported, so it must not be tagged.
	statusTrashed
)

// selectStats breaks down what selectTargets did with the source uuids.
type selectStats struct {
	Kept           int // live notes that will get the tag
	SkippedTrashed int // in the trash, so not exported, so skipped
	SkippedMissing int // no such note in the live vault, so skipped
	Duplicates     int // source entries that repeated an already-seen uuid
}

// selectTargets unions the source uuid lists, keeps only the uuids that name a
// live, non-trashed note, dedups them, and returns them sorted with a breakdown.
// status maps every known note uuid to its state; a uuid absent from status is
// statusMissing. Sorting makes the output stable, so a dry run and the write that
// follows name the same notes in the same order.
func selectTargets(sources [][]string, status map[string]noteStatus) ([]string, selectStats) {
	seen := make(map[string]bool)
	var kept []string
	var st selectStats
	for _, src := range sources {
		for _, id := range src {
			if id == "" {
				continue
			}
			if seen[id] {
				st.Duplicates++
				continue
			}
			seen[id] = true
			switch status[id] {
			case statusLive:
				kept = append(kept, id)
				st.Kept++
			case statusTrashed:
				st.SkippedTrashed++
			default:
				st.SkippedMissing++
			}
		}
	}
	sort.Strings(kept)
	return kept, st
}
