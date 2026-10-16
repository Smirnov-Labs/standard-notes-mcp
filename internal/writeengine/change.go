package writeengine

// Change is a planned, not-yet-applied mutation: a decrypt-diff plus a bound
// apply func. Plan* builds it (dry-run = build without Commit); Commit runs the
// apply through the serialized, bounded, ledgered, conflict-checked path.
// Before/After/TagUUID are used by later tasks (trash, merge, tag).
//
// OpID names one intent, not one target. The ledger is durable and a verified
// OpID makes Commit a no-op forever, so an OpID built only from the target
// (for example "trash:"+noteUUID) would turn a second, legitimate change to the
// same target into a silent no-op. Add a per-Plan nonce unless that is wanted.
//
// NoteUUID and TagUUID name the one note and the one tag this change may create.
// pushAndVerify and pushRawAndVerify treat any other new note or tag as a
// duplicate, and they halt. So a Plan that creates an item must set the matching
// field.
type Change struct {
	OpID     string
	Kind     string // create | edit | rename | trash | untrash | merge | tag | detach | tag-create | tag-rename | tag-trash
	NoteUUID string
	TagUUID  string
	Before   map[string]any
	After    map[string]any

	// apply does the write. For a change to an existing item it must re-read the
	// item's server timestamp right before it pushes (a stale timestamp is a
	// sync_conflict), then call Engine.pushRawAndVerify for a note or a tag that
	// exists, or Engine.pushAndVerify for a new item.
	apply func() error

	// reconcile answers one question on a RETRY: did an earlier attempt of this
	// change already reach the server? A retry is a Commit of an OpID that the
	// ledger already holds as intended or acked. A first attempt has no ledger
	// entry and never calls reconcile. Commit calls it under its lock, before any
	// push and before the cap check, so it must read the server live
	// (Client.FetchOne or Client.Fetch, never a cached view) and must not write.
	//
	//	(true,  nil)  The intended end state already holds. Commit records
	//	              verified and returns nil. No push, no budget used.
	//	(false, nil)  The end state does not hold and a push is safe. Commit
	//	              checks the cap, counts the attempt, and runs apply.
	//	(false, err)  Commit returns err. No push, no budget used. Return
	//	              ErrVerifyFailed when the target is in a state that is neither
	//	              the intended one nor the one apply starts from. For a create
	//	              that is: the uuid exists with other content. A push there is
	//	              a sync_conflict, and gosn-v2 answers it by minting a copy.
	//
	// The reason for all this: pushing a uuid the server already holds is a
	// sync_conflict, not an upsert. So a retry must never push blind.
	//
	// A Change with no reconcile cannot be retried: Commit refuses (fail closed).
	// Its first attempt is not affected.
	reconcile func() (landed bool, err error)
}
