# Learnings

In October 2026 we used this repo to clean up one real, end-to-end-encrypted
Standard Notes vault of a few thousand notes. These are the lessons that cost us
the most time. Each one is something we saw, not a guess. Where we did not find a
cause, we say so.

Setup: protocol 004, the official cloud (`api.standardnotes.com`), the official
apps, and the [gosn-v2](https://github.com/jonhadfield/gosn-v2) Go library.

## 1. One gosn-v2 call makes notes unreadable in the app

gosn-v2 has two encrypt paths. Only one of them makes item keys that the
official app can read.

| Path | Item key | In the official app |
|---|---|---|
| `c.Push` → `(*Items).Encrypt` → `EncryptItem` | `GenerateItemKey(64)`: 32 bytes | opens |
| `(DecryptedItem).Encrypt`, `ReEncryptItem` | `GenerateItemKey(32)`: 16 bytes | `errorDecrypting` |

`GenerateItemKey(n)` counts hex characters, not bytes. gosn-v2 reads its own
16-byte keys back, so its round trip looks fine. The app needs a 256-bit key and
shows the note as `errorDecrypting`. Nothing fails when you write. You find out
when you open the note.

- Never call `(DecryptedItem).Encrypt` or `ReEncryptItem`.
- After each write, read the item back. Check that the item key is 32 bytes and
  that the content round-trips.

## 2. Never round-trip the typed note struct

The typed gosn-v2 note struct does not model every field. A round trip through
it (decrypt, change the text, encrypt) drops each field that it does not model.
That includes stars, the archive flag, third-party `appData`, and any key that a
later app version adds.

The safe edit is surgical (`internal/snclient/rawnote.go`):

1. Fetch the raw item. Decrypt its content into a `map[string]json.RawMessage`.
2. Change only the keys you mean to change. Set `client_updated_at`.
3. Encrypt with a 32-byte item key. Push.
4. Read the item back and compare.

`cmd/sn-canary` proves this on a live account. It sets starred, protected,
pinned and archived, edits the text, and diffs the decrypted content. Only
`text` and `client_updated_at` can change.

## 3. Trash with `trashed`, never `deleted`

There are two ways to remove a note.

| Flag | Effect | Undo |
|---|---|---|
| `content.trashed = true` | The note moves to the app's Trash. | Restore it in the app. |
| envelope `deleted = true` | The server erases the content. | None. |

This server writes only `trashed`. A static test fails the build if any code
path sets `deleted`. The final purge is a manual step in the app.

## 4. Where the flags live

| Data | Location |
|---|---|
| trashed, starred, protected | top level of the decrypted `content` |
| pinned, archived | `content.appData["org.standardnotes.sn"]` |
| tag membership | on the tag, not the note: `tag.content.references` lists note uuids |

This has two results:

- An edit to a note does not touch its tags.
- One tag write can add or remove hundreds of notes. That makes tags the cheap
  way to do bulk work (see section 5).

The app does not hide a trashed tag. Remove it by hand.

## 5. The rate limit covers the whole account

The cloud limits bandwidth per account, not per client. Over the limit, the
server answers HTTP 429: "exceeded maximum bandwidth in a 5-minute period". The
official web app then hits the same wall. A mass archive in the web app failed
for us this way.

What we saw:

- A full sync of a few thousand notes uses a large share of the budget.
- After the limit tripped, one write went through after about 70 minutes of
  rest. Three writes in a row tripped it again.
- Per-note writes do not scale to thousands of notes. Tag the notes (one write
  per tag), then act on the tag in the app. Large selections in the app hit the
  same limit.

The self-hosted Docker server has no rate limit, so it cannot rehearse this.

## 6. A failed write can still land

After a 429 or a timeout, this server can report a failure although the push
reached Standard Notes. The error says: "could not finish the write to Standard
Notes; read the item again to see whether it changed". A blind retry then
applies the change twice. That is how we got two tags with the same title. The
first create "failed", and the retry made a second one.

- Make writes idempotent. The tag writes here compute a union, so a repeat does
  no harm.
- After an error, read the item back before you retry.
- Before you retry a create, look for the item by title.
- `tag_merge` cleans up a duplicate tag. It moves the notes to the keeper and
  trashes the copy.

## 7. A full sync can skip notes with no error

Our session's full sync came back a few hundred notes short of the app's
decrypted backup. The missing notes were the oldest ones. They did not arrive at
all: not as ciphertext, and not as decrypt errors.

We ruled out four causes:

- Pagination. A loop on the cursor changed nothing.
- The rate limit. The count was the same on every run.
- Decryption. Nothing failed.
- A stale sync token. Each run was a fresh full sync.

We did not find the cause.

- Do not treat a full sync as the whole vault. Compare its note count with the
  app or a backup before you call a job done.
- For read-only work, the app's decrypted backup is the ground truth. The
  scripts in `tools/` work from it.

## 8. Check which account you are in

A stale config signed us in to a second account, with 23 notes, and nothing
failed. The note count gave it away. Print the account email and the note count
at sign-in. Check both before any write.

With 2FA on, sign in once with `cmd/sn-login`. It saves the session to the
keychain, so later runs need no code. The session lasts about 30 days.

## 9. The privacy wall, and where it falls short

The gate decides which notes the assistant can see.

1. Tier 0 is deterministic: a secret scanner, and a BIP-39 seed-phrase
   detector that checks the checksum. A model scored a bare seed phrase at
   0.04, so a model alone is not a defense.
2. Some kinds are always sensitive: `authentication` and `credential`.
3. Tier 1 is a local model that returns a probability. A long note goes in
   overlapping windows, and the highest score decides.
4. The gate fails closed. An error, a NaN or a missing answer means
   "sensitive".
5. A sensitive note reaches the assistant as a stub: the uuid and a fixed
   label. It has no title and no text.
6. `note_edit`, `note_rename` and `note_merge` refuse a sensitive note. Each
   would make the assistant write content that it cannot see.

The model tier has false negatives. For bulk work on private notes (diaries,
health, relationships), we did not rely on the gate. We ran a local model over
the notes and printed only counts, so the content never left the machine. That
is the `--quiet` mode in `tools/`.

## 10. Local models for triage

- `gpt-oss` (20B) made the best keep-or-junk calls of the local models we
  tried. It took 5 to 20 seconds per note on an Apple Silicon Mac.
- Use temperature 0 and JSON output.
- Judge the body, not the title. Titles are often dates or junk.
- Take pinned notes out before any junk sweep. Our first sweep caught pinned
  working notes.
- A first pass keeps too much. A second pass with a strict prompt ("keep only
  what you would miss") trims the list.

## 11. Exporting to Obsidian

- Append. Never overwrite. Skip a note whose body is already in the target
  file, so a rerun is safe.
- A dry run cannot see two notes in one batch that land in the same file.
  Expect a few more appends when you apply. Nothing is lost.
- File diary notes by created date: `diary/YYYY/MM/DD.md`.
- Tag each exported note in Standard Notes (we used `exported`), so that the
  next pass skips it.

## Before you run this on a real vault

1. Download a full decrypted backup from the official app. Open it and check it.
2. Rehearse on a throwaway cloud account. Create, edit (run `cmd/sn-canary`),
   trash, untrash, and use each tag tool. Open the results in the official app.
3. Sign in to the real account. Check the email and the note count.
4. Stage changes with `cleanup/*` tags. Trash only. Purge by hand in the app at
   the end.
5. Work in small, reversible batches, and stay under the rate limit.
