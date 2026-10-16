# standard-notes-mcp

A local [MCP](https://modelcontextprotocol.io) server that lets an AI assistant
help clean up a large, end-to-end-encrypted **Standard Notes** vault, behind a
**privacy wall**. A local gate classifies every note, and the assistant sees only
the notes that the gate clears. Sensitive content (keys, seed phrases, passwords,
personal data) never leaves your machine.

We built it for one job, in October 2026. It cleaned up one personal vault of a
few thousand notes, moved the keepers to Obsidian, and left Standard Notes tidy.
We share it as-is, in case the code or the lessons help you.

- **[LEARNINGS.md](LEARNINGS.md)**: what the Standard Notes API taught us the
  hard way. Read it before you point anything at a real vault.
- **[tools/](tools/)**: a local-model pipeline that moves notes from a decrypted
  backup into Obsidian. No note content goes to a cloud model.

## Safety guarantees

- **Never permanent-delete.** Writes are Trash-only, through the reversible
  in-content `trashed` flag, never the permanent envelope `deleted`. A static
  guard test fails the build if any path could permanent-delete.
- **Metadata-safe edits.** A one-character edit keeps every other field
  byte-for-byte: stars, pins, archive and protect flags, tags, editor settings,
  and any key that a future app version adds. Proven on the real cloud and the
  official app (see `cmd/sn-canary`).
- **Privacy wall.** A local gate classifies every note: a deterministic secret
  scanner, a checksum-checked BIP-39 detector, and a local model. The assistant
  gets a sensitive note as an opaque stub with no content. The gate fails
  *closed*: if it cannot classify a note, it treats the note as sensitive.
- **You approve every write.** All 11 write tools are ask-gated and have a
  `dry_run` preview.

## How it works

| Package | Responsibility |
|---|---|
| `internal/snclient` | Auth, session guard (official-client cookie refresh), incremental sync, and the surgical **metadata-safe write path** (`rawnote.go`) |
| `internal/gate` | Sensitivity gate: scanner + BIP-39 + local model, fail-closed, content stub |
| `internal/writeengine` | Durable op ledger, conflict-safe plan/commit, additive merge, Trash-only |
| `internal/mcptools` | The MCP tool surface (4 read + 11 write) |
| `internal/obsidian` | Obsidian file layout: diary paths, append-never-overwrite |

| Command | Purpose |
|---|---|
| `cmd/sn-mcp` | The MCP server (stdio) |
| `cmd/sn-login` | Sign in once (2FA through `SN_MFA`) and save the session to the keychain |
| `cmd/sn-triage` | Read-only: classify every note with the gate and write a privacy-safe worklist |
| `cmd/sn-tag` | Put one tag (default `exported`) on a set of notes |
| `cmd/sn-export-diary` | Export diary-tagged notes to `diary/YYYY/MM/DD.md` |
| `cmd/sn-export-ideas` | Export notes to Obsidian folders from a routing map |
| `cmd/sn-seed` | Seed demo or test data into an account |
| `cmd/sn-canary` | Prove metadata preservation on a live account |
| `cmd/sn-verify` | Check that a restored account matches a decrypted export |

## Tools

**Read** (auto-allowed, read-only): `notes_search`, `notes_list`, `notes_get`,
`tags_list`.

**Write** (ask-gated, each with `dry_run`): `note_edit`, `note_rename`,
`note_trash`, `note_untrash`, `note_merge`, `tag_apply`, `tag_detach`,
`tag_create`, `tag_rename`, `tag_trash`, `tag_merge`.

## Requirements

- Go 1.27+
- A Standard Notes server: the official cloud (`https://api.standardnotes.com`) or
  a self-hosted one (see `ops/docker/README.md`).
- A **local sensitivity model** for the gate's model tier. The gate posts each
  note to `$TYPESAFE_BASE_URL/v1/systemone` (default `http://127.0.0.1:11434`)
  and reads back the probability that the note is sensitive. We ran `nimble`, a
  local model with that API, under Ollama. Any local service with the same API
  works. Do not point it at a hosted service, because that service then gets
  your notes. Without a model, the gate fails closed and every note comes back
  as a stub.

## Quick start

```sh
# 1. Build the server
go build -o ./bin/sn-mcp ./cmd/sn-mcp

# 2. Register it with Claude Code (both files are gitignored; they can hold creds)
cp config/mcp.sample.json .mcp.json          # then fill in your account
cp config/settings.sample.json .claude/settings.json
```

`config/README.md` covers how to sign in with no password in any file, the
permission rules, and the limits of the setup.

### Environment

| Var | Purpose |
|---|---|
| `SN_SERVER` | Server URL (default `http://localhost:3000`; cloud is `https://api.standardnotes.com`) |
| `SN_EMAIL`, `SN_PASSWORD` | Sign-in credentials |
| `SN_MFA` | 2FA code, if the account has it |
| `SN_SESSION_REF` | Keychain name of a saved session (instead of email and password) |
| `TYPESAFE_BASE_URL` | Sensitivity-model endpoint (default `http://127.0.0.1:11434`) |
| `SN_LEDGER` | Write-ledger path (default under your user config dir) |
| `SN_MAX_WRITES` | Safety cap on writes per run (default 1000) |
| `OBSIDIAN_VAULT` | Vault root for the export commands and `tools/` |

## Testing without your real account

```sh
# Seed a throwaway account (local Docker server, or a cloud test account)
SN_SERVER=... SN_EMAIL=... SN_PASSWORD=... go run ./cmd/sn-seed

# Prove that an edit keeps all metadata on a live account
SN_SERVER=... SN_EMAIL=... SN_PASSWORD=... go run ./cmd/sn-canary <note-uuid>

# Run the test suite. Integration tests use a self-hosted server at :3000 and
# skip when it is down.
go test ./...
```

## Before you run it on a real vault

Read [LEARNINGS.md](LEARNINGS.md), at least the checklist at the end. Short
version:

1. Download a full decrypted backup first.
2. Rehearse on a throwaway cloud account.
3. Check the account that you signed in to.
4. Work in small, reversible batches, under the rate limit.

## License

MIT. See [LICENSE](LICENSE).
