# standard-notes-mcp

A local [MCP](https://modelcontextprotocol.io) server that lets an AI assistant
help clean up a large, end-to-end-encrypted Standard Notes vault, with a privacy
wall in between. A local gate classifies every note, and the assistant sees only
the notes it clears. Sensitive content (keys, seed phrases, passwords, personal
data) never leaves your machine.

We built it in October 2026 to clean up one personal vault of a few thousand
notes and move the keepers to Obsidian, and it did that job. We're sharing it
as-is, in case the code or the lessons help you.

- [LEARNINGS.md](LEARNINGS.md) covers the Standard Notes behavior that cost us
  the most time. Read it before you point anything at a real vault.
- [tools/](tools/) holds a pipeline that moves notes from a decrypted backup into
  Obsidian. A local model does the sorting, so no note content goes to a cloud
  model.

## Safety guarantees

- Writes never delete anything for good. They set only the in-content `trashed`
  flag, which moves a note to the app's Trash, where you can restore it. Nothing
  sets the envelope `deleted` flag, and a static test fails the build if any
  code path could.
- A one-character edit leaves every other field byte for byte the same: stars,
  pins, archive and protect flags, tags, editor settings, and any key a future
  app version adds. `cmd/sn-canary` checks this on a live account, and we
  confirmed it on the real cloud with the official app.
- A deterministic secret scanner, a BIP-39 detector that verifies the checksum,
  and a local model classify every note. The assistant gets a sensitive note as
  a stub with no content. The gate fails closed: if it can't classify a note, it
  treats the note as sensitive.
- With the sample settings, Claude Code asks you before every write, and each of
  the 11 write tools has a `dry_run` preview.

## Code layout

| Package | Responsibility |
|---|---|
| `internal/snclient` | Auth, session guard (official-client cookie refresh), incremental sync, and the surgical metadata-safe write path (`rawnote.go`) |
| `internal/gate` | Sensitivity gate (scanner, BIP-39 check, local model); fails closed and returns stubs |
| `internal/writeengine` | Durable op ledger, conflict-safe plan and commit, additive merge, Trash-only writes |
| `internal/mcptools` | The MCP tools (4 read, 11 write) |
| `internal/obsidian` | Obsidian file layout (diary paths) and append-only writes |

| Command | Purpose |
|---|---|
| `cmd/sn-mcp` | The MCP server (stdio) |
| `cmd/sn-login` | Signs in once (2FA through `SN_MFA`) and saves the session to the keychain |
| `cmd/sn-triage` | Read-only: classifies every note with the gate and writes a privacy-safe worklist |
| `cmd/sn-tag` | Puts one tag (default `exported`) on a set of notes |
| `cmd/sn-export-diary` | Exports diary-tagged notes to `diary/YYYY/MM/DD.md` |
| `cmd/sn-export-ideas` | Exports notes to Obsidian folders from a routing map |
| `cmd/sn-seed` | Seeds demo or test data into an account |
| `cmd/sn-canary` | Proves on a live account that an edit keeps the metadata |
| `cmd/sn-verify` | Checks that a restored account matches a decrypted export |

## Tools

Four read-only tools run without asking: `notes_search`, `notes_list`,
`notes_get` and `tags_list`.

Eleven write tools ask first, and each takes a `dry_run` flag: `note_edit`,
`note_rename`, `note_trash`, `note_untrash`, `note_merge`, `tag_apply`,
`tag_detach`, `tag_create`, `tag_rename`, `tag_trash` and `tag_merge`.

## Requirements

- Go 1.27+
- A Standard Notes server: the official cloud (`https://api.standardnotes.com`) or
  a self-hosted one (see `ops/docker/README.md`).
- A local sensitivity model for the gate. The gate posts each note to
  `$TYPESAFE_BASE_URL/v1/systemone` (default `http://127.0.0.1:11434`) and reads
  back the probability that the note is sensitive. We ran `nimble`, a local model
  with that API, under Ollama; any local service with the same API works. Don't
  point it at a hosted service, since that service would then receive your notes.
  Without a model the gate fails closed, and every note comes back as a stub.

## Quick start

```sh
# 1. Build the server
go build -o ./bin/sn-mcp ./cmd/sn-mcp

# 2. Register it with Claude Code (both files are gitignored; they can hold creds)
cp config/mcp.sample.json .mcp.json          # then fill in your account
cp config/settings.sample.json .claude/settings.json
```

`config/README.md` explains how to sign in without putting your password in any
file. It also covers the permission rules and the limits of this setup.

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

The full checklist is at the end of [LEARNINGS.md](LEARNINGS.md). The short
version:

1. Download a full decrypted backup first.
2. Rehearse on a throwaway cloud account.
3. Check which account you're signed in to.
4. Work in small, reversible batches, and stay under the rate limit.

## License

MIT. See [LICENSE](LICENSE).
