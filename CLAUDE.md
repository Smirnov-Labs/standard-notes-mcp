# CLAUDE.md — standard-notes-mcp

Guidance for working in this repo. It is a **local-only** tool, built to clean up
one large Standard Notes vault once and then maintain it.
**Don't over-engineer** — reserve maximum rigor for the data-loss and
privacy-leak paths below, and drive everything else to "ready for testing."

## Prime directives — never violate

1. **Never permanent-delete.** Trash-only (reversible content `trashed` flag),
   never the envelope `deleted` flag. Guarded by a static test.
2. **Never lose data.** Merges are additive; cleanup is staged via `cleanup/*`
   tags; everything is reversible until the user's manual purge in the app.
3. **Hybrid privacy — sensitive content must NEVER reach the assistant or
   Anthropic.** The gate (`internal/gate`) stubs sensitive notes. Never bypass,
   weaken, or work around it. `note_edit` / `note_rename` / `note_merge` refuse a
   sensitive note by design.
4. **Metadata-safe writes only.** Edit existing items through the surgical path
   (`internal/snclient/rawnote.go`: `FetchRawOne` → `EncryptMutated` →
   `PushEncrypted`), which mutates only the named keys in a
   `map[string]json.RawMessage` and sets `client_updated_at`. **Never** round-trip
   the typed gosn-v2 struct to edit — it silently drops unmodeled fields (stars,
   archive, third-party appData, future keys).
5. **Crypto trap — never call `(DecryptedItem).Encrypt` or `ReEncryptItem`.** They
   build a 16-byte item key (`GenerateItemKey(32)` counts hex chars); the official
   app needs 256-bit and marks the note `errorDecrypting` (silent loss). Use
   `encryptRawContent` (edits) or `c.Push` / `EncryptItem` (new items) — both
   `GenerateItemKey(64)`.
6. **Don't write to the real vault** until the canary checklist passes and the user
   has a full decrypted backup. See the checklist at the end of `LEARNINGS.md`.
7. **Don't commit `.mcp.json`** (holds creds; gitignored). Don't push to any remote
   without the user asking.

## Crypto path cheat sheet

| Operation | Path | Item key | Safe? |
|---|---|---|---|
| New note / tag | `c.Push` → `(*Items).Encrypt` → `EncryptItem` | `GenerateItemKey(64)` → 32 B | ✅ |
| Edit existing | `encryptRawContent` (+ read-back verify) | `GenerateItemKey(64)` → 32 B | ✅ |
| `(DecryptedItem).Encrypt`, `ReEncryptItem` | — | `GenerateItemKey(32)` → 16 B | ❌ never |

## Build / test / tools

```sh
go build -o ./bin/sn-mcp ./cmd/sn-mcp   # the MCP server
go test ./...                            # suite; integration tests need a server at :3000, gate tests use a fake jev
go run ./cmd/sn-seed                     # seed test data (env-driven: SN_SERVER/SN_EMAIL/SN_PASSWORD)
go run ./cmd/sn-canary <note-uuid>       # prove metadata preservation on a live account
```

## Key docs

- **Overview + setup:** `README.md`, `config/README.md`
- **Lessons + pre-run checklist:** `LEARNINGS.md`
- **Backup-to-Obsidian pipeline:** `tools/README.md`
