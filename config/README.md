# Register sn-mcp with Claude Code

This is a personal, local setup. Claude reaches your notes only through the `standard-notes` MCP tools. Four read (`notes_search`, `notes_list`, `notes_get`, `tags_list`). Eleven write (`note_edit`, `note_rename`, `note_trash`, `note_untrash`, `note_merge`, `tag_apply`, `tag_detach`, `tag_create`, `tag_rename`, `tag_trash`, `tag_merge`). A sensitive note comes back as a stub: a uuid and a fixed label. It has no title, text or snippet. The preview of a write follows the same rule. A trash or untrash of a sensitive note shows the stub. An edit, a rename and a merge refuse a sensitive note with an error. Each would make Claude author or copy content that it cannot see. Claude Code denies the main session access to the folder where decrypted exports and local indexes live. So Claude cannot read around the gate.

No tool deletes anything for good. A trash is a flag inside the note, and `note_untrash` clears it. A merge makes a new note and trashes the sources. Each write tool takes `dry_run`: with it set to true, the tool writes nothing and returns what would change.

## 1. Build

```
go build -o bin/sn-mcp ./cmd/sn-mcp
```

`bin/` is git-ignored.

## 2. Sign in once

sn-mcp signs in when it starts. If it cannot, it prints the reason on stderr and exits.

| Variable | Meaning |
| --- | --- |
| `SN_SERVER` | API URL. The default is `http://localhost:3000`, the Docker test server. The hosted service is `https://api.standardnotes.com`. |
| `SN_SESSION_REF` | Name of a session in your keychain. If the keychain holds one, sn-mcp restores it. After a password sign-in, sn-mcp saves the session under this name. |
| `SN_EMAIL`, `SN_PASSWORD` | Used to sign in when there is no saved session. |
| `SN_MFA` | A current 2FA code, if the account has 2FA. A code lasts about 30 seconds. |
| `TYPESAFE_BASE_URL` | The jev (nimble) service for the sensitivity gate. The default is `http://127.0.0.1:11434`. |
| `SN_LEDGER` | The file for the write ledger: one JSON line for each step of each write, with the op id, the kind, a uuid and the state. It holds no note content. The default is `standard-notes-mcp/ledger.jsonl` in your config directory (`~/Library/Application Support` on macOS). sn-mcp makes the folder, private to you. |
| `SN_MAX_WRITES` | The most writes in one run of the server. The default is 1000. A write past it is refused, and a restart starts the count again. `0` refuses every write, and a dry run still works. A value that is not a whole number stops the server. |

Keep the password out of any file that Claude can read. That includes `.mcp.json`, settings files and your shell history. Sign in once in a terminal. The session goes into your keychain:

```
printf 'Password: '; read -rs SN_PASSWORD; echo; export SN_PASSWORD
SN_SERVER=https://api.standardnotes.com SN_EMAIL=you@example.com \
  SN_SESSION_REF=sn-main ./bin/sn-mcp < /dev/null
```

sn-mcp logs `signed in` and `saved the session as "sn-main"`, and then it exits. After that, register it with only `SN_SESSION_REF` and `SN_SERVER`.

## 3. Register

Copy `mcp.sample.json` to `.mcp.json` in the folder where you run `claude`. Add `SN_SERVER` to its `env` for any server except the Docker one. If you run `claude` from outside this repo, change `command` to the absolute path of `bin/sn-mcp`. Claude Code asks you to approve a project `.mcp.json` server the first time.

The CLI does the same:

```
claude mcp add standard-notes -e SN_SESSION_REF=sn-main -e SN_SERVER=https://api.standardnotes.com -- /abs/path/to/bin/sn-mcp
```

## 4. Sandbox

Merge `settings.sample.json` into `.claude/settings.json` (this project) or `~/.claude/settings.json` (all projects). The `allow` lines let Claude call the four read tools without a prompt. The `ask` lines make Claude Code ask you before each of the ten write tools, and a dry run asks too. Keep them under `ask`: a write tool in `allow` writes without your say.

Replace `<DATA_PATH>` with the absolute path of the folder for decrypted exports and local indexes. Keep that folder outside this repo. Drop the leading slash, because `//` is the filesystem root in a permission rule: `/Users/me/sn-data` becomes `Read(//Users/me/sn-data/**)`.

The deny rules cover Claude's Read, Edit and Write tools. They also cover the Bash file commands that Claude Code recognizes, such as `cat`, `head`, `tail`, `sed`, `tee` and redirections. They do not cover a script that opens the file itself (`python`, `node`), or `grep -r` run inside the folder. To block those at the OS level, turn on Claude Code's sandbox (`/sandbox`) and add the folder to `sandbox.filesystem.denyRead`. There, a plain absolute path is correct: `/Users/me/sn-data`.

The MCP server runs outside both controls. It is the one process that reads the vault.

## 5. Check

1. Run `/mcp` in Claude Code. `standard-notes` must show as connected.
2. Ask Claude to call `notes_list`. It returns 50 rows by default. `limit` (up to 500) and `offset` page through the rest, in uuid order.
3. Ask Claude to `Read` a file under the data folder. Claude Code must deny the read.
4. Ask Claude to call `note_trash` with `dry_run` true on a note. Claude Code must ask you first. The result shows the note and says nothing was written. Then call `notes_get` on a sensitive note's uuid, and `note_trash` with `dry_run` true on it: both show only the stub. `note_edit` on that uuid must fail with `cannot edit a sensitive note; it is walled off from the assistant`, in a dry run too.

## Know before you test

- Each tool call syncs the whole vault live, so a 20k-note vault takes time on every call. The gate runs only on the notes in the page, and it caches each verdict.
- If every note is a stub, jev is down or too slow, and the gate fails closed. nimble can need more than 20 seconds to load its model after it has been idle, and the gate gives up at 20 seconds. A jev failure is not cached, so call again.
- A write tool reads the whole vault several times (before the change, to write it, and to check it), so one write takes several times as long as a read. A merge of N notes takes about 7N such reads.
- `tag_trash` marks the tag trashed and nothing more. The official app does not hide a trashed tag, so the tag still shows there. Remove it by hand in the app. No tool of this server deletes a tag, and none clears the mark.
- Two writers can overwrite each other. A change sets its field whatever the note holds when the write runs, so an edit of the same field that you make in the app between a dry run and the write is lost. A real vault needs a version check here. This server does not have one.
- The saved session sits in your login keychain, under the service `standard-notes-mcp`. Any shell command can read it with `security find-generic-password`, and with it the whole vault. The deny rules keep Claude's own tools out. They do not stop a determined shell, so keep Bash on approval prompts.
