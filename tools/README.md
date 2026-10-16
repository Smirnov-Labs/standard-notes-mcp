# tools

Python scripts that move notes from a Standard Notes decrypted backup into an
Obsidian vault. A local model (through Ollama) decides where each note goes. No
note content goes to a cloud model.

We wrote these because our API session could not see a few hundred old notes
(see [LEARNINGS.md](../LEARNINGS.md), section 7). The app's decrypted backup
could.

## Safety

- The backup and every file these scripts write hold your notes as plain text.
  Keep them in `.local/` (gitignored) or outside the repo. Delete them when you
  finish.
- Run each script with `python3 -I`. Then Python does not import modules from the
  folder that holds the backup.
- The scripts print counts and tag names, not note text. Three print titles:
  `extract_collection.py --titles`, `fixed_map.py`, and `classify.py` without
  `--quiet`. Use those only on notes you are fine to show, for example when an AI
  assistant can see your terminal.
- `export_backup.py` creates and appends. It never overwrites. It skips a note
  whose body is already in the target file. Without `--apply` it changes nothing.

## Requirements

- Python 3, standard library only. Tested on 3.14.
- For `classify.py`: [Ollama](https://ollama.com) on `127.0.0.1:11434`, with a
  model pulled. We used `gpt-oss:20b`.
- For `export_backup.py`: `OBSIDIAN_VAULT` set to the root of your vault.

## Get the backup

In the Standard Notes app, open Preferences > Backups and download a decrypted
backup. Unzip it into a new, empty folder. The scripts read the file
`Standard Notes Backup and Import File.txt`.

## The scripts

| Script | What it does |
|---|---|
| `parse_backup.py` | Counts items, live and trashed notes, and notes per tag. Shows how many live notes have no `exported` tag. |
| `extract_collection.py` | Writes the live, not-yet-exported notes of one tag to a JSONL file. |
| `extract_remaining.py` | Writes every other live, not-yet-exported note, minus the tags you exclude. |
| `fixed_map.py` | Sends a whole collection to one destination, for example book notes to `book`. |
| `classify.py` | Asks a local model where each note goes, or whether it is junk. Writes a routing map. |
| `export_backup.py` | Writes the Obsidian files from a JSONL file and a routing map. |

A note counts as exported when it has a tag named `exported`. That was our
marker for notes that we had already moved. The extract scripts skip those notes
and all trashed notes.

## Example run

```sh
B=".local/backup/Standard Notes Backup and Import File.txt"
export OBSIDIAN_VAULT=~/obsidian

python3 -I tools/parse_backup.py "$B"

# A collection you are fine to show: one fixed destination
python3 -I tools/extract_collection.py "$B" book-notes .local/books.jsonl
python3 -I tools/fixed_map.py .local/books.jsonl book .local/books-map.json
python3 -I tools/export_backup.py .local/books.jsonl .local/books-map.json          # dry run
python3 -I tools/export_backup.py .local/books.jsonl .local/books-map.json --apply

# Everything else: a local model routes each note, and only counts are printed
python3 -I tools/extract_remaining.py "$B" .local/rest.jsonl book-notes,cleanup/junk
python3 -I tools/classify.py .local/rest.jsonl .local/rest-map.json gpt-oss:20b --gold-route --quiet
python3 -I tools/export_backup.py .local/rest.jsonl .local/rest-map.json --apply --quiet
```

## classify.py modes

| Flag | The model decides | Output |
|---|---|---|
| (none) | keep or leave, and a destination | `{uuid: {dest, slug, title}}` |
| `--gold-route` | the same, under a strict privacy rule | the same |
| `--hybrid` | a destination only; every note is kept | the same |
| `--sensitive` | keep or leave, private destinations only | the same |
| `--rescue` | `KEEP_PRIVATE`, `KEEP_SN` or `JUNK`, for notes flagged as junk | a private-export map, plus `<out>.detach.json` |
| `--rescue-strict` | keep only notes with clear, lasting value | `{uuid: {}}` for the keepers |

With `--quiet`, the routing map holds only `{dest}`. `export_backup.py` then makes
each file name from the note title on your machine, and no title reaches the
terminal.

The privacy rule sends intimate content to `personal-nsfw`, medical content to
`personal-medical` or `health`, and relationship content to `personal` or
`diary`. It never sends them to a shared folder.

## Destinations

| `dest` | Folder | `private: true` |
|---|---|---|
| `diary` | `diary/YYYY/MM/DD.md`, by created date | yes |
| `personal` | `personal/` | yes |
| `personal-medical` | `personal/medical/` | yes |
| `personal-nsfw`, `nsfw` | `personal/nsfw/` | yes |
| `health` | `personal/health/` | yes |
| `musings` | `personal/musings/` | yes |
| `journeys` | `journeys/` | yes |
| `book` | `notes/book/` | no |
| `blog` | `blog/` | no |
| `idea` | `idea/` | no |
| `people` | `people/` | no |
| `reference` | `reference/` | no |
| `project` | `project/` | no |

A private destination adds `private: true` to the frontmatter of the file. To
change the folders, edit `DEST_FOLDER` in `export_backup.py`.
