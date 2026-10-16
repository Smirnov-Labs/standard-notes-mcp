"""Write Obsidian files from an SN backup's extracted bodies, matching the format of
cmd/sn-export-ideas (frontmatter + '## <title>' + body; append-never-overwrite). Used
for notes that don't sync to our session, so content comes from the local backup.

Usage: OBSIDIAN_VAULT=<vault> python3 -I export_backup.py <bodies.jsonl> <routing.json> [--apply] [--quiet]
  routing.json: {uuid: {dest, slug?, title?}}; bodies.jsonl: {uuid,title,text,date}
"""
import json, os, re, sys

VAULT = os.environ.get("OBSIDIAN_VAULT")
if not VAULT:
    sys.exit("set OBSIDIAN_VAULT to the root of your Obsidian vault")
VAULT = os.path.expanduser(VAULT)

def slugify(t):
    s = re.sub(r"[^a-z0-9]+", "-", (t or "").lower()).strip("-")
    return s[:50] or "note"
DEST_FOLDER = {
    "journeys": "journeys", "health": "personal/health", "nsfw": "personal/nsfw",
    "musings": "personal/musings", "book": "notes/book", "blog": "blog", "idea": "idea",
    "people": "people", "reference": "reference", "project": "project",
    "personal": "personal", "personal-medical": "personal/medical", "personal-nsfw": "personal/nsfw",
}
DEST_TAG = {
    "journeys": "journey", "health": "health", "nsfw": "nsfw", "musings": "musing",
    "book": "book-notes", "blog": "blog", "idea": "idea", "people": "person",
    "reference": "reference", "project": "project", "personal": "personal",
    "personal-medical": "medical", "personal-nsfw": "nsfw",
}
PRIVATE = {"journeys", "health", "nsfw", "musings", "personal", "personal-medical", "personal-nsfw"}

bodies_path, routing_path = sys.argv[1], sys.argv[2]
apply = "--apply" in sys.argv[3:]
quiet = "--quiet" in sys.argv[3:]

bodies = {}
for l in open(bodies_path, encoding="utf-8"):
    if l.strip():
        r = json.loads(l)
        bodies[r["uuid"]] = r
routing = json.load(open(routing_path))

def by_date(d):
    m = re.match(r"(\d{4}-\d{2}-\d{2})", d or "")
    return m.group(1) if m else "undated"

def diary_rel(date):
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", date or "")
    return (f"diary/{m.group(1)}/{m.group(2)}/{m.group(3)}.md", f"{m.group(1)}-{m.group(2)}-{m.group(3)}") if m else (None, None)

def title_lead(title, heading):
    t = (title or "").strip()
    return "" if (not t or t == heading) else "**" + t + "**"

created = appended = skipped = missing = 0
counts = {}
for uuid, r in routing.items():
    dest = r["dest"]
    b = bodies.get(uuid)
    if not b:
        missing += 1
        continue
    title = b.get("title") or "untitled"
    body = (b.get("text") or "").rstrip("\n")

    # Diary: date-based path diary/YYYY/MM/DD.md with a dated heading + bold title lead,
    # append-never-overwrite (matches internal/obsidian). Undated diary notes fall back
    # to the flat personal folder so nothing is dropped.
    if dest == "diary":
        rel, heading = diary_rel(b.get("date"))
        if rel is None:
            dest = "personal"
        else:
            path = os.path.join(VAULT, rel)
            existing = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
            if body and body in existing:
                action, skipped = "SKIP", skipped + 1
            elif not existing:
                action, created = "CREATE", created + 1
            else:
                action, appended = "APPEND", appended + 1
            counts["diary"] = counts.get("diary", 0) + 1
            if not quiet:
                print(f"  {'diary':16} {title[:38]:38} -> {rel:42} [{action}]")
            if apply and action != "SKIP":
                os.makedirs(os.path.dirname(path), exist_ok=True)
                lead = title_lead(title, heading)
                lead = (lead + "\n\n") if lead else ""
                if action == "APPEND":
                    out = existing.rstrip("\n") + f"\n\n## {heading} (imported from Standard Notes)\n\n" + lead + body + "\n"
                else:
                    out = "---\nprivate: true\ntags:\n  - diary\n---\n\n" + f"## {heading}\n\n" + lead + body + "\n"
                open(path, "w", encoding="utf-8").write(out)
            continue

    folder = DEST_FOLDER.get(dest)
    if folder is None:
        print(f"  SKIP unknown dest {dest!r}")
        continue
    # slug from the routing map, else from the note's own title (computed locally so a
    # quiet/personal run gets readable filenames without any title reaching the terminal).
    slug = r.get("slug") or slugify(title)
    name = slug + ".md"
    rel = os.path.join(folder, name)
    path = os.path.join(VAULT, rel)
    existing = ""
    if os.path.exists(path):
        existing = open(path, encoding="utf-8").read()
    if body and body in existing:
        action, skipped = "SKIP", skipped + 1
    elif not existing:
        action, created = "CREATE", created + 1
    else:
        action, appended = "APPEND", appended + 1
    counts[dest] = counts.get(dest, 0) + 1
    if not quiet:
        print(f"  {dest:16} {title[:38]:38} -> {rel:42} [{action}]")
    if apply and action != "SKIP":
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if action == "APPEND":
            out = existing.rstrip("\n") + "\n\n## " + title + "\n\n" + body + "\n"
        else:
            fm = "---\n" + ("private: true\n" if dest in PRIVATE else "") + "tags:\n  - " + DEST_TAG[dest] + "\n---\n\n"
            out = fm + "## " + title + "\n\n" + body + "\n"
        open(path, "w", encoding="utf-8").write(out)

print(f"\n{'APPLIED' if apply else 'DRY-RUN'}: {len(routing)} notes -> {created} new, {appended} appends, {skipped} skipped, {missing} missing-body")
for d in sorted(counts):
    print(f"  {d:16} {counts[d]}")
