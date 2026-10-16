"""Extract one tag's UNCAPTURED (live, not exported, not trashed) notes from an SN
decrypted backup into a bodies JSONL ({uuid,title,text,text_len,date,tags}) for local
processing. Prints a count, and (only with --titles) the titles — use that ONLY for
non-sensitive public collections.

Usage: python3 -I extract_collection.py <backup.txt> <tag> <out.jsonl> [--titles]
"""
import json, sys

path, tag, outp = sys.argv[1], sys.argv[2], sys.argv[3]
show = "--titles" in sys.argv[4:]
data = json.load(open(path, encoding="utf-8"))
items = data.get("items", [])

def content(i):
    c = i.get("content")
    return c if isinstance(c, dict) else {}

notes = {i["uuid"]: i for i in items if i.get("content_type") == "Note" and i.get("uuid")}
tags = [i for i in items if i.get("content_type") == "Tag"]

exported = set()
want_members = set()
for t in tags:
    title = (content(t).get("title") or "").strip()
    refs = {r.get("uuid") for r in content(t).get("references", []) if r.get("uuid") in notes}
    if title.lower() == "exported":
        exported |= refs
    if title.lower() == tag.lower():
        want_members |= refs

# tag titles per note (for context in the map)
tags_of = {}
for t in tags:
    title = (content(t).get("title") or "").strip()
    for r in content(t).get("references", []):
        u = r.get("uuid")
        if u in notes:
            tags_of.setdefault(u, []).append(title)

rows = []
for u in want_members:
    n = notes[u]
    c = content(n)
    if c.get("trashed") or u in exported:
        continue
    text = c.get("text") or ""
    rows.append({
        "uuid": u, "title": c.get("title") or "", "text": text, "text_len": len(text),
        "date": n.get("created_at") or "", "tags": tags_of.get(u, []),
    })

with open(outp, "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"{tag}: {len(rows)} uncaptured notes -> {outp}")
if show:
    for r in sorted(rows, key=lambda x: -x["text_len"]):
        print(f"  - {(r['title'] or '(untitled)')[:68]:68}  {r['text_len']:5} chars")
