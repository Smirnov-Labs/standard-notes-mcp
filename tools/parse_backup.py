"""Parse an SN decrypted backup JSON. Prints ONLY structure/counts and tag labels —
never note titles or bodies (except a few non-sensitive sanity titles passed as args).

Usage: python3 -I parse_backup.py <backup.txt> [sanity-title-substr ...]
"""
import json, sys
from collections import Counter

path = sys.argv[1]
sanity = sys.argv[2:]
data = json.load(open(path, encoding="utf-8"))
items = data.get("items", data if isinstance(data, list) else [])

by_type = Counter(i.get("content_type", "?") for i in items)
notes = [i for i in items if i.get("content_type") == "Note"]
tags = [i for i in items if i.get("content_type") == "Tag"]

def content(i):
    c = i.get("content")
    return c if isinstance(c, dict) else {}

live = [n for n in notes if not content(n).get("trashed")]
trashed = [n for n in notes if content(n).get("trashed")]

# tag -> set of referenced note uuids
note_uuids = {n.get("uuid") for n in notes}
tag_members = {}
exported_set = set()
for t in tags:
    title = (content(t).get("title") or "").strip()
    refs = {r.get("uuid") for r in content(t).get("references", []) if r.get("uuid") in note_uuids}
    tag_members.setdefault(title, set()).update(refs)
    if title.lower() == "exported":
        exported_set |= refs

live_uuids = {n.get("uuid") for n in live}
uncaptured = live_uuids - exported_set

print(f"items: {dict(by_type)}")
print(f"notes: {len(notes)} ({len(live)} live, {len(trashed)} trashed)")
print(f"live notes: {len(live_uuids)}; exported-tagged: {len(exported_set & live_uuids)}; UNCAPTURED (live, not exported): {len(uncaptured)}")
print("\ntags (live-note members):")
for title in sorted(tag_members, key=lambda t: -len(tag_members[t] & live_uuids)):
    n_live = len(tag_members[title] & live_uuids)
    n_unc = len(tag_members[title] & uncaptured)
    if n_live:
        print(f"  {title:18} live={n_live:4}  uncaptured={n_unc}")

if sanity:
    print("\nsanity (do these notes exist in the backup?):")
    titles_l = [(content(n).get("title") or "").lower() for n in notes]
    for q in sanity:
        hits = sum(1 for t in titles_l if q.lower() in t)
        print(f"  {q!r:30} -> {'FOUND '+str(hits) if hits else 'not found'}")
