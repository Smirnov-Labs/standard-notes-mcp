"""Extract ALL uncaptured (live, not exported, not trashed) notes from an SN decrypted
backup, EXCLUDING any note tagged with one of the excluded tags. For the personal
remainder after the public collections are done. Writes a bodies JSONL; prints only a
count + the per-tag spread (tag labels, not titles).

Usage: python3 -I extract_remaining.py <backup.txt> <out.jsonl> <exclude1,exclude2,...>
"""
import json, sys
from collections import Counter

path, outp = sys.argv[1], sys.argv[2]
exclude = {t.strip().lower() for t in (sys.argv[3] if len(sys.argv) > 3 else "").split(",") if t.strip()}
data = json.load(open(path, encoding="utf-8"))
items = data.get("items", [])

def content(i):
    c = i.get("content")
    return c if isinstance(c, dict) else {}

notes = {i["uuid"]: i for i in items if i.get("content_type") == "Note" and i.get("uuid")}
tags = [i for i in items if i.get("content_type") == "Tag"]

exported = set()
excluded_notes = set()
tags_of = {}
for t in tags:
    title = (content(t).get("title") or "").strip()
    tl = title.lower()
    refs = {r.get("uuid") for r in content(t).get("references", []) if r.get("uuid") in notes}
    if tl == "exported":
        exported |= refs
    if tl in exclude:
        excluded_notes |= refs
    for u in refs:
        tags_of.setdefault(u, []).append(title)

rows = []
for u, n in notes.items():
    c = content(n)
    if c.get("trashed") or u in exported or u in excluded_notes:
        continue
    text = c.get("text") or ""
    rows.append({
        "uuid": u, "title": c.get("title") or "", "text": text, "text_len": len(text),
        "date": n.get("created_at") or "", "tags": tags_of.get(u, []),
    })

with open(outp, "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

spread = Counter(t for r in rows for t in (r["tags"] or ["(untagged)"]))
print(f"remainder: {len(rows)} uncaptured notes -> {outp}")
print("tag spread (labels only):")
for t, n in spread.most_common():
    print(f"  {t:18} {n}")
