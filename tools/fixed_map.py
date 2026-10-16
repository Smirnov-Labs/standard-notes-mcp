"""Build a routing map for a whole curated collection -> one Obsidian dest.
Reads a bodies JSONL ({uuid,title,...}) and writes {uuid: {dest, slug, title}}.
For PUBLIC collections only (it prints titles). Skips empty titles' slug via fallback.

Usage: python3 -I fixed_map.py <bodies.jsonl> <dest> <out-map.json>
"""
import json, re, sys

def slugify(t):
    s = re.sub(r"[^a-z0-9]+", "-", (t or "").lower()).strip("-")
    return s[:50] or "note"

inp, dest, outp = sys.argv[1], sys.argv[2], sys.argv[3]
rows = [json.loads(l) for l in open(inp, encoding="utf-8") if l.strip()]
out = {}
print(f"routing {len(rows)} notes -> {dest}:")
for r in rows:
    title = r.get("title", "") or "(untitled)"
    out[r["uuid"]] = {"dest": dest, "slug": slugify(r.get("title", "")), "title": r.get("title", "")}
    print(f"  - {title[:70]}  ({r.get('text_len','?')} chars)")
json.dump(out, open(outp, "w"), indent=2)
print(f"\nwrote {len(out)} -> {outp}")
