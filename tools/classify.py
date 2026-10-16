"""Local-model gold classifier. Reads a JSONL of notes ({uuid,title,body|snippet|text}),
asks a local Ollama model per note whether it is GOLD and where it belongs, writes a
routing map, and prints a summary. With --quiet it prints ONLY counts (no titles /
reasons) — for scanning sensitive notes without their content reaching the terminal.

Usage: python3 -I classify.py <in.jsonl> <out-routing.json> <model> [mode] [--quiet]
  mode (pick one; the default is keep-or-leave plus a destination):
    --gold-route     keep-or-leave plus a destination, under a strict privacy rule
    --hybrid         destination only; every note is kept
    --sensitive      keep-or-leave, private destinations only
    --rescue         KEEP_PRIVATE / KEEP_SN / JUNK, for notes flagged as junk
    --rescue-strict  keep only notes with clear, lasting value
"""
import json, re, sys, urllib.request

def slugify(t):
    s = re.sub(r"[^a-z0-9]+", "-", (t or "").lower()).strip("-")
    return s[:40] or "note"

inp, outp, model = sys.argv[1], sys.argv[2], sys.argv[3]
quiet = "--quiet" in sys.argv[4:]
sensitive = "--sensitive" in sys.argv[4:]
hybrid = "--hybrid" in sys.argv[4:]
goldroute = "--gold-route" in sys.argv[4:]
rescue = "--rescue" in sys.argv[4:]
rescue_strict = "--rescue-strict" in sys.argv[4:]

SYS_HYBRID = """You re-file ONE personal note (already deemed worth keeping) into the single best folder.
CRITICAL privacy rule: intimate/sexual content -> personal-nsfw; relationship or private-personal content -> personal or diary; medical/body content -> personal-medical or health. NEVER put intimate, sexual, relationship, or medical content into a shared folder (reference/project/people/idea/book/blog).
Reply with ONLY JSON: {"gold": true, "dest": "<dest>", "reason": "<=8 words"}.
dest is one of: reference (how-tos/specs/links), project (work/product projects), idea (concepts), people (a non-intimate note about a person), health (fitness/training), book (reading notes), blog (writing drafts), diary (personal reflection), personal (private life), personal-medical (health/medical/body), personal-nsfw (intimate/sexual). Always set gold true; just choose the best dest, honoring the privacy rule."""

SYS_PUBLIC = """You triage ONE personal note and decide if it is GOLD worth keeping long-term in a knowledge base, vs ephemera to leave behind.
GOLD = a durable plan, hard-won insight, decision, how-to, spec, resource/link list, framework, recipe, routine, or meaningful reflection.
LEAVE = one-off logistics, a grocery/food order, scheduling, a stray number/credential, a half-finished fragment, or a duplicate.
Reply with ONLY JSON: {"gold": true|false, "dest": "<dest>", "reason": "<=10 words"}.
dest is one of: reference (how-tos/specs/links), project (work/product projects), idea (concepts), people (about a person), health (fitness/medical), book (reading notes), blog (writing drafts), diary (personal reflection), personal (private life, not fitting the others), leave (if gold is false).
Base the decision on the BODY, not the title; titles are often junk or timestamps."""

SYS_SENSITIVE = """You triage ONE private, sensitive personal note and decide if it is GOLD worth keeping long-term in a PRIVATE knowledge base, vs ephemera to leave behind. Everything here is personal; route gold to the right private folder, never discard it for being intimate or medical.
GOLD = durable private content worth retaining: a health/medical record or protocol, a meaningful personal or relationship insight, a private plan or decision, a substantive reflection, a framework or routine.
LEAVE = one-off logistics, a throwaway, a bare fragment, or a duplicate.
Reply with ONLY JSON: {"gold": true|false, "dest": "<dest>", "reason": "<=8 words"}.
dest is one of: personal-medical (health/medical/body records), personal-nsfw (intimate/sexual), diary (personal reflection), personal (other private life), health (fitness/training), leave (if gold is false).
Base the decision on the BODY, not the title."""

SYS_HYBRID_FILTER = """You triage ONE personal note: first decide if it is GOLD worth keeping long-term in a knowledge base, and if so, pick the single best folder — honoring a strict privacy rule.
GOLD = a durable plan, hard-won insight, decision, how-to, spec, resource/link list, framework, recipe, routine, or a meaningful reflection (personal or intimate reflections count as gold).
LEAVE = one-off logistics, a grocery/food order, scheduling, a stray number/credential, a half-finished fragment, or a duplicate.
CRITICAL privacy rule: intimate/sexual content -> personal-nsfw; relationship or private-personal content -> personal or diary; medical/body content -> personal-medical or health. NEVER put intimate, sexual, relationship, or medical content into a shared folder (reference/project/people/idea/book/blog).
Reply with ONLY JSON: {"gold": true|false, "dest": "<dest>", "reason": "<=8 words"}.
dest is one of: reference (how-tos/specs/links), project (work/product projects), idea (concepts), people (a non-intimate note about a person), health (fitness/training), book (reading notes), blog (writing drafts), diary (personal reflection), personal (private life), personal-medical (health/medical/body), personal-nsfw (intimate/sexual), leave (if gold is false).
Base the decision on the BODY, not the title; titles are often junk or timestamps."""

SYS_RESCUE = """You re-examine ONE note that a cleanup pass flagged as a possible junk candidate. Decide its fate:
- KEEP_PRIVATE: deeply personal or sensitive content that must be preserved and never trashed — intimate/sexual, a romantic relationship or a specific partner, medical/body, parenting, or a meaningful private reflection.
- KEEP_SN: an actively-used or substantive working note worth keeping — a current project, workshop or product ideas, stories or creative writing, games, a reading/book list, a package or gift plan, event/dinner planning, a person's contact/details, a how-to or reference.
- JUNK: genuine ephemera safe to leave as a cleanup candidate — a one-off logistic, a grocery/food order, a stray number or credential, a bare fragment, a duplicate, or an empty stub.
Reply with ONLY JSON: {"fate": "KEEP_PRIVATE|KEEP_SN|JUNK", "dest": "<private folder or empty>", "reason": "<=8 words"}.
For KEEP_PRIVATE, dest is one of: personal-nsfw (intimate/sexual), personal-medical (medical/body), personal (private life, relationship, parenting), diary (personal reflection). For KEEP_SN and JUNK, set dest to "".
Base the decision on the BODY, not the title. Most flagged notes are genuine ephemera — use KEEP only when the note has clear lasting personal or working value."""

SYS_RESCUE_STRICT = """You re-examine ONE note that was tentatively kept as a "working note," now applying a STRICT bar. Keep it ONLY if it has clear, lasting, reusable value the person would genuinely miss. Otherwise it is junk.
KEEP (strict) = a real ongoing project with substance; a developed idea, plan, or decision; a story or creative piece; a curated list (reading, games, gifts) with actual entries; a reusable how-to, spec, or reference; meaningful notes about a specific person or a planned event. The note must have real, substantive content — not just a title, a line, or a vague stub.
JUNK = a one-off logistic, a short reminder, a stray link or number, a grocery/order, an unfinished fragment, a duplicate, a near-empty or vague note, or anything whose lasting value is unclear.
When in doubt, choose JUNK: these are cleanup candidates and the bar is HIGH.
Reply with ONLY JSON: {"keep": true|false, "reason": "<=8 words"}.
Base the decision on the BODY, not the title."""

SYS = SYS_RESCUE_STRICT if rescue_strict else (SYS_RESCUE if rescue else (SYS_SENSITIVE if sensitive else (SYS_HYBRID_FILTER if goldroute else (SYS_HYBRID if hybrid else SYS_PUBLIC))))

def classify(title, body):
    prompt = f"TITLE: {title}\n\nBODY:\n{body[:4000]}"
    data = json.dumps({
        "model": model, "stream": False, "format": "json",
        "options": {"temperature": 0, "num_ctx": 4096},
        "messages": [{"role": "system", "content": SYS}, {"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request("http://127.0.0.1:11434/api/chat", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        resp = json.load(r)
    return json.loads(resp["message"]["content"])

rows = [json.loads(l) for l in open(inp, encoding="utf-8") if l.strip()]
PRIV_DESTS = {"personal-nsfw", "personal-medical", "personal", "diary"}
out, gold, err = {}, 0, 0
private, keepers = {}, {}  # rescue mode: private export map, and all-keepers detach set
kp = ks = junk = 0
for r in rows:
    body = r.get("body") or r.get("snippet") or r.get("text") or ""
    try:
        v = classify(r.get("title", ""), body)
    except Exception as e:
        err += 1
        if not quiet:
            print(f"  ERR  {r['uuid'][:8]}  {e}")
        continue
    if rescue_strict:
        if bool(v.get("keep")):
            keepers[r["uuid"]] = {}
            ks += 1
        else:
            junk += 1
        continue
    if rescue:
        fate = str(v.get("fate", "")).upper()
        if fate == "KEEP_PRIVATE":
            dest = v.get("dest") or ""
            if dest not in PRIV_DESTS:
                dest = "personal"  # keep private even if the model left dest blank
            private[r["uuid"]] = {"dest": dest}
            keepers[r["uuid"]] = {}
            kp += 1
        elif fate == "KEEP_SN":
            keepers[r["uuid"]] = {}
            ks += 1
        else:
            junk += 1
        continue
    is_gold = bool(v.get("gold")) and v.get("dest") not in (None, "", "leave")
    if is_gold:
        # quiet mode (sensitive scan) stores dest only — no title ever reaches the map
        out[r["uuid"]] = {"dest": v["dest"]} if quiet else {"dest": v["dest"], "slug": slugify(r.get("title", "")), "title": r.get("title", "")}
        gold += 1
    if not quiet:
        print(f"  {'GOLD' if is_gold else 'leave':5} {str(v.get('dest','')):10} {(r.get('title','') or '(untitled)')[:34]!r:36} :: {str(v.get('reason',''))[:42]}")

if rescue_strict:
    json.dump(keepers, open(outp, "w"), indent=2)
    print(f"\nrescue-strict: KEEP={ks}  JUNK={junk}  err={err}  (model={model})")
    print(f"  strict keepers to detach -> {outp} ({len(keepers)})")
elif rescue:
    json.dump(private, open(outp, "w"), indent=2)
    json.dump(keepers, open(outp + ".detach.json", "w"), indent=2)
    print(f"\nrescue: KEEP_PRIVATE={kp}  KEEP_SN={ks}  JUNK={junk}  err={err}  (model={model})")
    print(f"  private export map -> {outp} ({kp})")
    print(f"  keepers to detach  -> {outp}.detach.json ({len(keepers)})")
else:
    json.dump(out, open(outp, "w"), indent=2)
    print(f"\n{gold}/{len(rows)} gold, {err} errors  (model={model})")
