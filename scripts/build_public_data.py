#!/usr/bin/env python3
"""Turn a raw export of the Silmun Launch Tracker into the trimmed public data file.

Usage (no password needed, it encrypts to data/public-key.json):
    python3 scripts/build_public_data.py RAW.json data/tracker.enc.json

RAW.json holds one list of rows per sheet (header row left out):
    {"Timeline": [[...]], "Tasks": [[...]], "Risks": [[...]], "Decisions": [[...]]}
Dates can be "YYYY-MM-DD", {"date": "YYYY-MM-DD"} or plain text.

The raw export is private. Never commit it. Only the output of this script
goes in the repo, and the rules below decide what gets trimmed out.
"""
import json
import re
import sys
from datetime import datetime, timezone

# --- What stays out of the public page -------------------------------------
# Any row whose text contains "[private]" is dropped entirely.
PRIVATE_TAG = "[private]"
# Risks about people's personal situations are dropped.
DROP_RISK_WORDS = ["travel", "graduation", "kazim's time", "final quarter"]
# Sentences that mention these are removed from notes.
DROP_SENTENCE_WORDS = ["travel", "whatsapp", "$", "/month", "per month"]
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
MONEY = re.compile(r"\$\s?\d")


def as_date(v):
    if isinstance(v, dict):
        v = v.get("date") or v.get("value")
    if isinstance(v, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        return v
    return None


def as_text(v):
    if v is None:
        return None
    if isinstance(v, dict):
        v = v.get("markdown") or v.get("value") or v.get("date")
    s = str(v).strip()
    return s or None


def clean_note(s):
    if not s:
        return None
    parts = re.split(r"(?<=[.!?])\s+", s)
    keep = [p for p in parts if not any(w in p.lower() for w in DROP_SENTENCE_WORDS)]
    out = " ".join(keep).strip()
    out = EMAIL.sub("", out)
    return out or None


def clean_title(s):
    if not s:
        return s
    if EMAIL.search(s):
        # "Support email: a@x.com or b@y.com" -> "Support email"
        s = s.split(":")[0].strip()
    s = EMAIL.sub("", s)
    if MONEY.search(s):
        s = MONEY.split(s)[0].strip(" ,(-")
    return s


def is_private(row):
    return any(PRIVATE_TAG in (as_text(c) or "").lower() for c in row)


def pad(row, n):
    row = list(row) + [None] * n
    return row[:n]


def build(raw):
    out = {"updated": datetime.now(timezone.utc).isoformat(timespec="minutes")}

    milestones = []
    for r in raw.get("Timeline", []):
        if is_private(r):
            continue
        title, owner, date, status, dep, notes = pad(r, 6)
        if not as_text(title):
            continue
        milestones.append({
            "title": clean_title(as_text(title)),
            "owner": as_text(owner),
            "date": as_date(date),
            "status": as_text(status) or "To do",
            "notes": clean_note(as_text(notes)),
        })
    out["milestones"] = milestones
    launch = next((m for m in milestones if m["title"].lower().startswith("public launch")), None)
    if launch is None:
        dated = sorted((m for m in milestones if m["date"]), key=lambda m: m["date"])
        launch = dated[-1] if dated else None
    out["launch"] = {
        "date": launch["date"] if launch else None,
        "proposed": bool(launch and "proposed" in (raw_note_for(raw, launch["title"]) or "").lower()),
    }

    tasks = []
    for r in raw.get("Tasks", []):
        if is_private(r):
            continue
        title, owner, due, status, area, notes = pad(r, 6)
        if not as_text(title):
            continue
        tasks.append({
            "title": clean_title(as_text(title)),
            "owner": as_text(owner) or "Unassigned",
            "due": as_date(due),
            "status": as_text(status) or "To do",
            "area": as_text(area) or "Other",
            "notes": clean_note(as_text(notes)),
        })
    out["tasks"] = tasks

    risks = []
    for r in raw.get("Risks", []):
        if is_private(r):
            continue
        title, impact, owner, status, plan = pad(r, 5)
        t = as_text(title) or ""
        if not t or any(w in t.lower() for w in DROP_RISK_WORDS):
            continue
        if (as_text(status) or "").lower() == "closed":
            continue
        risks.append({
            "title": clean_title(t),
            "impact": as_text(impact) or "Medium",
            "owner": as_text(owner),
            "plan": clean_note(as_text(plan)),
        })
    out["risks"] = risks

    open_d, made_d = [], []
    for r in raw.get("Decisions", []):
        if is_private(r):
            continue
        title, status, who, when, notes = pad(r, 5)
        if not as_text(title):
            continue
        item = {
            "title": clean_title(as_text(title)),
            "who": as_text(who),
            "date": as_date(when),
            "dateText": None if as_date(when) else as_text(when),
            "notes": clean_note(as_text(notes)),
        }
        (made_d if (as_text(status) or "").lower() == "made" else open_d).append(item)
    out["decisions"] = {"open": open_d, "made": made_d}
    return out


def raw_note_for(raw, title):
    for r in raw.get("Timeline", []):
        if as_text(r[0]) and clean_title(as_text(r[0])) == title:
            return as_text(pad(r, 6)[5])
    return None


PUBLIC_KEY = "data/public-key.json"
HKDF_INFO = b"silmun-board-v2"


def encrypt(text):
    """Encrypt to the dashboard's public key (ECDH P-256 + HKDF-SHA256 + AES-256-GCM).

    No password needed here: only the password-protected private key can decrypt.
    """
    import base64
    import os
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    with open(PUBLIC_KEY) as f:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), base64.b64decode(json.load(f)["key"]))
    eph = ec.generate_private_key(ec.SECP256R1())
    shared = eph.exchange(ec.ECDH(), pub)
    salt, iv = os.urandom(16), os.urandom(12)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO).derive(shared)
    ct = AESGCM(key).encrypt(iv, text.encode(), None)
    b64 = lambda b: base64.b64encode(b).decode()
    epk = eph.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return {"v": 2, "epk": b64(epk), "salt": b64(salt), "iv": b64(iv), "data": b64(ct)}


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1]) as f:
        raw = json.load(f)
    data = build(raw)
    text = json.dumps(data, ensure_ascii=False)
    # Last safety net: nothing that looks like an email or a price gets out.
    if EMAIL.search(text) or MONEY.search(text):
        sys.exit("Refusing to write: an email address or a price is still in the output.")
    with open(sys.argv[2], "w") as f:
        json.dump(encrypt(text), f)
        f.write("\n")
    print(f"Wrote {sys.argv[2]} (encrypted): {len(data['tasks'])} tasks, {len(data['milestones'])} milestones, "
          f"{len(data['risks'])} risks, {len(data['decisions']['open'])} open decisions")


if __name__ == "__main__":
    main()
