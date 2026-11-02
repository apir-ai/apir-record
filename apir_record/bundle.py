"""Check an APIR evidence bundle, or a public agent's stamp, offline.

A signed-in member of an organisation exports an agent's log book from the
Black Box page, free, as a zip: ``events.json``, ``report.pdf``,
``custody.json``, ``anchors.json`` and ``manifest.json``. They hand it to a
buyer, an auditor or an insurer, who checks it here with no APIR server in the
loop:

1. every file against the hash the manifest records for it, and the manifest's
   own hash;
2. every entry's chain hash from its own fields, every link, no gaps;
3. for each chain, the stamped head: it is an entry in the bundle, it is among
   the heads stamped that night, those heads rebuild the Merkle root, and the
   RFC 3161 token names exactly that root, with the authority's own date.

Only step 3 ties the bundle to anyone but APIR. Steps 1 and 2 show the bundle
is consistent with itself, which a forger could also arrange; a head under a
real token could not have been written after the authority's date.

Not checked here: the authority's signature on the token (the Python standard
library has no public-key cryptography, see :func:`anchor_openssl_commands`)
and the manifest's HMAC (APIR holds its key, so only APIR can check it).

What a passing bundle does not show: that the log book is complete, that the
agent was right, or that the exporter included every agent. It shows what the
agent and its owner reported. Entries after the last stamp rest on APIR's word
until the next one.
"""
from __future__ import annotations

import json
import os
import zipfile
from typing import Any, Iterable, Mapping

from .canonical import load_json, sha256_hex, verify_chain
from .seal import _DRIFT_LIMIT, _b64, _date, _iso_ms, gen_time_to_datetime, merkle_root, read_tsa

__all__ = [
    "HMAC_NOT_RUN",
    "anchor_openssl_commands",
    "anchor_tsr_files",
    "read_bundle",
    "verify_anchor",
    "verify_bundle",
]

MANIFEST_FORMAT = "apir.evidence-manifest.v1"
EVENTS_FORMAT = "apir.evidence-bundle.v1"
ANCHORS_FORMAT = "apir.evidence-anchors.v1"

#: The manifest fields added after its hash and HMAC were taken.
_MANIFEST_EXTRA = ("manifest_hash", "signature", "signature_alg", "verify_hint")
_MAX_BUNDLE_BYTES = 1 << 30

#: Said wherever a bundle result is shown.
HMAC_NOT_RUN = (
    "The manifest's HMAC signature was NOT checked here: APIR holds its key, so only APIR can check it. "
    "The hashes and the outside timestamp are what a stranger can check."
)


def read_bundle(path: str) -> "dict[str, bytes]":
    """The files of a bundle, from its zip or from a folder it was unpacked into."""
    if os.path.isdir(path):
        out = {}
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if os.path.isfile(full):
                with open(full, "rb") as f:
                    out[name] = f.read()
        return out
    with zipfile.ZipFile(path) as z:
        if sum(i.file_size for i in z.infolist()) > _MAX_BUNDLE_BYTES:
            raise ValueError("The bundle unpacks to more than 1 GiB.")
        return {i.filename: z.read(i.filename) for i in z.infolist() if not i.is_dir()}


def _check_stamp(block: Any, step: Any) -> dict:
    """The steps one stamped night shares: root, token, date. Returns ``ok`` and ``gen_date``."""
    block = block if isinstance(block, Mapping) else {}
    heads = block.get("heads")
    heads = heads if isinstance(heads, list) else []
    root = block.get("merkle_root")
    root_text = root if isinstance(root, str) else ""
    ok = step(bool(heads) and merkle_root(heads) == root_text,
              f"The {len(heads)} heads stamped that night rebuild the Merkle root.", f"root {root_text}")
    try:
        t = read_tsa(block.get("tsa_response_der_b64"))
    except Exception as err:  # a damaged token is a failed check, never a crash
        t = {"error": str(err) or err.__class__.__name__}
    good = (not t.get("error") and t.get("status") in (0, 1) and bool(t.get("sha256"))
            and t.get("hashed") == sha256_hex(root_text))
    ok = step(good, "The timestamp token was granted, and it names exactly this root (SHA-256 of the root text).",
              t["error"] if t.get("error") else f"imprint {t.get('hashed')}") and ok
    gen_date = gen_time_to_datetime(t.get("gen_time")) if t.get("gen_time") else None
    if gen_date is None:
        ok = step(False, "The authority's date could not be read from the token.") and ok
    else:
        anchored_at = block.get("anchored_at")
        claimed = _date(anchored_at) if anchored_at else None
        shown = _iso_ms(gen_date).replace("T", " ")[:19]
        ok = step(claimed is not None and abs(claimed - gen_date) <= _DRIFT_LIMIT,
                  f"The receipt's date agrees with the authority's own date, {shown} UTC.",
                  f"anchored_at {anchored_at}") and ok
    return {"ok": bool(ok), "gen_date": gen_date}


def verify_anchor(block: Any) -> dict:
    """Check the ``anchor`` block of a public agent's verify-black-box answer, offline.

    It shows the agent's chain stood at ``head_chain_hash`` no later than the
    authority's date, so a later rewrite of anything before that head would
    change the head. It says nothing about what the entries contain: those are
    the owner's to share, in an evidence bundle.

    Returns ``ok``, ``gen_time``, ``head_chain_hash``, ``steps`` and
    ``signature_checked``, which is always False here.
    """
    steps: list = []

    def step(ok: Any, text: str, detail: Any = None, kind: str = "check") -> Any:
        steps.append({"ok": ok, "text": text, "detail": detail, "kind": kind})
        return ok

    if isinstance(block, Mapping) and isinstance(block.get("anchor"), Mapping):
        block = block["anchor"]
    if not isinstance(block, Mapping) or not block.get("merkle_root"):
        step(False, "This holds no stamp to check.")
        return {"ok": False, "gen_time": None, "head_chain_hash": None, "steps": steps, "signature_checked": False}
    head = block.get("head_chain_hash")
    heads = block.get("heads")
    heads = heads if isinstance(heads, list) else []
    ok = step(isinstance(head, str) and head in heads, "The agent's chain head is one of the heads stamped that night.",
              f"head {head}")
    stamp = _check_stamp(block, step)
    gen = stamp["gen_date"]
    return {
        "ok": bool(ok and stamp["ok"]),
        "gen_time": _iso_ms(gen) if gen is not None else None,
        "head_chain_hash": head,
        "steps": steps,
        "signature_checked": False,
    }


def _by_chain(events: Iterable[Any]) -> "dict[str, list]":
    chains: dict = {}
    for e in events:
        chains.setdefault(str(e.get("agent_id") if isinstance(e, Mapping) else None), []).append(e)
    for group in chains.values():
        group.sort(key=lambda e: e.get("sequence_number") if isinstance(e.get("sequence_number"), int) else -1)
    return chains


def verify_bundle(files: Mapping[str, bytes]) -> dict:
    """Check a bundle's files, as :func:`read_bundle` returns them, offline.

    Returns ``ok`` (every check run passed), ``anchored`` (every chain has a
    head under an outside stamp), ``gen_times``, ``chains`` (for each agent:
    ``agent_id``, ``entries``, ``stamped_entries``, ``later_entries``,
    ``gen_time``), ``anchors``, ``steps`` (each ``{"ok", "text", "detail",
    "kind"}``), and ``signature_checked`` and ``hmac_checked``, always False.
    """
    steps: list = []

    def step(ok: Any, text: str, detail: Any = None, kind: str = "check") -> Any:
        steps.append({"ok": ok, "text": text, "detail": detail, "kind": kind})
        return ok

    def done(ok: Any, chains: list, anchors: list, anchored: bool, gen_times: list) -> dict:
        return {"ok": bool(ok), "anchored": anchored, "gen_times": gen_times, "chains": chains, "anchors": anchors,
                "steps": steps, "signature_checked": False, "hmac_checked": False}

    # 1. The manifest, and every file against it.
    try:
        manifest = json.loads(files["manifest.json"].decode("utf-8"))
    except KeyError:
        step(False, "This bundle has no manifest.json.")
        return done(False, [], [], False, [])
    except ValueError as err:
        step(False, "manifest.json could not be read.", str(err))
        return done(False, [], [], False, [])
    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT:
        step(False, "This is not a bundle manifest this checker reads.",
             f"format: {manifest.get('format') if isinstance(manifest, dict) else None}")
        return done(False, [], [], False, [])

    ok = True
    listed = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
    for name, want in listed.items():
        data = files.get(name)
        digest = want.get("sha256") if isinstance(want, dict) else None
        same = data is not None and sha256_hex(data) == digest
        ok = step(same, f"{name} is byte for byte the file the manifest records.",
                  "missing from the bundle" if data is None else f"sha256 {sha256_hex(data)}") and ok
    extra = sorted(set(files) - set(listed) - {"manifest.json"})
    if extra:
        step(None, "Files the manifest does not record are in this bundle, and nothing here vouches for them.",
             ", ".join(extra), "note")

    core = {k: v for k, v in manifest.items() if k not in _MANIFEST_EXTRA}
    recomputed = sha256_hex(json.dumps(core, separators=(",", ":"), ensure_ascii=False))
    ok = step(recomputed == manifest.get("manifest_hash"), "The manifest hashes to its recorded manifest_hash.",
              f"manifest_hash {recomputed}") and ok

    # 2. Every entry, chain by chain.
    if "events.json" not in files:
        ok = step(False, "This bundle has no events.json.") and ok
        return done(ok, [], [], False, [])
    try:
        record = load_json(files["events.json"])
    except ValueError as err:
        ok = step(False, "events.json could not be read.", str(err)) and ok
        return done(ok, [], [], False, [])
    if not isinstance(record, dict) or record.get("format") != EVENTS_FORMAT or not isinstance(record.get("events"), list):
        ok = step(False, "events.json is not a log book this checker reads.") and ok
        return done(ok, [], [], False, [])
    events = record["events"]
    ok = step(record.get("bundle_id") == manifest.get("bundle_id") and len(events) == manifest.get("event_count"),
              f"events.json is this bundle's, with the {len(events)} entries the manifest counts.") and ok

    filters = record.get("filters") if isinstance(record.get("filters"), dict) else {}
    by_type = bool(filters.get("event_types"))
    chains = _by_chain(events)
    reports = {}
    for agent_id, group in sorted(chains.items()):
        r = verify_chain(group)
        reports[agent_id] = r
        first, last = group[0].get("sequence_number"), group[-1].get("sequence_number")
        detail = None
        if r["tampered_sequences"]:
            detail = f"does not recompute at {r['tampered_sequences'][:10]}"
        ok = step(r["content_intact"], f"Agent {agent_id}: all {len(group)} entries, {first} to {last}, "
                  "hash to their recorded chain hashes from their own fields.", detail) and ok
        if by_type:
            step(None, f"Agent {agent_id}: exported by event type, so the links and sequence across the entries "
                 "left out cannot be checked here.", None, "note")
        else:
            detail = None
            if not r["links_intact"]:
                detail = f"broken at {r['broken_link_sequences'][:10]}"
            elif not r["sequence_intact"]:
                detail = f"gap before {r['sequence_gap_at']}"
            ok = step(r["links_intact"] and r["sequence_intact"],
                      f"Agent {agent_id}: each entry names the one before it, with no gap in the sequence.",
                      detail) and ok

    labelled = sum(1 for e in events if isinstance(e, Mapping) and isinstance(e.get("data_accessed"), Mapping)
                   and "trust_score_after" in e["data_accessed"])
    if labelled:
        step(None, f"{labelled} audit entries, written up to 18:00 UTC on 2 November 2026, call the hourly monitor's reading a trust "
             "score. It is not a rating: a rating comes only from the Trust Genome, and an agent without one is Unrated. "
             "Rewriting those entries would break their hashes, so their words stay.", None, "note")

    # 3. The outside stamps.
    anchors: list = []
    if "anchors.json" not in files:
        step(None, "This bundle carries no timestamp tokens: it was exported before they were added. "
             "Its entries are consistent with each other, and nothing here dates them.", None, "note")
    else:
        try:
            block = json.loads(files["anchors.json"].decode("utf-8"))
        except ValueError as err:
            ok = step(False, "anchors.json could not be read.", str(err)) and ok
            block = {}
        if isinstance(block, dict) and block.get("format") not in (None, ANCHORS_FORMAT):
            ok = step(False, "anchors.json is not a file this checker reads.", f"format: {block.get('format')}") and ok
            block = {}
        anchors = block.get("anchors") if isinstance(block, dict) and isinstance(block.get("anchors"), list) else []

    covered: dict = {}
    gen_times: list = []
    for a in anchors:
        a = a if isinstance(a, Mapping) else {}
        stamp = _check_stamp(a, step)
        ok = stamp["ok"] and ok
        gen = stamp["gen_date"]
        if gen is not None:
            gen_times.append(_iso_ms(gen))
        heads = a.get("heads") if isinstance(a.get("heads"), list) else []
        covers = a.get("covers") if isinstance(a.get("covers"), list) else []
        for c in covers:
            c = c if isinstance(c, Mapping) else {}
            agent_id, head = str(c.get("agent_id")), c.get("chain_hash")
            group = chains.get(agent_id, [])
            event = next((e for e in group if e.get("chain_hash") == head), None)
            stamped_at = _date(event.get("timestamp")) if event is not None and event.get("timestamp") else None
            good = (event is not None and head in heads and gen is not None
                    and stamped_at is not None and stamped_at <= gen)
            seq = event.get("sequence_number") if event is not None else None
            ok = step(good, f"Agent {agent_id}: entry {seq} is one of those heads, so it and every entry before it "
                      "existed by the authority's date.", f"head {head}") and ok
            if good:
                covered[agent_id] = {"seq": seq, "gen": gen}

    chain_rows = []
    for agent_id, group in sorted(chains.items()):
        c = covered.get(agent_id)
        stamped = sum(1 for e in group if isinstance(e.get("sequence_number"), int) and c
                      and e["sequence_number"] <= c["seq"]) if c else 0
        later = len(group) - stamped
        if not c:
            if "anchors.json" in files:
                step(None, f"Agent {agent_id}: no head of this chain in this bundle is under an outside stamp yet.",
                     None, "note")
        elif later:
            step(None, f"Agent {agent_id}: {later} later entries are not under a stamp yet. They rest on APIR's word "
                 "until the next one.", None, "note")
        chain_rows.append({"agent_id": agent_id, "entries": len(group), "stamped_entries": stamped,
                           "later_entries": later, "gen_time": _iso_ms(c["gen"]) if c else None})

    anchored = bool(chain_rows) and all(row["gen_time"] for row in chain_rows)
    return done(ok, chain_rows, anchors, anchored, gen_times)


def anchor_tsr_files(block: Any, index: "int | None" = None) -> "dict[str, bytes]":
    """The token (DER) and the root text (no newline), the two files the openssl check reads."""
    if not isinstance(block, Mapping):
        return {}
    token = block.get("tsa_response_der_b64")
    if not isinstance(token, str) or not token:
        return {}
    base = "anchor" if index is None else f"anchor-{index}"
    return {f"{base}.tsr": _b64(token), f"{base}-root.txt": str(block.get("merkle_root") or "").encode("utf-8")}


def anchor_openssl_commands(blocks: Iterable[Any], numbered: bool = True) -> "list[str]":
    """The commands that check the authority's signature, run where the token files were written."""
    blocks = [b for b in blocks if isinstance(b, Mapping) and b.get("tsa_response_der_b64")]
    if not blocks:
        return []
    out = []
    certs = blocks[0].get("tsa_certificates")
    certs = certs if isinstance(certs, Mapping) else {}
    tsa_crt, ca_pem = certs.get("tsa_crt"), certs.get("ca_pem")
    if isinstance(tsa_crt, str) and tsa_crt and isinstance(ca_pem, str) and ca_pem:
        out.append(f"curl -s -o tsa.crt {tsa_crt}")
        out.append(f"curl -s -o cacert.pem {ca_pem}")
    for i in range(1, len(blocks) + 1):
        base = f"anchor-{i}" if numbered else "anchor"
        out.append(f"openssl ts -verify -in {base}.tsr -data {base}-root.txt -CAfile cacert.pem -untrusted tsa.crt")
    return out
