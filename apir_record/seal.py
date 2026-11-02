"""Check an APIR seal's portable proof (format ``apir-seal-proof/1``) offline.

A port of ``verifyProof`` in apir-seal.mjs (served at
https://apir.ai/proof/apir-seal.mjs), check for check, in the same order and
with the same words:

1. the declaration hashes to the sealed event's ``input_hash``, and its file
   list to the ``output_hash``;
2. every event from the seal to the timestamped head hashes to its chain hash
   and links to the one before it, in sequence;
3. the head is one of that night's chain heads, and the heads rebuild the
   Merkle root;
4. the RFC 3161 token was granted and its message imprint is SHA-256 of
   exactly that root;
5. the proof's ``anchored_at`` agrees with the authority's ``genTime``, and the
   seal was recorded and declared before it;
6. any later act on the seal inside the segment recomputes to its own hash;
7. each file given is a sealed file, or a process file, byte for byte.

One check is added: each event's canonical text is compared with the Postgres
jsonb rendering of its own nine fields (:mod:`apir_record.canonical`). A
difference is reported as a note, not a failure, because the chain hash is
recomputed over the text as given either way.

One difference on malformed input: where the reference checker reads past the
end of a truncated timestamp token and can still find the imprint, this one
fails the token as truncated.

One check is NOT run here: the timestamp authority's signature on the token.
That needs public-key cryptography, which the Python standard library does
not have. :func:`openssl_commands` gives the exact commands that check it.

What a passing proof shows: that this declaration, over these exact files,
was on APIR's hash chain by the time the outside authority timestamped it, and
has not changed since. What it does not: APIR sealed the declaration and the
files; it did not determine how the work was made, whether the contents are
true, or who owns anything described.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .canonical import EVENT_FIELDS, _sorted_js, event_canonical, load_json, sha256_hex, stable_stringify

__all__ = [
    "FORMAT",
    "verify_proof",
    "merkle_root",
    "read_tsa",
    "gen_time_to_datetime",
    "openssl_commands",
    "SIGNATURE_NOT_RUN",
]

FORMAT = "apir-seal-proof/1"

#: Said wherever a result is shown: this checker does not check the authority's signature.
SIGNATURE_NOT_RUN = (
    "The authority's signature on the timestamp token was NOT checked here: the Python standard "
    "library has no public-key cryptography. Check it with openssl."
)

ACT_WORDS = {
    "statement": "AI involvement statement",
    "process": "process files",
    "transfer": "custody record",
    "attestation": "attestation",
    "contest": "contest",
    "answer": "answer to a contest",
    "review": "signed review",
    "evidence_pack": "Evidence Pack issued",
}

_SHA256_ALG_OID = "608648016503040201"
_TSTINFO_OID = bytes([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04])
_DRIFT_LIMIT = timedelta(minutes=15)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# JavaScript semantics, where the reference checker's result depends on them
# ---------------------------------------------------------------------------

class _Undefined:
    """JavaScript's undefined: a missing property."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "undefined"

    def __bool__(self) -> bool:
        return False


UNDEFINED = _Undefined()


def _get(obj: Any, key: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, UNDEFINED)
    return UNDEFINED


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float, Decimal)) and not isinstance(v, bool)


def _truthy(v: Any) -> bool:
    if v is UNDEFINED or v is None or v is False:
        return False
    if _is_number(v):
        return not (v == 0 or (isinstance(v, float) and math.isnan(v)) or (isinstance(v, Decimal) and v.is_nan()))
    if isinstance(v, str):
        return v != ""
    return True


def _same(a: Any, b: Any) -> bool:
    """JavaScript's ===."""
    if a is UNDEFINED or b is UNDEFINED:
        return a is b
    if a is None or b is None:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_number(a) and _is_number(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is b


def _js_str(v: Any) -> str:
    """String(v), and what a template literal prints."""
    if v is UNDEFINED:
        return "undefined"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return v
    if _is_number(v):
        f = float(v)
        if math.isnan(f):
            return "NaN"
        if math.isinf(f):
            return "Infinity" if f > 0 else "-Infinity"
        return stable_stringify(v)
    if isinstance(v, (list, tuple)):
        return ",".join("" if x is None or x is UNDEFINED else _js_str(x) for x in v)
    return "[object Object]"


def _js_parse(text: Any) -> Any:
    """JSON.parse inside the reference checker's try: None stands for its fallback."""
    if not isinstance(text, str):
        raise ValueError("not text")
    return load_json(text)


def _plus_one(v: Any) -> Any:
    if v is UNDEFINED:
        return float("nan")
    if v is None:
        return 1
    if isinstance(v, bool):
        return int(v) + 1
    if _is_number(v):
        return v + 1
    if isinstance(v, str):
        return v + "1"
    return float("nan")


# ---------------------------------------------------------------------------
# Merkle root and the RFC 3161 token
# ---------------------------------------------------------------------------

def merkle_root(leaves: Iterable[Any]) -> Any:
    """The root of the night's chain heads, by the rule the proof states.

    Leaves sorted as text; each pair becomes SHA-256 of the two hex strings
    concatenated; an odd leaf is paired with itself; repeat until one remains.
    No leaves gives ``""``.
    """
    leaves = list(leaves)
    if not leaves:
        return ""
    defined = [x for x in leaves if x is not UNDEFINED]
    missing = [x for x in leaves if x is UNDEFINED]
    level = sorted(defined, key=lambda x: _sorted_key(_js_str(x))) + missing
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(sha256_hex(_js_str(level[i]) + _js_str(right)))
        level = nxt
    return level[0]


def _sorted_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


class _Node:
    __slots__ = ("tag", "start", "length", "end")

    def __init__(self, tag: int, start: int, length: int):
        self.tag = tag
        self.start = start
        self.length = length
        self.end = start + length


def _tlv(b: bytes, i: int, whole: bool = True) -> _Node:
    """One DER tag-length-value header at i. ``whole`` also requires its content to be in the buffer."""
    if i + 1 >= len(b):
        raise ValueError("The timestamp token is truncated.")
    length = b[i + 1]
    hdr = 2
    if length & 0x80:
        n = length & 0x7F
        if i + 2 + n > len(b):
            raise ValueError("The timestamp token is truncated.")
        length = int.from_bytes(b[i + 2:i + 2 + n], "big") if n else 0
        hdr = 2 + n
    node = _Node(b[i], i + hdr, length)
    if whole and node.end > len(b):
        raise ValueError("The timestamp token is truncated.")
    return node


def _kids(b: bytes, node: _Node) -> list:
    out = []
    i = node.start
    while i < node.end:
        c = _tlv(b, i)
        out.append(c)
        i = c.end
    return out


def _b64(text: Any) -> bytes:
    if not isinstance(text, str):
        raise TypeError("The timestamp token is not base64 text.")
    s = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/").rstrip("=")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=False)
    except (binascii.Error, ValueError) as err:
        raise ValueError(f"The timestamp token is not base64: {err}") from None


def read_tsa(b64: str) -> dict:
    """Enough DER to find TSTInfo in an RFC 3161 response: status, imprint, genTime.

    Returns ``status`` (0 granted, 1 granted with modifications), ``sha256``
    (the imprint's algorithm is SHA-256), ``hashed`` (the imprint, hex) and
    ``gen_time`` (the GeneralizedTime text), or ``status`` and ``error``.
    It does not check the authority's signature.
    """
    b = _b64(b64)
    try:
        # PKIStatusInfo is the first child of the response, and the status its first integer.
        status_info = _tlv(b, _tlv(b, 0, False).start, False)
        status: "int | None" = b[_tlv(b, status_info.start, False).start]
    except (ValueError, IndexError):
        status = None
    n = len(_TSTINFO_OID)
    for p in range(0, len(b) - n):
        if b[p:p + n] != _TSTINFO_OID:
            continue
        try:
            ctx = _tlv(b, p + n, False)
            if ctx.tag != 0xA0:
                continue
            octet = _tlv(b, ctx.start, False)
            if octet.tag != 0x04:
                continue
            info = _tlv(b, octet.start, False)
            if info.tag != 0x30:
                continue
        except ValueError:
            continue
        if info.end > len(b):
            raise ValueError("The timestamp token is truncated.")
        f = _kids(b, info)
        mi = _kids(b, f[2])
        alg = _kids(b, mi[0])
        return {
            "status": status,
            "sha256": b[alg[0].start:alg[0].end].hex() == _SHA256_ALG_OID,
            "hashed": b[mi[1].start:mi[1].end].hex(),
            "gen_time": b[f[4].start:f[4].end].decode("latin-1"),
        }
    return {"status": status, "error": "No TSTInfo found in the response."}


_GEN_TIME = re.compile(r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z\Z", re.ASCII)


def gen_time_to_datetime(gt: Any) -> "datetime | None":
    """A GeneralizedTime (``20260919000007Z``) as a UTC datetime, to the millisecond."""
    m = _GEN_TIME.match(gt or "") if isinstance(gt, str) else None
    if not m:
        return None
    ms = int(((m.group(7) or ".")[1:] + "000")[:3])
    try:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)),
                        int(m.group(5)), int(m.group(6)), ms * 1000, tzinfo=timezone.utc)
    except ValueError:
        return None


_ISO = re.compile(
    r"^\s*([+-]?\d{4,6})-(\d{2})-(\d{2})"
    r"(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*(Z|z|[+-]\d{2}(?::?\d{2})?)?)?\s*$",
    re.ASCII,
)


def _date(v: Any) -> "datetime | None":
    """new Date(v) for the dates a proof carries, to the millisecond. None when it is not a date."""
    if _is_number(v):
        try:
            return _EPOCH + timedelta(milliseconds=int(float(v)))
        except (OverflowError, ValueError):
            return None
    if not isinstance(v, str):
        return None
    m = _ISO.match(v)
    if not m:
        return None
    try:
        tz = timezone.utc
        off = m.group(8)
        if off and off not in ("Z", "z"):
            sign = -1 if off[0] == "-" else 1
            digits = off[1:].replace(":", "")
            tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0)))
        ms = int(((m.group(7) or "") + "000")[:3])
        dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0),
                      int(m.group(5) or 0), int(m.group(6) or 0), ms * 1000, tzinfo=tz)
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _iso_ms(dt: datetime) -> str:
    """Date.prototype.toISOString."""
    return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond // 1000)


# ---------------------------------------------------------------------------
# The proof
# ---------------------------------------------------------------------------

def _canonical_form_mismatches(chain: list, parsed: list) -> "list | None":
    """Events whose text is not the jsonb rendering of their own nine fields. None if none were readable."""
    out = []
    readable = 0
    for e, c in zip(chain, parsed):
        text = _get(e, "canonical")
        if not isinstance(c, Mapping) or not isinstance(text, str):
            continue
        readable += 1
        try:
            same = all(f in c for f in EVENT_FIELDS) and event_canonical(c) == text
        except (KeyError, TypeError, ValueError):
            same = False
        if not same:
            out.append(_js_str(_get(e, "sequence_number")))
    return out if readable else None


def verify_proof(proof: Any, files: "Iterable[Mapping] | None" = None) -> dict:
    """Verify a proof object, offline.

    ``files`` is ``[{"name": ..., "sha256": ...}]``, already hashed by the
    caller (lowercase hex). Returns ``ok``, ``files_ok``, ``anchored``,
    ``gen_time``, ``steps`` (each ``{"ok": True | False | None, "text",
    "detail", "kind"}``; ``kind`` is ``"check"`` or ``"note"``), ``acts``,
    ``files``, ``declaration``, ``attestation``, and ``signature_checked``,
    which is always False here (see :data:`SIGNATURE_NOT_RUN`).
    """
    files = list(files or [])
    steps: list = []

    def step(ok: Any, text: str, detail: Any = None, kind: str = "check") -> Any:
        steps.append({"ok": ok, "text": text, "detail": detail, "kind": kind})
        return ok

    P = proof
    if not _truthy(P) or not _same(_get(P, "format"), FORMAT):
        step(False, "This is not a proof file this checker reads.", f"format: {_js_str(_get(P, 'format'))}")
        return {"ok": False, "files_ok": False, "anchored": False, "gen_time": None, "steps": steps,
                "acts": [], "files": [], "declaration": None, "attestation": None, "signature_checked": False}

    ok = True
    chain = _get(P, "chain")
    chain = chain if isinstance(chain, list) else []
    try:
        ev = _js_parse(_get(chain[0] if chain else UNDEFINED, "canonical"))
    except ValueError:
        ev = None
    try:
        decl = _js_parse(_get(P, "declaration_canonical"))
    except ValueError:
        decl = None

    # 1. The declaration is the one on the chain.
    decl_text = _get(P, "declaration_canonical")
    decl_text = decl_text if _truthy(decl_text) else ""
    d_hash = sha256_hex(decl_text if isinstance(decl_text, str) else _js_str(decl_text))
    decl_files = _get(decl, "files") if _truthy(decl) else UNDEFINED
    decl_files = decl_files if isinstance(decl_files, list) else []
    f_digest = sha256_hex("\n".join(_sorted_js([_js_str(_get(f, "sha256")).lower() for f in decl_files])))
    ok = step(_truthy(ev) and _same(d_hash, _get(ev, "input_hash")) and _same(f_digest, _get(ev, "output_hash")),
              "The declaration and its file list are exactly the ones recorded in the sealed event.",
              f"declaration {d_hash}") and ok

    # 2. Every chain link hashes and connects, seal to head.
    link_ok = len(chain) > 0
    prev: Any = None
    parsed: list = []
    for i, e in enumerate(chain):
        try:
            c = _js_parse(_get(e, "canonical"))
        except ValueError:
            c = {}
        parsed.append(c)
        text = _get(e, "canonical")
        if not isinstance(text, str) or not _same(sha256_hex(text), _get(e, "chain_hash")):
            link_ok = False
        if not _same(_get(c, "sequence_number"), _get(e, "sequence_number")):
            link_ok = False
        if i > 0 and (not _same(_get(c, "prev_chain_hash"), prev)
                      or not _same(_get(c, "sequence_number"), _plus_one(_get(chain[i - 1], "sequence_number")))):
            link_ok = False
        prev = _get(e, "chain_hash")
    ok = step(link_ok,
              "The sealed event hashes to its recorded chain hash." if len(chain) == 1
              else f"All {len(chain)} events from the seal to the timestamped head hash correctly and link in order.",
              f"head {_js_str(prev)}") and ok

    # Added here: the text of each event is the jsonb rendering of its fields.
    mismatched = _canonical_form_mismatches(chain, parsed)
    if mismatched is not None:
        if not mismatched:
            step(True, "Each event's text is exactly the Postgres jsonb rendering of its own nine fields, "
                       "so its chain hash can be recomputed from the fields alone.", None, "note")
        else:
            step(None, "Some event texts are not the exact jsonb rendering of their own fields. The chain hash "
                       "was still recomputed over the text as given; this only means the fields alone would not "
                       "reproduce it (an event written under a retired form shows this way).",
                 "events " + ", ".join("#" + s for s in mismatched), "note")

    # 6. The acts on this seal inside the segment, each recomputed.
    acts: list = []
    seal_id = _get(P, "seal_id")
    for i in range(1, len(parsed)):
        c = parsed[i]
        da = _get(c, "data_accessed")
        a = _get(da, "act")
        rs = _get(c, "reasoning_summary")
        if _truthy(a) and _same(_get(a, "seal_id"), seal_id):
            intact = _same(sha256_hex(stable_stringify(a)), _get(c, "input_hash"))
            actor = _get(_get(a, "actor"), "name")
            body_files = _get(_get(a, "body"), "files")
            acts.append({
                "sequence_number": _get(c, "sequence_number"),
                "act": _get(a, "act"),
                "actor": None if actor is UNDEFINED else actor,
                "at": _get(a, "at"),
                "intact": intact,
                "private": False,
                "files": body_files if isinstance(body_files, list) else [],
            })
        elif _truthy(_get(da, "private")) and isinstance(rs, str) and f"on seal {_js_str(seal_id)}" in rs:
            m = re.match(r"Private (\w+)", rs, re.ASCII)
            acts.append({
                "sequence_number": _get(c, "sequence_number"),
                "act": m.group(1) if m else "act",
                "actor": None,
                "at": _get(c, "timestamp"),
                "intact": _same(_get(da, "act_sha256"), _get(c, "input_hash")),
                "private": True,
                "files": [],
            })
    if acts:
        n = len(acts)

        def act_line(a: dict) -> str:
            word = ACT_WORDS.get(a["act"]) if isinstance(a["act"], str) else None
            by = f" by {_js_str(a['actor'])}" if _truthy(a["actor"]) else ""
            return (f"#{_js_str(a['sequence_number'])} {word or _js_str(a['act'])}{by}"
                    f"{' (private: hash only)' if a['private'] else ''}")

        ok = step(all(a["intact"] for a in acts),
                  f"{n} later act{'' if n == 1 else 's'} on this seal inside the timestamped segment recompute to their own hashes.",
                  "; ".join(act_line(a) for a in acts)) and ok

    A = _get(P, "anchor")
    anchored = False
    gen_date = None
    if not _truthy(A):
        nya = _get(P, "not_yet_anchored")
        step(None, f"Not yet under an outside timestamp. {_js_str(nya) if _truthy(nya) else ''}".strip())
    else:
        # 3. The head is in that night's heads, and the heads rebuild the root.
        heads = _get(A, "chain_heads")
        heads = heads if isinstance(heads, list) else []
        in_heads = any(_same(_get(x, "chain_hash"), prev)
                       and (not _truthy(ev) or _same(_get(x, "agent_id"), _get(ev, "agent_id"))) for x in heads)
        ok = step(in_heads and _same(prev, _get(A, "head_chain_hash")),
                  f"The chain head is one of the {len(heads)} heads timestamped that night.") and ok
        root = merkle_root([_get(x, "chain_hash") for x in heads])
        ok = step(_same(root, _get(A, "merkle_root")), "Those heads rebuild the Merkle root.", f"root {_js_str(root)}") and ok

        # 4. The root is what the authority was asked to sign.
        try:
            t = read_tsa(_get(A, "tsa_response_der_b64"))
        except Exception as err:  # the reference checker catches everything here too
            t = {"error": str(err) or err.__class__.__name__}
        mr = _get(A, "merkle_root")
        want = sha256_hex(_js_str(mr) if _truthy(mr) else "")
        granted = t.get("status") in (0, 1)
        ok = step(not t.get("error") and granted and bool(t.get("sha256")) and t.get("hashed") == want,
                  "The timestamp token was granted, and it names exactly this root (SHA-256 of the root text).",
                  t["error"] if t.get("error") else f"imprint {_js_str(t.get('hashed', UNDEFINED))}") and ok

        # 5. The dates agree with the authority's.
        gen_date = gen_time_to_datetime(t.get("gen_time")) if t.get("gen_time") else None
        if gen_date is not None:
            anchored_at = _get(A, "anchored_at")
            claimed = _date(anchored_at) if _truthy(anchored_at) else None
            drift_ok = claimed is not None and abs(claimed - gen_date) <= _DRIFT_LIMIT
            shown = _iso_ms(gen_date).replace("T", " ")[:19]
            ok = step(drift_ok, f"The proof's anchor date agrees with the authority's own date, {shown} UTC.",
                      f"anchored_at {_js_str(anchored_at)}") and ok
            rec = _get(P, "recorded_at")
            dec = _get(decl, "declared_at")
            recorded = _date(rec) if _truthy(rec) else None
            declared = _date(dec) if _truthy(dec) else None
            ok = step(recorded is not None and declared is not None and recorded <= gen_date and declared <= gen_date,
                      "The seal was declared and recorded before the authority dated the chain containing it.",
                      f"declared {_js_str(dec)}, recorded {_js_str(rec)}") and ok
            anchored = True
        else:
            ok = step(False, "The authority's date could not be read from the token.") and ok

    # 7. The files in hand.
    sealed: dict = {}
    for f in decl_files:
        sealed[_js_str(_get(f, "sha256")).lower()] = f
    process: dict = {}
    for a in acts:
        if a["act"] == "process":
            for f in a["files"] or []:
                entry = dict(f) if isinstance(f, Mapping) else {}
                entry["seq"] = a["sequence_number"]
                process[_js_str(_get(f, "sha256")).lower()] = entry
    results = []
    for f in files:
        name, digest = f.get("name"), f.get("sha256")
        m = sealed.get(digest)
        p = process.get(digest) if not _truthy(m) else None
        match = "sealed" if _truthy(m) else "process" if _truthy(p) else "none"
        hit = m if _truthy(m) else p
        as_name = _get(hit, "name") if hit is not None else UNDEFINED
        as_name = None if as_name is UNDEFINED else as_name
        if match == "sealed":
            text = f'{name} is sealed file "{_js_str(as_name)}", byte for byte.'
        elif match == "process":
            text = f'{name} is process file "{_js_str(as_name)}", added in event {_js_str(p["seq"])}, byte for byte.'
        else:
            text = (f"{name} is not one of the sealed or process files. One changed byte is enough to fail; "
                    "it may also simply be a different file.")
        step(match != "none", text, digest)
        results.append({"name": name, "sha256": digest, "match": match, "as": as_name})
    files_ok = all(r["match"] != "none" for r in results)
    att = _get(P, "attestation")
    return {
        "ok": bool(ok),
        "files_ok": files_ok,
        "anchored": anchored,
        "gen_time": _iso_ms(gen_date) if gen_date is not None else None,
        "steps": steps,
        "acts": [_clean(a) for a in acts],
        "files": results,
        "declaration": decl,
        "attestation": None if att is UNDEFINED or att is None else att,
        "signature_checked": False,
    }


def _clean(v: Any) -> Any:
    """Undefined becomes None, so a result is plain JSON."""
    if v is UNDEFINED:
        return None
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_clean(x) for x in v]
    return v


def openssl_commands(proof: Any) -> "list[str]":
    """The commands that check the authority's signature, run in the folder holding seal.tsr and root.txt.

    Empty when the proof carries no timestamp yet.
    """
    A = _get(proof, "anchor")
    if not _truthy(A):
        return []
    certs = _get(A, "tsa_certificates")
    tsa_crt, ca_pem = _get(certs, "tsa_crt"), _get(certs, "ca_pem")
    out = []
    if isinstance(tsa_crt, str) and tsa_crt and isinstance(ca_pem, str) and ca_pem:
        out.append(f"curl -s -o tsa.crt {tsa_crt}")
        out.append(f"curl -s -o cacert.pem {ca_pem}")
    out.append("openssl ts -verify -in seal.tsr -data root.txt -CAfile cacert.pem -untrusted tsa.crt")
    return out


def tsr_files(proof: Any) -> "dict[str, bytes]":
    """seal.tsr (the token, DER) and root.txt (the root text, no newline): what the openssl check reads."""
    A = _get(proof, "anchor")
    token = _get(A, "tsa_response_der_b64")
    if not isinstance(token, str) or not token:
        return {}
    return {"seal.tsr": _b64(token), "root.txt": _js_str(_get(A, "merkle_root")).encode("utf-8")}


def load_proof(text: "str | bytes") -> Any:
    """Parse a proof file. Numbers keep their exact text, as the canonical check needs."""
    if isinstance(text, bytes):
        text = text.decode("utf-8-sig")
    elif text.startswith("﻿"):
        text = text[1:]
    return load_json(text)


def to_json(result: dict) -> str:
    """A result as JSON text."""
    return json.dumps(_clean(result), default=_json_default, ensure_ascii=False, indent=2)


def _json_default(v: Any) -> Any:
    if isinstance(v, Decimal):
        return float(v)
    raise TypeError(f"{type(v).__name__} is not JSON")
