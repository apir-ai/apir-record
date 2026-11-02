"""The exact texts APIR hashes, reproduced with the Python standard library.

Two forms, each byte for byte:

* The Black Box event form. An event's chain hash is SHA-256 of
  ``jsonb_build_object(<nine fields>)::text`` as Postgres renders it with the
  session pinned to UTC (``private.bb_event_canonical``, migration
  20261009020000). :func:`event_canonical` reproduces that text and
  :func:`chain_hash` hashes it, so anyone holding the nine fields can recompute
  the hash without APIR.

* The act form, used for later acts on a seal: object keys sorted at every
  depth (UTF-16 code unit order), array order kept, rendered compactly the way
  JavaScript's ``JSON.stringify`` renders it. :func:`stable_stringify` matches
  ``stableStringify`` in apir-seal.mjs and src/lib/seal/acts.ts.

Postgres jsonb rendering, as reproduced here: keys sorted shorter first, then
by their UTF-8 bytes; a later duplicate key wins; ``", "`` between members and
``": "`` after a key; strings escape only ``"`` ``\\`` and control characters
(``\\b \\f \\n \\r \\t``, the rest as lowercase ``\\u00xx``), everything else
raw UTF-8; numbers exactly as numeric prints them (no exponent, scale kept, so
``1.50`` stays ``1.50`` and ``1e3`` becomes ``1000``); timestamps in UTC as
``2026-09-18T07:30:09.596951+00:00`` with trailing zeros of the fraction
dropped.

Numbers are only exact if they reach this module the way the database holds
them. Parse JSON with :func:`load_json`, which keeps each number's text as a
``Decimal``. A record that has passed through JavaScript (``JSON.parse`` then
``JSON.stringify``) may have turned ``1.50`` into ``1.5``; its hash will then
not recompute here, and that is the export's doing, not the chain's.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "EVENT_FIELDS",
    "sha256_hex",
    "load_json",
    "jsonb_text",
    "pg_timestamp_text",
    "parse_timestamp",
    "event_canonical",
    "chain_hash",
    "verify_chain",
    "stable_stringify",
]

#: The nine fields of a Black Box event that its chain hash covers.
EVENT_FIELDS = (
    "agent_id",
    "sequence_number",
    "event_type",
    "input_hash",
    "output_hash",
    "reasoning_summary",
    "data_accessed",
    "timestamp",
    "prev_chain_hash",
)

_BIGINT_MIN = -(2 ** 63)
_BIGINT_MAX = 2 ** 63 - 1


def sha256_hex(data: "str | bytes | bytearray | memoryview") -> str:
    """SHA-256 in lowercase hex. Text is hashed as UTF-8."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(bytes(data)).hexdigest()


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def load_json(text: "str | bytes") -> Any:
    """Parse JSON keeping every number exact: decimals as ``Decimal``, integers as ``int``.

    ``NaN`` and ``Infinity`` are refused, as JSON and jsonb both refuse them.
    """
    return json.loads(text, parse_float=Decimal, parse_constant=_no_constants)


# ---------------------------------------------------------------------------
# Postgres jsonb text
# ---------------------------------------------------------------------------

_PG_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}
_PG_NEEDS_ESCAPE = re.compile(r'["\\\x00-\x1f]')


def _pg_string(s: str) -> str:
    if "\x00" in s:
        raise ValueError("Postgres text cannot hold a NUL character (\\u0000).")
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("The text is not valid Unicode (it holds a lone surrogate).") from None
    if not _PG_NEEDS_ESCAPE.search(s):
        return f'"{s}"'
    out = []
    for ch in s:
        esc = _PG_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ch < " ":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _pg_number(v: "float | Decimal") -> str:
    if isinstance(v, float):
        if not math.isfinite(v):
            raise ValueError("jsonb cannot hold NaN or Infinity.")
        d = Decimal(repr(v))
    else:
        d = v
        if not d.is_finite():
            raise ValueError("jsonb cannot hold NaN or Infinity.")
    if d.is_zero():
        d = d.copy_abs()
    return format(d, "f")


def _pg_key_order(key: str) -> "tuple[int, bytes]":
    b = key.encode("utf-8")
    return (len(b), b)


def _jsonb(v: Any, out: list) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, str):
        out.append(_pg_string(v))
    elif isinstance(v, int):
        out.append(str(int(v)))
    elif isinstance(v, (float, Decimal)):
        out.append(_pg_number(v))
    elif isinstance(v, Mapping):
        for k in v:
            if not isinstance(k, str):
                raise TypeError(f"A JSON object key must be text, not {type(k).__name__}.")
        keys = sorted(v.keys(), key=_pg_key_order)
        if not keys:
            out.append("{}")
            return
        out.append("{")
        for i, k in enumerate(keys):
            if i:
                out.append(", ")
            out.append(_pg_string(k))
            out.append(": ")
            _jsonb(v[k], out)
        out.append("}")
    elif isinstance(v, (list, tuple)):
        if not v:
            out.append("[]")
            return
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(", ")
            _jsonb(item, out)
        out.append("]")
    else:
        raise TypeError(f"{type(v).__name__} is not a JSON value.")


def jsonb_text(value: Any) -> str:
    """The text Postgres prints for ``value::jsonb``: what ``jsonb::text`` returns."""
    out: list = []
    _jsonb(value, out)
    return "".join(out)


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

_TS_RE = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})"
    r"(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?"
    r"\s*(Z|z|UTC|[+-]\d{2}(?::?\d{2}(?::?\d{2})?)?)?\s*$",
    re.ASCII,
)


def _offset(text: "str | None") -> timezone:
    if not text or text in ("Z", "z", "UTC"):
        return timezone.utc
    sign = -1 if text[0] == "-" else 1
    digits = text[1:].replace(":", "")
    hours = int(digits[0:2])
    minutes = int(digits[2:4] or 0)
    seconds = int(digits[4:6] or 0)
    return timezone(sign * timedelta(hours=hours, minutes=minutes, seconds=seconds))


def parse_timestamp(value: "str | datetime") -> datetime:
    """A timestamp as an aware UTC ``datetime`` with microsecond precision.

    Takes ISO 8601 (``2026-09-18T07:30:09.596951+00:00``, ``...Z``) or the
    Postgres text form (``2026-09-18 07:30:09.596951+00``). More than six
    fractional digits round half to even, as Postgres rounds them. A time with
    no offset is read as UTC, because every APIR timestamp is written in UTC.
    """
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if not isinstance(value, str):
        raise TypeError(f"A timestamp must be text or a datetime, not {type(value).__name__}.")
    m = _TS_RE.match(value)
    if not m:
        raise ValueError(f"Not a timestamp this reads: {value!r}")
    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hour, minute, second = int(m.group(4) or 0), int(m.group(5) or 0), int(m.group(6) or 0)
    frac = m.group(7) or ""
    micro = 0
    if frac:
        micro = int(Decimal("0." + frac).scaleb(6).quantize(Decimal(1), rounding=ROUND_HALF_EVEN))
    base = datetime(year, month, day, hour, minute, 0, tzinfo=_offset(m.group(8)))
    dt = base + timedelta(seconds=second, microseconds=micro)
    return dt.astimezone(timezone.utc)


def pg_timestamp_text(value: "str | datetime") -> str:
    """How jsonb prints a timestamptz in a UTC session: ``2026-09-18T07:30:09.596951+00:00``."""
    dt = parse_timestamp(value)
    text = "%04d-%02d-%02dT%02d:%02d:%02d" % (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
    if dt.microsecond:
        text += "." + ("%06d" % dt.microsecond).rstrip("0")
    return text + "+00:00"


# ---------------------------------------------------------------------------
# The event form
# ---------------------------------------------------------------------------

def _uuid_text(v: Any) -> "str | None":
    if v is None:
        return None
    if isinstance(v, uuid.UUID):
        return str(v)
    if not isinstance(v, str):
        raise TypeError("agent_id must be a UUID.")
    return str(uuid.UUID(v.strip()))


def _integral(v: "float | Decimal") -> bool:
    try:
        return v == int(v)
    except (OverflowError, ValueError, ArithmeticError):
        return False


def _bigint(v: Any) -> "int | None":
    if v is None:
        return None
    if isinstance(v, bool):
        raise TypeError("sequence_number must be an integer, not a boolean.")
    if isinstance(v, int):
        n = int(v)
    elif isinstance(v, str) and re.fullmatch(r"\s*[+-]?\d+\s*", v, re.ASCII):
        n = int(v)
    elif isinstance(v, (float, Decimal)) and _integral(v):
        n = int(v)
    else:
        raise TypeError("sequence_number must be an integer.")
    if not _BIGINT_MIN <= n <= _BIGINT_MAX:
        raise ValueError("sequence_number is outside the bigint range.")
    return n


def _text(v: Any, field: str) -> "str | None":
    if v is None or isinstance(v, str):
        return v
    raise TypeError(f"{field} must be text or None.")


def event_canonical(event: Mapping) -> str:
    """The exact text APIR's database hashes for one Black Box event.

    ``event`` carries the nine :data:`EVENT_FIELDS` (extra keys, such as
    ``chain_hash`` or ``id``, are ignored). ``data_accessed`` is the parsed
    JSON value; parse it with :func:`load_json` so numbers stay exact.
    ``timestamp`` is ISO 8601 text or a ``datetime``.
    """
    missing = [f for f in EVENT_FIELDS if f not in event]
    if missing:
        raise KeyError("The event is missing " + ", ".join(missing) + ".")
    ts = event["timestamp"]
    fields = {
        "agent_id": _uuid_text(event["agent_id"]),
        "sequence_number": _bigint(event["sequence_number"]),
        "event_type": _text(event["event_type"], "event_type"),
        "input_hash": _text(event["input_hash"], "input_hash"),
        "output_hash": _text(event["output_hash"], "output_hash"),
        "reasoning_summary": _text(event["reasoning_summary"], "reasoning_summary"),
        "data_accessed": event["data_accessed"],
        "timestamp": None if ts is None else pg_timestamp_text(ts),
        "prev_chain_hash": _text(event["prev_chain_hash"], "prev_chain_hash"),
    }
    return jsonb_text(fields)


def chain_hash(event: Mapping) -> str:
    """SHA-256 of :func:`event_canonical`: the event's chain hash, in hex."""
    return sha256_hex(event_canonical(event))


def verify_chain(events: Iterable[Mapping]) -> dict:
    """Recompute a run of Black Box events, oldest first.

    Each event needs the nine fields and its stored ``chain_hash``. Checks that
    every hash recomputes from its own content, that each event names the one
    before it as ``prev_chain_hash``, and that sequence numbers run without a
    gap. A run may start mid-chain; the first event's link is not checked.

    Returns ``ok`` (all three hold), ``content_intact``, ``links_intact``,
    ``sequence_intact``, ``tampered_sequences``, ``broken_link_sequences``,
    ``sequence_gap_at`` (the first sequence number after a gap, or None),
    ``unreadable`` (events that could not be rendered, with the reason),
    ``total_events`` and ``head_chain_hash``.

    APIR's own verifier also knows a short registry of events written under a
    retired canonical form (``bb_legacy_hash_events``); this function does not,
    so such an event shows here as not recomputing.
    """
    tampered: list = []
    broken: list = []
    unreadable: list = []
    gap_at = None
    prev_hash = None
    prev_seq = None
    count = 0
    for i, e in enumerate(events):
        count += 1
        seq = e.get("sequence_number")
        try:
            if chain_hash(e) != e.get("chain_hash"):
                tampered.append(seq)
        except (KeyError, TypeError, ValueError) as err:
            unreadable.append({"sequence_number": seq, "error": str(err)})
            tampered.append(seq)
        if i > 0:
            if e.get("prev_chain_hash") != prev_hash:
                broken.append(seq)
            if gap_at is None and (not isinstance(seq, int) or not isinstance(prev_seq, int) or seq != prev_seq + 1):
                gap_at = seq
        prev_hash = e.get("chain_hash")
        prev_seq = seq
    content_intact = count > 0 and not tampered
    links_intact = not broken
    sequence_intact = gap_at is None
    return {
        "ok": content_intact and links_intact and sequence_intact,
        "content_intact": content_intact,
        "links_intact": links_intact,
        "sequence_intact": sequence_intact,
        "tampered_sequences": tampered,
        "broken_link_sequences": broken,
        "sequence_gap_at": gap_at,
        "unreadable": unreadable,
        "total_events": count,
        "head_chain_hash": prev_hash,
    }


# ---------------------------------------------------------------------------
# The act form: JSON.stringify with keys sorted
# ---------------------------------------------------------------------------

def _js_number(v: "int | float | Decimal") -> str:
    """How JSON.stringify prints a number once JSON.parse has made it a double."""
    try:
        f = float(v)
    except OverflowError:
        return "null"
    if math.isnan(f) or math.isinf(f):
        return "null"
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    t = Decimal(repr(abs(f))).as_tuple()
    digits = "".join(str(d) for d in t.digits)
    exp = t.exponent
    stripped = digits.rstrip("0")
    exp += len(digits) - len(stripped)
    digits = stripped or "0"
    k = len(digits)
    n = k + exp
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return sign + mantissa + "e" + ("+" if e >= 0 else "-") + str(abs(e))


_JS_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _js_string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _JS_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ch < " " or "\ud800" <= ch <= "\udfff":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_order(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def stable_stringify(value: Any) -> str:
    """Keys sorted at every depth, array order kept, rendered as JSON.stringify would.

    Numbers are treated as JavaScript doubles (``1.50`` prints ``1.5``,
    ``1e21`` prints ``1e+21``), because the JavaScript side parsed them that way
    before hashing.
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _js_string(value)
    if isinstance(value, (int, float, Decimal)):
        return _js_number(value)
    if isinstance(value, Mapping):
        keys = sorted((str(k) for k in value.keys()), key=_utf16_order)
        return "{" + ",".join(_js_string(k) + ":" + stable_stringify(value[k]) for k in keys) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(stable_stringify(v) for v in value) + "]"
    raise TypeError(f"{type(value).__name__} is not a JSON value.")


def _sorted_js(values: Sequence[str]) -> list:
    """Sort text the way JavaScript's default sort does (UTF-16 code units)."""
    return sorted(values, key=_utf16_order)
