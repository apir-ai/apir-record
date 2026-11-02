"""Send what an agent did to its APIR Black Box: ``POST https://apir.ai/api/v1/events``.

The agent runs wherever it runs. Each event goes into its Black Box through
APIR's one writer, so it is hash-chained and sequence-numbered like any other
event, and the chain head is timestamped nightly by an outside RFC 3161
authority.

Inputs and outputs are hashed here, with SHA-256, and the hashes are what is
sent: the prompt and the answer stay on your side. Keep the exact bytes you
hashed if you may need to show later that they match.

The contract, as the endpoint enforces it (src/app/api/v1/events/route.ts and
src/lib/agents/externalEvents.ts in APIR's code):

* ``Authorization: Bearer <key>``. The key comes from the agent's connect page
  or Settings, API keys, and must carry ``agent:write``.
* Body ``{"agent_id": "<uuid>", "events": [{"type", "summary", "input_hash",
  "output_hash", "data"}]}``, at most 50 events a request.
* ``type`` is one of action, decision, tool_call (counted as conduct) or input,
  output, reasoning, data_access, error (recorded, not counted).
* ``summary`` is required, one line on what the agent did, at most 1,000
  characters. ``input_hash`` and ``output_hash`` are 64 hex characters or
  absent. ``data`` is an object of at most 8,192 bytes as JSON.
* More than 600 events a minute on one key is refused (HTTP 429).
* 201 on success: ``recorded``, ``agent_id``, ``events`` (each ``id``,
  ``sequence``, ``chain_hash``, ``type``, ``at``) and ``scored: true`` when the
  batch led APIR to score the agent. 207 when recording stopped part way: the
  events before ``failed_at`` are on the record.

This client never retries on its own. A retry after a lost answer could put the
same event on the record twice, and the record keeps both.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from decimal import Decimal
from typing import Any, Iterable, Mapping

from . import __version__
from .canonical import sha256_hex, stable_stringify

__all__ = [
    "DEFAULT_URL",
    "CONDUCT_TYPES",
    "OTHER_TYPES",
    "EVENT_TYPES",
    "MAX_BATCH",
    "MAX_SUMMARY",
    "MAX_DATA_BYTES",
    "MAX_EVENTS_PER_MINUTE",
    "APIRError",
    "make_event",
    "EventsClient",
]

DEFAULT_URL = "https://apir.ai/api/v1/events"

#: Counted as conduct by the trust genome.
CONDUCT_TYPES = ("action", "decision", "tool_call")
#: Recorded, not counted.
OTHER_TYPES = ("input", "output", "reasoning", "data_access", "error")
EVENT_TYPES = frozenset(CONDUCT_TYPES + OTHER_TYPES)

MAX_BATCH = 50
MAX_SUMMARY = 1000
MAX_DATA_BYTES = 8192
#: Per key, a ceiling against a runaway loop, not a quota.
MAX_EVENTS_PER_MINUTE = 600

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_HEX64 = re.compile(r"[0-9a-f]{64}")
_EVENT_KEYS = frozenset(("type", "summary", "input_hash", "output_hash", "data"))


class APIRError(Exception):
    """APIR refused or could not finish a request.

    ``status`` is the HTTP status (None when no answer came back), ``recorded``
    how many events of this ``send`` are on the record, ``events`` those
    events as APIR returned them, and ``body`` the parsed answer, if any.
    """

    def __init__(self, message: str, status: "int | None" = None, recorded: int = 0,
                 events: "list | None" = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.recorded = recorded
        self.events = events or []
        self.body = body


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _hash_or_none(value: Any, field: str) -> "str | None":
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _HEX64.fullmatch(value.lower()):
        raise ValueError(f"{field} must be a SHA-256 hash in hex (64 characters). Hash the content yourself; never send it.")
    return value.lower()


def _content_hash(content: Any, field: str) -> str:
    if isinstance(content, (bytes, bytearray, memoryview, str)):
        return sha256_hex(content)
    raise TypeError(
        f"{field} must be text or bytes: the exact content you keep, so you can show later that it hashes "
        f"to the same value. Serialise {type(content).__name__} yourself first."
    )


def _check_data(data: Any) -> dict:
    if data is None:
        return {}
    if not isinstance(data, Mapping):
        raise ValueError('data must be an object (for example {"tool": "search"}).')
    size = len(stable_stringify(data).encode("utf-8"))
    if size > MAX_DATA_BYTES:
        raise ValueError(f"data is {size} bytes as JSON; the limit is {MAX_DATA_BYTES}.")
    return dict(data)


def make_event(type: str, summary: str, *, input: Any = None, output: Any = None,
               input_hash: "str | None" = None, output_hash: "str | None" = None,
               data: "Mapping | None" = None) -> dict:
    """One event, checked against the endpoint's rules, with input and output hashed here.

    Pass ``input``/``output`` (text or bytes; hashed with SHA-256 and never
    sent) or ``input_hash``/``output_hash`` (already hashed), not both.
    """
    if input is not None and input_hash is not None:
        raise ValueError("Give input or input_hash, not both.")
    if output is not None and output_hash is not None:
        raise ValueError("Give output or output_hash, not both.")
    kind = type.strip().lower() if isinstance(type, str) else ""
    if kind not in EVENT_TYPES:
        raise ValueError("type must be one of: " + ", ".join(CONDUCT_TYPES + OTHER_TYPES) + ".")
    text = summary.strip() if isinstance(summary, str) else ""
    if not text:
        raise ValueError("summary is required: one line on what the agent did.")
    if _utf16_len(text) > MAX_SUMMARY:
        raise ValueError(f"summary is longer than {MAX_SUMMARY} characters.")
    ih = _content_hash(input, "input") if input is not None else _hash_or_none(input_hash, "input_hash")
    oh = _content_hash(output, "output") if output is not None else _hash_or_none(output_hash, "output_hash")
    return {"type": kind, "summary": text, "input_hash": ih, "output_hash": oh, "data": _check_data(data)}


def _from_mapping(e: Any, i: int) -> dict:
    if not isinstance(e, Mapping):
        raise ValueError(f"events[{i}] must be an object.")
    extra = set(e.keys()) - _EVENT_KEYS
    if extra:
        raise ValueError(
            f"events[{i}] has {', '.join(sorted(map(str, extra)))}: the event takes only "
            "type, summary, input_hash, output_hash and data. Hash content with make_event(input=..., output=...)."
        )
    try:
        return make_event(e.get("type"), e.get("summary"), input_hash=e.get("input_hash"),
                          output_hash=e.get("output_hash"), data=e.get("data"))
    except (ValueError, TypeError) as err:
        raise type(err)(f"events[{i}]: {err}") from None


def _json_default(v: Any) -> Any:
    if isinstance(v, Decimal):
        return float(v)
    raise TypeError(f"{type(v).__name__} is not JSON.")


class EventsClient:
    """Send an agent's events to APIR.

    ``api_key`` defaults to the ``APIR_API_KEY`` environment variable. The key
    is sent only in the Authorization header of each request.
    """

    def __init__(self, agent_id: str, api_key: "str | None" = None, *, url: str = DEFAULT_URL,
                 timeout: float = 10.0, user_agent: "str | None" = None):
        agent = agent_id.strip() if isinstance(agent_id, str) else ""
        if not _UUID.fullmatch(agent):
            raise ValueError("agent_id must be the agent's id (a UUID), as shown on its connect page.")
        key = api_key if api_key is not None else os.environ.get("APIR_API_KEY", "")
        if not isinstance(key, str) or not key.strip():
            raise ValueError("An API key is required: pass api_key or set APIR_API_KEY.")
        self.agent_id = agent
        self._key = key.strip()
        self.url = url
        self.timeout = timeout
        self.user_agent = user_agent or f"apir-record/{__version__} (+https://apir.ai)"

    def __repr__(self) -> str:
        return f"EventsClient(agent_id={self.agent_id!r}, url={self.url!r})"

    def record(self, type: str, summary: str, *, input: Any = None, output: Any = None,
               input_hash: "str | None" = None, output_hash: "str | None" = None,
               data: "Mapping | None" = None) -> dict:
        """Send one event. Same arguments as :func:`make_event`; returns what :meth:`send` returns."""
        return self.send([make_event(type, summary, input=input, output=output,
                                     input_hash=input_hash, output_hash=output_hash, data=data)])

    def send(self, events: Iterable[Mapping]) -> dict:
        """Send events in order, 50 a request, and stop at the first refusal.

        Every event is checked before anything is sent. Returns ``recorded``,
        ``events`` (as APIR returned them, in order) and ``scored``. Raises
        :class:`APIRError` if APIR refuses a request or does not answer;
        ``recorded`` on the error says how many are already on the record.
        """
        checked = [_from_mapping(e, i) for i, e in enumerate(events)]
        if not checked:
            raise ValueError("No events to send.")
        done: list = []
        scored = False
        for start in range(0, len(checked), MAX_BATCH):
            batch = checked[start:start + MAX_BATCH]
            status, body = self._post({"agent_id": self.agent_id, "events": batch})
            if status in (200, 201):
                done.extend((body.get("events") or []) if isinstance(body, dict) else [])
                scored = scored or bool(isinstance(body, dict) and body.get("scored"))
                continue
            message = body.get("error") if isinstance(body, dict) else None
            partial = body.get("recorded", 0) if isinstance(body, dict) and status == 207 else 0
            raise APIRError(
                f"APIR answered {status}: {message or 'no reason given'}",
                status=status,
                recorded=len(done) + (partial if isinstance(partial, int) else 0),
                events=done,
                body=body,
            )
        return {"recorded": len(done), "events": done, "scored": scored}

    def _post(self, payload: dict) -> "tuple[int, Any]":
        data = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"),
                          default=_json_default).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, method="POST", headers={
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                return res.status, _read_json(res.read())
        except urllib.error.HTTPError as err:
            try:
                return err.code, _read_json(err.read())
            finally:
                err.close()
        except (urllib.error.URLError, OSError) as err:
            reason = getattr(err, "reason", err)
            raise APIRError(
                f"No answer from APIR ({reason}). This batch may or may not be on the record; "
                "look at the agent's record before sending it again.",
                status=None,
            ) from err


def _read_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, ValueError):
        return {"error": raw[:200].decode("utf-8", "replace")}
