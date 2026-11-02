"""apir-record: check an APIR agent record offline.

APIR gives every AI agent signed papers and a tamper-evident work history that
buyers, auditors and insurers can check without trusting you. This package
recomputes that record on your own machine with the Python standard library:

* :func:`verify_bundle` checks an agent's exported log book: every file, every
  entry's hash and link, and each chain's head against the RFC 3161 token (the
  authority's signature is checked with openssl);
* :func:`verify_anchor` checks the stamp a public agent's record answers with;
* :func:`chain_hash` and :func:`verify_chain` recompute Black Box events, the
  hash-chained, append-only log book of an agent, from their own fields;
* :func:`verify_proof` checks an APIR seal's portable proof: the declaration,
  the chain, the Merkle root and the RFC 3161 token's imprint and date (the
  authority's signature is checked with openssl, see :func:`openssl_commands`);
* :class:`EventsClient` sends an agent's actions to its Black Box with inputs
  and outputs hashed locally.
"""
__version__ = "0.2.0"

from .bundle import read_bundle, verify_anchor, verify_bundle  # noqa: E402
from .canonical import (  # noqa: E402
    EVENT_FIELDS,
    chain_hash,
    event_canonical,
    jsonb_text,
    load_json,
    sha256_hex,
    stable_stringify,
    verify_chain,
)
from .events import APIRError, EventsClient, EVENT_TYPES, make_event  # noqa: E402
from .seal import FORMAT, SIGNATURE_NOT_RUN, merkle_root, openssl_commands, read_tsa, verify_proof  # noqa: E402

__all__ = [
    "__version__",
    "read_bundle",
    "verify_anchor",
    "verify_bundle",
    "EVENT_FIELDS",
    "chain_hash",
    "event_canonical",
    "jsonb_text",
    "load_json",
    "sha256_hex",
    "stable_stringify",
    "verify_chain",
    "APIRError",
    "EventsClient",
    "EVENT_TYPES",
    "make_event",
    "FORMAT",
    "SIGNATURE_NOT_RUN",
    "merkle_root",
    "openssl_commands",
    "read_tsa",
    "verify_proof",
]
