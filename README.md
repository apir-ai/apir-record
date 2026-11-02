# apir-record: check an AI agent's tamper-evident work history offline

Check an APIR agent record on your own machine: the hash-chained, append-only work history of an AI agent, its seals and their RFC 3161 timestamps, recomputed with nothing but the Python standard library.

APIR gives every AI agent signed papers and a tamper-evident work history that buyers, auditors and insurers can check without trusting you. This package is the part you run yourself. It does five things.

- **Checks an agent's exported log book.** The owner exports it free as a zip and hands it to you. Every file against its manifest, every entry's hash and link, and each chain's head against the RFC 3161 token.
- **Checks a public agent's stamp.** For an agent with a public passport: its chain head is among that night's heads, they rebuild the Merkle root, and the token names that root with the authority's date.
- **Recomputes a Black Box event.** An agent's log book is a hash chain: each event's hash covers its own fields and the hash of the event before it. `chain_hash()` rebuilds the exact text APIR's database hashes, byte for byte, so a changed field, a removed event or a reordered one shows.
- **Verifies a seal's portable proof.** The declaration, every link of the chain from the seal to the timestamped head, the Merkle root of that night's chain heads, and the RFC 3161 token's imprint and date. Then whether the file you hold is the sealed file.
- **Sends an agent's actions to its log book.** Any agent, any framework. Inputs and outputs are hashed with SHA-256 on your side; the hashes go to APIR and the content stays with you.

Python 3.9 or later. No dependencies. MIT licence.

## Install

```sh
pip install git+https://github.com/apir-ai/apir-record
```

## Check an agent's exported log book

Ask the agent's owner for its export: a signed-in member makes one, free, on the Black Box page. Then:

```sh
apir-record verify-bundle bundle.zip --tsr-out .
```

```text
  PASS  events.json is byte for byte the file the manifest records.
  PASS  The manifest hashes to its recorded manifest_hash.
  PASS  Agent d25e0c5b-...: all 400 entries, 1 to 400, hash to their recorded chain hashes from their own fields.
  PASS  Agent d25e0c5b-...: each entry names the one before it, with no gap in the sequence.
  PASS  The 22 heads stamped that night rebuild the Merkle root.
  PASS  The timestamp token was granted, and it names exactly this root (SHA-256 of the root text).
  PASS  The receipt's date agrees with the authority's own date, 2026-11-01 00:00:08 UTC.
  PASS  Agent d25e0c5b-...: entry 355 is one of those heads, so it and every entry before it existed by the authority's date.
  NOTE  Agent d25e0c5b-...: 45 later entries are not under a stamp yet. They rest on APIR's word until the next one.
```

Run the openssl commands it prints to check the authority's signature. That is the step that matters most: the hashes alone show a file consistent with itself, and only a head under a real token could not have been written after the authority's date.

Exit 0 when every check it runs passes, 1 when one fails, 2 on bad usage. A bundle with a chain not yet under an outside timestamp exits 0 with a note; `--require-anchor` makes it exit 1. `--json` prints the result as JSON.

An export holds what its owner chose to export. A window or a filter can leave entries out, and no file shows what an agent did not report.

## Check a public agent's stamp

```sh
curl -s "https://podncdlwtknujadrtsxz.supabase.co/functions/v1/verify-black-box?agent_id=<id>" -o answer.json
apir-record verify-anchor answer.json --tsr-out .
```

It shows the agent's chain stood at that head no later than the authority's date, so a later rewrite of anything before it would change the head. It says nothing about what the entries contain: those are the owner's to share. An agent without a public passport answers `not_found`.

## Verify a seal

Download the proof from the seal's page (it is served at `https://apir.ai/api/seal/<id>/proof`), then:

```sh
apir-record verify-seal apir-seal-<id>.proof.json yourfile.pdf --tsr-out .
```

```text
  PASS  The declaration and its file list are exactly the ones recorded in the sealed event.
  PASS  The sealed event hashes to its recorded chain hash.
  PASS  Each event's text is exactly the Postgres jsonb rendering of its own nine fields, ...
  PASS  The chain head is one of the <n> heads timestamped that night.
  PASS  Those heads rebuild the Merkle root.
  PASS  The timestamp token was granted, and it names exactly this root (SHA-256 of the root text).
  PASS  The proof's anchor date agrees with the authority's own date, 2026-09-19 00:00:07 UTC.
  PASS  The seal was declared and recorded before the authority dated the chain containing it.
  PASS  yourfile.pdf is sealed file "specimen-triage-verdict.pdf", byte for byte.

  NOT RUN  The authority's signature on the timestamp token. The Python standard library has
           no public-key cryptography, so this checker did not check it. Check it with openssl:
    curl -s -o tsa.crt https://freetsa.org/files/tsa.crt
    curl -s -o cacert.pem https://freetsa.org/files/cacert.pem
    openssl ts -verify -in seal.tsr -data root.txt -CAfile cacert.pem -untrusted tsa.crt
```

Run the three printed commands in the folder you gave `--tsr-out`; openssl prints `Verification: OK` when the authority's signature holds.

Exit 0 when every check it runs passes, 1 when one fails or a file given is not on the seal, 2 on bad usage. A proof not yet under an outside timestamp exits 0 with a warning, because the declaration and the chain still check; `--require-anchor` makes it exit 1. `--json` prints the result as JSON.

The checks are a port of `apir-seal.mjs`, the Node checker APIR serves at <https://apir.ai/proof/apir-seal.mjs>, in the same order and with the same words. One check is added: each event's text is compared with the database rendering of its own fields. One case differs: a truncated timestamp token fails here, where the Node checker can still read its imprint.

From Python:

```python
from apir_record import verify_proof
from apir_record.seal import load_proof

proof = load_proof(open("apir-seal-<id>.proof.json", "rb").read())
result = verify_proof(proof, [{"name": "yourfile.pdf", "sha256": "<sha-256 hex>"}])
result["ok"], result["anchored"], result["gen_time"]
```

## Hash a file

```sh
apir-record hash yourfile.pdf
```

Prints the SHA-256 fingerprint APIR records for a file.

## Recompute a Black Box event

```python
from apir_record import chain_hash, load_json, verify_chain

event = load_json(open("event.json", "rb").read())  # numbers kept exactly as written
chain_hash(event) == event["chain_hash"]

report = verify_chain(events)  # oldest first: every hash, every link, no gaps
report["ok"], report["tampered_sequences"], report["broken_link_sequences"], report["sequence_gap_at"]
```

An event's chain hash is SHA-256 of `jsonb_build_object(...)::text` over nine fields, as Postgres prints it in UTC: `agent_id`, `sequence_number`, `event_type`, `input_hash`, `output_hash`, `reasoning_summary`, `data_accessed`, `timestamp`, `prev_chain_hash`. `event_canonical()` returns that text. The rules (key order, spacing, escapes, how numbers and timestamps print) are in the module docstring and the specification, and `tests/fixtures/canonical-vectors.json` holds texts produced by APIR's database function itself.

Parse with `load_json()`. It keeps `1.50` as `1.50`; Python's `json.loads` turns it into `1.5`, and the hash would then not recompute. An export that has passed through JavaScript may have lost that already.

## Send events from your agent

```python
import os
from apir_record import EventsClient

apir = EventsClient(agent_id="<the agent's id>", api_key=os.environ["APIR_API_KEY"])
apir.record("decision", "Approved refund #4521 within the agent's limit",
            input=prompt, output=answer, data={"tool": "refunds"})
```

Register the agent and make its key at <https://apir.ai/agents/connect>. The client posts to `https://apir.ai/api/v1/events` and checks every event against the endpoint's rules before it sends anything:

- `Authorization: Bearer <key>`; the key needs `agent:write`.
- `type` is `action`, `decision` or `tool_call` (counted as conduct), or `input`, `output`, `reasoning`, `data_access` or `error` (recorded, not counted).
- `summary` is one line on what the agent did, up to 1,000 characters.
- `input` and `output` are text or bytes and are hashed here; or pass `input_hash` and `output_hash` you made yourself. Keep the exact bytes you hashed: to show later that a record matches, you hash them again.
- `data` is an object up to 8,192 bytes as JSON. It is sent as it is, so put no secrets in it.
- `send()` takes any number of events and posts them 50 to a request, in order, stopping at the first refusal. The endpoint answers 429 to more than 600 events a minute on one key; batch, and slow down.

A refusal raises `APIRError` with the status, APIR's reason and how many events are already on the record. The client never retries on its own: a retry after a lost answer could record the same event twice, and the record keeps both.

## What is checked, and what is not

Checked here, with no APIR server in the loop: every hash and link from the fields up, every file of a bundle against its manifest, the Merkle root, the token's status, imprint and date, and the dates in the proof or receipt against the authority's.

Not checked here:

- **The timestamp authority's signature on the token.** That needs public-key cryptography, which the Python standard library does not have. The step is not run, the output says so every time, and the openssl command above checks it.
- **Whether you trust that authority.** That is your choice of CA file.
- **A bundle's HMAC signature.** APIR holds its key, so only APIR can check it.
- **APIR's signed papers** (the Ed25519 Trust Passport). Check one at <https://apir.ai/verify-passport> against the keys at <https://apir.ai/.well-known/jwks.json>.

What the record shows, and its limits:

- The log book proves what an agent reported and shows any later change to it. It does not prove the report was complete, or that the agent was right.
- The mandate is written by the agent's owner, and signed with APIR's key. APIR does not decide what it says.
- APIR operates the writer. The nightly outside RFC 3161 timestamp is what stops backdating past the last stamp: once a chain head is stamped, changing anything before it changes the head and the root the authority signed. Events after the last stamp rest on APIR's word until the next one.
- A seal: APIR sealed the declaration and the files. It did not determine how the work was made, whether the contents are true, or who owns anything described.
- APIR holds no SOC 2 report, no ISO 27001 certificate and no penetration test.

## Links

- The specification of the record: every object, its canonical form, the chain rules and the outside timestamps, with test vectors: <https://apir.ai/agent-record-specification>
- Check any agent, free, no account: <https://apir.ai/check-agent>
- The same seal check in a browser: <https://apir.ai/proof/verify-seal>
- Developers: <https://apir.ai/developers>
- What APIR holds and does not hold yet: <https://apir.ai/trust>

## Licence

MIT. Copyright (c) 2026 RIPA PTY LTD trading as APIR (ABN 48 638 569 632). Questions and bugs: <ripa@apir.ai>.
