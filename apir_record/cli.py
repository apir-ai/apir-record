"""The apir-record command.

    apir-record verify-bundle <bundle.zip or folder> [--require-anchor] [--tsr-out DIR] [--json]
    apir-record verify-anchor <answer.json or -> [--tsr-out DIR] [--json]
    apir-record verify-seal <proof.json> [file ...] [--require-anchor] [--tsr-out DIR] [--json]
    apir-record hash <file> [file ...]

verify-bundle and verify-seal exit 0 when every check they run passes, 1 when
one fails or a file given is not on the seal, 2 on bad usage. Without
--require-anchor a record not yet under an outside timestamp exits 0 with a
warning, because its hashes and links still check; with it, that exits 1.
verify-anchor exits 0 when the stamp checks, 1 when it does not, 2 on bad usage.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import zipfile
from typing import Sequence

from . import __version__
from .bundle import (
    HMAC_NOT_RUN,
    anchor_openssl_commands,
    anchor_tsr_files,
    read_bundle,
    verify_anchor,
    verify_bundle,
)
from .canonical import load_json
from .seal import SIGNATURE_NOT_RUN, load_proof, openssl_commands, to_json, tsr_files, verify_proof

_LOCKED = "APIR sealed the declaration and the files. APIR did not determine how the work was made."
_LOG_BOOK = ("A log book shows what the agent and its owner reported. It does not show that the report was "
             "complete, or that the agent was right.")


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    if path == "-":
        stream = sys.stdin.buffer
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
        return h.hexdigest()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _mark(s: dict) -> str:
    if s.get("kind") == "note" and s["ok"] is not True:
        return "NOTE"
    return "PASS" if s["ok"] is True else "FAIL" if s["ok"] is False else "WAIT"


def _verify_seal(args: argparse.Namespace) -> int:
    out = sys.stdout
    try:
        with open(args.proof, "rb") as f:
            proof = load_proof(f.read())
    except (OSError, ValueError) as err:
        sys.stderr.write(f"Could not read {args.proof} as a proof: {err}\n")
        return 2
    try:
        files = [{"name": os.path.basename(p), "sha256": _file_sha256(p)} for p in args.files]
    except OSError as err:
        sys.stderr.write(f"Could not read a file to check: {err}\n")
        return 2
    r = verify_proof(proof, files)
    anchored_proof = isinstance(proof, dict) and bool(proof.get("anchor"))

    written = None
    if args.tsr_out and anchored_proof:
        blobs = tsr_files(proof)
        if blobs:
            os.makedirs(args.tsr_out, exist_ok=True)
            for name, data in blobs.items():
                with open(os.path.join(args.tsr_out, name), "wb") as f:
                    f.write(data)
            written = args.tsr_out

    failed = not r["ok"] or not r["files_ok"] or (args.require_anchor and not r["anchored"])

    if args.json:
        r = dict(r)
        r["signature_check"] = {"run": False, "why": SIGNATURE_NOT_RUN, "commands": openssl_commands(proof)}
        out.write(to_json(r) + "\n")
        return 1 if failed else 0

    seal_id = proof.get("seal_id") if isinstance(proof, dict) else None
    out.write(f"APIR seal {seal_id or ''}\n{r['attestation'] or ''}\n\n")
    for s in r["steps"]:
        detail = f"\n        {s['detail']}" if s["detail"] else ""
        out.write(f"  {_mark(s)}  {s['text']}{detail}\n")

    if anchored_proof:
        out.write("\n  NOT RUN  The authority's signature on the timestamp token. The Python standard library has\n"
                  "           no public-key cryptography, so this checker did not check it. Check it with openssl:\n")
        if written:
            out.write(f"           wrote seal.tsr and root.txt to {written}; in that folder run\n")
        else:
            out.write("           write seal.tsr and root.txt first with --tsr-out <dir>, then in that folder run\n")
        for cmd in openssl_commands(proof):
            out.write(f"    {cmd}\n")

    if not r["ok"]:
        verdict = "DOES NOT CHECK: see the step marked FAIL."
    elif not r["files_ok"]:
        verdict = "The seal checks, but a file given is not on it."
    elif not r["anchored"]:
        verdict = ("NOT YET DATED: the declaration and chain check; the outside timestamp is not in this proof yet."
                   if args.require_anchor else
                   "Checks, not yet dated: the outside timestamp is not in this proof yet.")
    else:
        when = r["gen_time"].replace("T", " ")[:19]
        verdict = (f"CHECKS without APIR. Dated by the authority {when} UTC. "
                   "The authority's signature was not checked here: run the openssl command above.")
    out.write(f"\n{verdict}\n{_LOCKED}\n")
    return 1 if failed else 0


def _print_steps(steps: list) -> None:
    for s in steps:
        detail = f"\n        {s['detail']}" if s["detail"] else ""
        sys.stdout.write(f"  {_mark(s)}  {s['text']}{detail}\n")


def _print_signature_not_run(commands: list, written: "str | None") -> None:
    sys.stdout.write("\n  NOT RUN  The authority's signature on the timestamp token. The Python standard library has\n"
                     "           no public-key cryptography, so this checker did not check it. Check it with openssl:\n")
    if written:
        sys.stdout.write(f"           wrote the token files to {written}; in that folder run\n")
    else:
        sys.stdout.write("           write the token files first with --tsr-out <dir>, then in that folder run\n")
    for cmd in commands:
        sys.stdout.write(f"    {cmd}\n")


def _verify_bundle(args: argparse.Namespace) -> int:
    try:
        files = read_bundle(args.bundle)
    except (OSError, ValueError, zipfile.BadZipFile) as err:
        sys.stderr.write(f"Could not read {args.bundle} as a bundle: {err}\n")
        return 2
    r = verify_bundle(files)
    failed = not r["ok"] or (args.require_anchor and not r["anchored"])
    anchors = r["anchors"]

    written = None
    if args.tsr_out and anchors:
        os.makedirs(args.tsr_out, exist_ok=True)
        for i, a in enumerate(anchors, 1):
            for name, data in anchor_tsr_files(a, i).items():
                with open(os.path.join(args.tsr_out, name), "wb") as f:
                    f.write(data)
        written = args.tsr_out
    commands = anchor_openssl_commands(anchors)

    if args.json:
        out = {k: v for k, v in r.items() if k != "anchors"}
        out["signature_check"] = {"run": False, "why": SIGNATURE_NOT_RUN, "commands": commands}
        out["hmac_check"] = {"run": False, "why": HMAC_NOT_RUN}
        sys.stdout.write(to_json(out) + "\n")
        return 1 if failed else 0

    sys.stdout.write("APIR evidence bundle\n\n")
    _print_steps(r["steps"])
    if anchors:
        _print_signature_not_run(commands, written)
    sys.stdout.write(f"\n  NOT RUN  {HMAC_NOT_RUN}\n")

    if not r["ok"]:
        verdict = "DOES NOT CHECK: see the step marked FAIL."
    elif not r["anchored"]:
        verdict = ("NOT FULLY DATED: the hashes and links check; a chain in this bundle has no head under an outside "
                   "timestamp." if args.require_anchor else
                   "Checks, not fully dated: a chain in this bundle has no head under an outside timestamp, so "
                   "only its internal consistency is shown.")
    else:
        when = max(r["gen_times"]).replace("T", " ")[:19]
        stamped = sum(c["stamped_entries"] for c in r["chains"])
        total = sum(c["entries"] for c in r["chains"])
        verdict = (f"CHECKS without APIR. {stamped} of {total} entries are under an outside stamp, the latest dated "
                   f"{when} UTC. The authority's signature was not checked here: run the openssl commands above.")
    sys.stdout.write(f"\n{verdict}\n{_LOG_BOOK}\n")
    return 1 if failed else 0


def _verify_anchor(args: argparse.Namespace) -> int:
    try:
        if args.answer == "-":
            raw = sys.stdin.buffer.read()
        else:
            with open(args.answer, "rb") as f:
                raw = f.read()
        answer = load_json(raw)
    except (OSError, ValueError) as err:
        sys.stderr.write(f"Could not read {args.answer} as JSON: {err}\n")
        return 2
    block = answer.get("anchor") if isinstance(answer, dict) and "anchor" in answer else answer
    r = verify_anchor(block)
    written = None
    if args.tsr_out and r["ok"]:
        os.makedirs(args.tsr_out, exist_ok=True)
        for name, data in anchor_tsr_files(block).items():
            with open(os.path.join(args.tsr_out, name), "wb") as f:
                f.write(data)
        written = args.tsr_out
    commands = anchor_openssl_commands([block], numbered=False)
    if args.json:
        out = dict(r)
        out["signature_check"] = {"run": False, "why": SIGNATURE_NOT_RUN, "commands": commands}
        sys.stdout.write(to_json(out) + "\n")
        return 0 if r["ok"] else 1
    sys.stdout.write("APIR agent stamp\n\n")
    _print_steps(r["steps"])
    if isinstance(block, dict) and block.get("tsa_response_der_b64"):
        _print_signature_not_run(commands, written)
    if r["ok"]:
        when = r["gen_time"].replace("T", " ")[:19]
        verdict = (f"CHECKS without APIR. This agent's chain stood at this head no later than {when} UTC. "
                   "The entries themselves are the owner's to share, in an evidence bundle.")
    else:
        verdict = "DOES NOT CHECK: see the step marked FAIL."
    sys.stdout.write(f"\n{verdict}\n")
    return 0 if r["ok"] else 1


def _hash(args: argparse.Namespace) -> int:
    code = 0
    for p in args.files:
        try:
            sys.stdout.write(f"{_file_sha256(p)}  {p}\n")
        except OSError as err:
            sys.stderr.write(f"{p}: {err}\n")
            code = 1
    return code


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="apir-record",
        description="Check an APIR agent record offline: tamper-evident, hash-chained work history for AI agents, "
                    "with RFC 3161 timestamps.",
    )
    ap.add_argument("--version", action="version", version=f"apir-record {__version__}")
    sub = ap.add_subparsers(dest="command", metavar="command")
    sub.required = True

    b = sub.add_parser("verify-bundle", help="check an agent's exported log book offline",
                       description="Check an APIR evidence bundle offline: every file against its manifest, every "
                                   "log book entry's hash and link, and each chain's head against the RFC 3161 "
                                   "token's root, imprint and date.")
    b.add_argument("bundle", help="the bundle zip the Black Box page exports, or the folder it was unpacked into")
    b.add_argument("--require-anchor", action="store_true", help="fail a bundle with a chain not under an outside timestamp")
    b.add_argument("--tsr-out", metavar="DIR", help="write each token and root to DIR for the openssl check")
    b.add_argument("--json", action="store_true", help="print the result as JSON")
    b.set_defaults(run=_verify_bundle)

    a = sub.add_parser("verify-anchor", help="check a public agent's latest stamp offline",
                       description="Check the stamp in a public agent's verify-black-box answer offline: its head is "
                                   "among that night's heads, they rebuild the Merkle root, and the RFC 3161 token "
                                   "names that root with the authority's date.")
    a.add_argument("answer", help="the saved answer, from verify-black-box?agent_id=<id>, or - for standard input")
    a.add_argument("--tsr-out", metavar="DIR", help="write the token and root to DIR for the openssl check")
    a.add_argument("--json", action="store_true", help="print the result as JSON")
    a.set_defaults(run=_verify_anchor)

    v = sub.add_parser("verify-seal", help="check an APIR seal's portable proof offline",
                       description="Check an APIR seal's portable proof (apir-seal-proof/1) offline: the declaration, "
                                   "the hash chain, the Merkle root, and the RFC 3161 token's imprint and date. "
                                   "Files given are matched to the seal byte for byte.")
    v.add_argument("proof", help="the proof file, from https://apir.ai/api/seal/<id>/proof")
    v.add_argument("files", nargs="*", help="files to match against the sealed and process files")
    v.add_argument("--require-anchor", action="store_true", help="fail a proof that is not yet under an outside timestamp")
    v.add_argument("--tsr-out", metavar="DIR", help="write seal.tsr and root.txt to DIR for the openssl check")
    v.add_argument("--json", action="store_true", help="print the result as JSON")
    v.set_defaults(run=_verify_seal)

    h = sub.add_parser("hash", help="print the SHA-256 of files", description="Print the SHA-256 of each file, "
                       "the fingerprint APIR records. '-' reads standard input.")
    h.add_argument("files", nargs="+", metavar="file")
    h.set_defaults(run=_hash)
    return ap


def main(argv: "Sequence[str] | None" = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (ValueError, OSError):
                pass
    args = _parser().parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
