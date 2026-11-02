import base64
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile

from apir_record import chain_hash, load_json, merkle_root, read_bundle, sha256_hex, verify_anchor, verify_bundle
from apir_record import cli

AGENT = "6d9e771a-091b-4409-981e-289a60ecbf4b"
OTHER_HEAD = "ab" * 32


def der(tag, content):
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def fake_token(root, gen_time="20261101000003Z", status=0):
    """A DER response shaped as read_tsa reads one, with no signature: the parser never checks one."""
    alg = der(0x30, der(0x06, bytes.fromhex("608648016503040201")) + der(0x05, b""))
    imprint = der(0x30, alg + der(0x04, hashlib.sha256(root.encode()).digest()))
    info = der(0x30, der(0x02, b"\x01") + der(0x06, b"\x2a\x03") + imprint + der(0x02, b"\x07")
               + der(0x18, gen_time.encode()))
    econtent = bytes([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04]) \
        + der(0xA0, der(0x04, info))
    response = der(0x30, der(0x30, der(0x02, bytes([status]))) + der(0x30, econtent))
    return base64.b64encode(response).decode()


def chain(n=4, agent=AGENT):
    events, prev = [], None
    for i in range(1, n + 1):
        e = load_json(json.dumps({
            "agent_id": agent, "sequence_number": i, "event_type": "audit", "input_hash": None, "output_hash": None,
            "reasoning_summary": f"Run {i}", "prev_chain_hash": prev,
            "timestamp": f"2026-10-3{min(i, 1)}T0{i}:00:00.123456+00:00",
        }).encode()[:-1] + b', "data_accessed": {"trust_score_after": 88.00, "drift_score": 0.00}}')
        e["chain_hash"] = chain_hash(e)
        prev = e["chain_hash"]
        events.append(e)
    return events


def _dumps(value):
    return json.dumps(value, default=str)


def events_json(events, **over):
    head = {"format": "apir.evidence-bundle.v1", "bundle_id": "b-1", "org_id": "o-1", "filters": {},
            "event_count": len(events)}
    head.update(over)
    lines = []
    for e in events:
        rest = {k: v for k, v in e.items() if k != "data_accessed"}
        lines.append(_dumps(rest)[:-1] + ', "data_accessed": {"trust_score_after": 88.00, "drift_score": 0.00}}')
    return (json.dumps(head)[:-1] + ', "events": [' + ",\n".join(lines) + "]}").encode()


def build(events=None, stamp_seq=3, token=None, drop_anchors=False, anchored_at="2026-11-01T00:00:08.327245+00:00"):
    events = chain() if events is None else events
    head = next(e for e in events if e["sequence_number"] == stamp_seq)["chain_hash"]
    heads = [head, OTHER_HEAD]
    root = merkle_root(heads)
    files = {"events.json": events_json(events), "report.pdf": b"%PDF-1.4 a report", "custody.json": b'{"entries": []}'}
    if not drop_anchors:
        files["anchors.json"] = json.dumps({"format": "apir.evidence-anchors.v1", "anchors": [{
            "merkle_root": root, "anchored_at": anchored_at, "tsa_url": "https://freetsa.org/tsr",
            "tsa_certificates": {"tsa_crt": "https://freetsa.org/files/tsa.crt",
                                 "ca_pem": "https://freetsa.org/files/cacert.pem"},
            "tsa_response_der_b64": token or fake_token(root), "heads": heads,
            "covers": [{"agent_id": AGENT, "chain_hash": head}],
        }]}).encode()
    return seal(files, len(events))


def seal(files, event_count):
    listed = {n: {"sha256": hashlib.sha256(d).hexdigest(), "bytes": len(d)} for n, d in files.items()}
    core = {"format": "apir.evidence-manifest.v1", "bundle_id": "b-1", "event_count": event_count, "files": listed}
    payload = json.dumps(core, separators=(",", ":"), ensure_ascii=False)
    manifest = dict(core, manifest_hash=sha256_hex(payload), signature="ab", signature_alg="HMAC-SHA256", verify_hint="x")
    out = dict(files)
    out["manifest.json"] = json.dumps(manifest).encode()
    return out


def reseal(files, event_count=4):
    return seal({k: v for k, v in files.items() if k != "manifest.json"}, event_count)


def failed(r):
    return [s["text"] for s in r["steps"] if s["ok"] is False]


class Passing(unittest.TestCase):
    def test_a_whole_bundle_checks(self):
        r = verify_bundle(build())
        self.assertTrue(r["ok"], failed(r))
        self.assertTrue(r["anchored"])
        self.assertFalse(r["signature_checked"])
        self.assertFalse(r["hmac_checked"])
        self.assertEqual(r["chains"][0]["entries"], 4)
        self.assertEqual(r["chains"][0]["stamped_entries"], 3)
        self.assertEqual(r["chains"][0]["later_entries"], 1)
        self.assertEqual(r["gen_times"], ["2026-11-01T00:00:03.000Z"])

    def test_later_entries_are_named_not_hidden(self):
        r = verify_bundle(build())
        notes = [s["text"] for s in r["steps"] if s["kind"] == "note"]
        self.assertTrue(any("1 later entries are not under a stamp" in n for n in notes), notes)

    def test_old_audit_entries_are_explained(self):
        r = verify_bundle(build())
        self.assertTrue(r["ok"], failed(r))
        self.assertTrue(any("4 audit entries" in s["text"] and "not a rating" in s["text"] for s in r["steps"]))

    def test_new_audit_entries_need_no_explanation(self):
        events = chain()
        prev = None
        for e in events:
            e["data_accessed"] = load_json(b'{"monitor_reading": 88.00}')
            e["prev_chain_hash"] = prev
            e["chain_hash"] = chain_hash(e)
            prev = e["chain_hash"]
        head = {"format": "apir.evidence-bundle.v1", "bundle_id": "b-1", "filters": {}, "event_count": 4}
        lines = [_dumps({k: v for k, v in e.items() if k != "data_accessed"})[:-1]
                 + ', "data_accessed": {"monitor_reading": 88.00}}' for e in events]
        raw = (json.dumps(head)[:-1] + ', "events": [' + ",\n".join(lines) + "]}").encode()
        r = verify_bundle(seal({"events.json": raw}, 4))
        self.assertTrue(r["ok"], failed(r))
        self.assertFalse(any("hourly monitor" in s["text"] for s in r["steps"]))

    def test_numbers_keep_their_written_form(self):
        # 88.00 printed by the database hashes differently from 88: the reason the export must not pass through JS.
        files = build()
        self.assertIn(b"88.00", files["events.json"])
        rewritten = files["events.json"].replace(b"88.00", b"88")
        r = verify_bundle(reseal(dict(files, **{"events.json": rewritten})))
        self.assertFalse(r["ok"])
        self.assertTrue(any("hash to their recorded chain hashes" in t for t in failed(r)))


class Tampering(unittest.TestCase):
    def test_a_changed_file_fails(self):
        files = build()
        files["report.pdf"] = b"%PDF-1.4 another report"
        r = verify_bundle(files)
        self.assertFalse(r["ok"])
        self.assertTrue(any("report.pdf" in t for t in failed(r)))

    def test_a_changed_manifest_fails(self):
        files = build()
        m = json.loads(files["manifest.json"])
        m["event_count"] = 3
        files["manifest.json"] = json.dumps(m).encode()
        self.assertFalse(verify_bundle(files)["ok"])

    def test_a_changed_entry_fails_even_when_every_file_hash_is_redone(self):
        files = build()
        changed = files["events.json"].replace(b"Run 2", b"Run X")
        r = verify_bundle(reseal(dict(files, **{"events.json": changed})))
        self.assertFalse(r["ok"])
        self.assertTrue(any("hash to their recorded chain hashes" in t for t in failed(r)))

    def test_a_removed_entry_fails(self):
        events = chain()
        files = build(events=[e for e in events if e["sequence_number"] != 2], stamp_seq=3)
        r = verify_bundle(files)
        self.assertFalse(r["ok"])
        self.assertTrue(any("names the one before it" in t for t in failed(r)))

    def test_a_token_for_another_root_fails(self):
        r = verify_bundle(build(token=fake_token("another root")))
        self.assertFalse(r["ok"])
        self.assertTrue(any("names exactly this root" in t for t in failed(r)))

    def test_a_refused_token_fails(self):
        events = chain()
        root = merkle_root([events[2]["chain_hash"], OTHER_HEAD])
        self.assertFalse(verify_bundle(build(events=events, token=fake_token(root, status=2)))["ok"])

    def test_a_receipt_date_far_from_the_authoritys_fails(self):
        r = verify_bundle(build(anchored_at="2026-06-01T00:00:00+00:00"))
        self.assertFalse(r["ok"])
        self.assertTrue(any("agrees with the authority's own date" in t for t in failed(r)))

    def test_a_head_not_in_the_bundle_fails(self):
        files = build()
        a = json.loads(files["anchors.json"])
        a["anchors"][0]["covers"][0]["chain_hash"] = OTHER_HEAD
        r = verify_bundle(reseal(dict(files, **{"anchors.json": json.dumps(a).encode()})))
        self.assertFalse(r["ok"])

    def test_an_entry_dated_after_the_stamp_fails(self):
        events = chain()
        root = merkle_root([events[2]["chain_hash"], OTHER_HEAD])
        self.assertFalse(verify_bundle(build(events=events, token=fake_token(root, "20260101000003Z"),
                                             anchored_at="2026-01-01T00:00:08+00:00"))["ok"])


class Undated(unittest.TestCase):
    def test_no_anchors_file_checks_but_is_not_dated(self):
        r = verify_bundle(build(drop_anchors=True))
        self.assertTrue(r["ok"], failed(r))
        self.assertFalse(r["anchored"])
        self.assertTrue(any("carries no timestamp tokens" in s["text"] for s in r["steps"]))

    def test_a_filtered_export_does_not_claim_the_links(self):
        events = [e for e in chain() if e["sequence_number"] != 2]
        files = build(events=events, drop_anchors=True)
        filtered = files["events.json"].replace(b'"filters": {}', b'"filters": {"event_types": ["audit"]}')
        r = verify_bundle(reseal(dict(files, **{"events.json": filtered}), 3))
        self.assertTrue(r["ok"], failed(r))
        self.assertTrue(any("exported by event type" in s["text"] for s in r["steps"]))
        self.assertFalse(any("names the one before it" in s["text"] for s in r["steps"]))


class Anchor(unittest.TestCase):
    def block(self):
        head = "cd" * 32
        heads = [head, OTHER_HEAD]
        root = merkle_root(heads)
        return {"merkle_root": root, "anchored_at": "2026-11-01T00:00:08+00:00", "head_chain_hash": head, "heads": heads,
                "tsa_response_der_b64": fake_token(root)}

    def test_checks(self):
        r = verify_anchor(self.block())
        self.assertTrue(r["ok"])
        self.assertEqual(r["gen_time"], "2026-11-01T00:00:03.000Z")

    def test_reads_the_whole_answer(self):
        self.assertTrue(verify_anchor({"verified": True, "anchor": self.block()})["ok"])

    def test_a_head_outside_the_stamp_fails(self):
        b = self.block()
        b["head_chain_hash"] = "ef" * 32
        self.assertFalse(verify_anchor(b)["ok"])

    def test_nothing_to_check_fails(self):
        self.assertFalse(verify_anchor(None)["ok"])
        self.assertFalse(verify_anchor({"anchor": None})["ok"])


class Commands(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(list(argv))
        return code, out.getvalue()

    def zipped(self, files, folder):
        path = os.path.join(folder, "bundle.zip")
        with zipfile.ZipFile(path, "w") as z:
            for name, data in files.items():
                z.writestr(name, data)
        return path

    def test_verify_bundle_passes_and_says_what_it_did_not_check(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = self.run_cli("verify-bundle", self.zipped(build(), d), "--tsr-out", d)
            self.assertEqual(code, 0, out)
            self.assertIn("CHECKS without APIR", out)
            self.assertIn("3 of 4 entries", out)
            self.assertIn("NOT RUN  The authority's signature", out)
            self.assertIn("NOT RUN  The manifest's HMAC", out)
            self.assertIn("It does not show that the report was complete", out)
            self.assertTrue(os.path.exists(os.path.join(d, "anchor-1.tsr")))
            self.assertTrue(os.path.exists(os.path.join(d, "anchor-1-root.txt")))
            self.assertEqual(read_bundle(os.path.join(d, "bundle.zip"))["report.pdf"], b"%PDF-1.4 a report")

    def test_verify_bundle_exits_1_on_a_bad_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            files = build()
            files["report.pdf"] = b"changed"
            code, out = self.run_cli("verify-bundle", self.zipped(files, d))
            self.assertEqual(code, 1)
            self.assertIn("DOES NOT CHECK", out)

    def test_require_anchor_fails_an_undated_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            path = self.zipped(build(drop_anchors=True), d)
            self.assertEqual(self.run_cli("verify-bundle", path)[0], 0)
            self.assertEqual(self.run_cli("verify-bundle", path, "--require-anchor")[0], 1)

    def test_verify_anchor_reads_a_saved_answer(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "answer.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"verified": True, "anchor": Anchor().block()}, f)
            code, out = self.run_cli("verify-anchor", path)
            self.assertEqual(code, 0, out)
            self.assertIn("stood at this head", out)


if __name__ == "__main__":
    unittest.main()
