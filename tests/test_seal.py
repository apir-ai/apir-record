import base64
import json
import os
import unittest
from decimal import Decimal

from apir_record import chain_hash, event_canonical, merkle_root, read_tsa, sha256_hex, stable_stringify, verify_proof
from apir_record.seal import load_proof, openssl_commands, tsr_files

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "fixtures", "seal-proof.json"), "rb") as f:
    RAW = f.read()
SEALED_FILE = "1cc5be7e5f2271bc2f46c1a2dd4231978164910c7251a0a00c1ee0f67cba098f"


def real():
    return load_proof(RAW)


def failed(r):
    return [s["text"] for s in r["steps"] if s["ok"] is False]


class RealProof(unittest.TestCase):
    def test_passes_untouched(self):
        r = verify_proof(real())
        self.assertTrue(r["ok"], failed(r))
        self.assertTrue(r["anchored"])
        self.assertEqual(r["gen_time"], "2026-09-19T00:00:07.000Z")
        self.assertFalse(r["signature_checked"])
        self.assertEqual(sum(1 for s in r["steps"] if s["kind"] == "check"), 7)
        self.assertTrue(all(s["ok"] is True for s in r["steps"]))

    def test_the_token(self):
        t = read_tsa(real()["anchor"]["tsa_response_der_b64"])
        self.assertEqual(t["status"], 0)
        self.assertTrue(t["sha256"])
        self.assertEqual(t["hashed"], sha256_hex(real()["anchor"]["merkle_root"]))
        self.assertEqual(t["gen_time"], "20260919000007Z")

    def test_the_root(self):
        heads = [h["chain_hash"] for h in real()["anchor"]["chain_heads"]]
        self.assertEqual(merkle_root(heads), real()["anchor"]["merkle_root"])
        self.assertEqual(merkle_root(list(reversed(heads))), real()["anchor"]["merkle_root"])
        self.assertEqual(merkle_root([]), "")

    def test_a_sealed_file_matches(self):
        r = verify_proof(real(), [{"name": "copy.pdf", "sha256": SEALED_FILE}])
        self.assertTrue(r["files_ok"])
        self.assertEqual(r["files"][0]["as"], "specimen-triage-verdict.pdf")


class Tampering(unittest.TestCase):
    def check_fails(self, change):
        p = real()
        change(p)
        r = verify_proof(p)
        self.assertFalse(r["ok"])
        return r

    def test_one_byte_of_the_declaration(self):
        self.check_fails(lambda p: p.__setitem__("declaration_canonical", p["declaration_canonical"].replace("Slav", "Slaw")))

    def test_one_byte_of_the_chain(self):
        def change(p):
            c = p["chain"][0]["canonical"]
            i = c.index('"event_type"')
            p["chain"][0]["canonical"] = c[:i] + c[i:].replace("action", "actiom", 1)
        self.check_fails(change)

    def test_recorded_after_the_authority_dated_the_chain(self):
        self.check_fails(lambda p: p.__setitem__("recorded_at", "2026-12-01T00:00:00Z"))

    def test_anchor_date_that_disagrees_with_the_authority(self):
        self.check_fails(lambda p: p["anchor"].__setitem__("anchored_at", "2026-08-01T00:00:00Z"))

    def test_token_that_names_another_root(self):
        self.check_fails(lambda p: p["anchor"].__setitem__("merkle_root", "f" * 64))

    def test_head_not_among_the_nights_heads(self):
        self.check_fails(lambda p: p["anchor"]["chain_heads"].pop(10))

    def test_truncated_token(self):
        r = self.check_fails(lambda p: p["anchor"].__setitem__("tsa_response_der_b64", p["anchor"]["tsa_response_der_b64"][:400]))
        self.assertIn("truncated", " ".join(str(s["detail"]) for s in r["steps"]))

    def test_not_a_proof(self):
        r = verify_proof({"format": "something-else"})
        self.assertFalse(r["ok"])
        self.assertEqual(r["steps"][0]["text"], "This is not a proof file this checker reads.")

    def test_a_file_that_is_not_on_the_seal(self):
        r = verify_proof(real(), [{"name": "other.txt", "sha256": sha256_hex("not the sealed file")}])
        self.assertTrue(r["ok"])
        self.assertFalse(r["files_ok"])
        self.assertIn("is not one of the sealed or process files", r["steps"][-1]["text"])


class NotYetDated(unittest.TestCase):
    def test_checks_but_is_not_anchored(self):
        p = real()
        p["anchor"] = None
        p["not_yet_anchored"] = "Tonight."
        r = verify_proof(p)
        self.assertTrue(r["ok"])
        self.assertFalse(r["anchored"])
        self.assertIn(None, [s["ok"] for s in r["steps"]])
        self.assertEqual(openssl_commands(p), [])
        self.assertEqual(tsr_files(p), {})


class LaterActs(unittest.TestCase):
    """A segment that runs past the seal into later acts on it. No anchor: the head is not a real night's head."""

    def segment(self, *acts, tamper=False):
        p = real()
        p["anchor"] = None
        first = load_proof(p["chain"][0]["canonical"])
        for n, a in enumerate(acts):
            prev = p["chain"][-1]
            fields = {"agent_id": first["agent_id"], "sequence_number": prev["sequence_number"] + 1, "event_type": "action",
                      "input_hash": "9" * 64 if tamper else sha256_hex(stable_stringify(a)), "output_hash": None,
                      "reasoning_summary": f"{a['act']} on seal {p['seal_id']}", "data_accessed": {"act": a, "source": "seal_act"},
                      "timestamp": f"2026-10-31T0{n}:00:00+00:00", "prev_chain_hash": prev["chain_hash"]}
            text = event_canonical(fields)
            p["chain"].append({"sequence_number": fields["sequence_number"], "chain_hash": chain_hash(fields), "canonical": text})
        return p

    def act(self, kind, **body):
        return {"act": kind, "seal_id": real()["seal_id"], "actor": {"name": "Test Fixture"}, "at": "2026-10-31T00:00:00.000Z",
                "body": body, "version": 1}

    def test_acts_recompute_and_process_files_match(self):
        statement = self.act("statement", share=Decimal("0.25"), components=[{"key": "image", "band": "none"}])
        process = self.act("process", files=[{"name": "draft-1.png", "sha256": "cd" * 32, "size": 10}])
        p = self.segment(statement, process)
        r = verify_proof(p, [{"name": "mine.png", "sha256": "cd" * 32}, {"name": "copy.pdf", "sha256": SEALED_FILE}])
        self.assertTrue(r["ok"], failed(r))
        self.assertEqual([a["act"] for a in r["acts"]], ["statement", "process"])
        self.assertTrue(all(a["intact"] for a in r["acts"]))
        self.assertEqual([f["match"] for f in r["files"]], ["process", "sealed"])
        self.assertIn("2 later acts on this seal", " ".join(s["text"] for s in r["steps"]))

    def test_a_changed_act_fails(self):
        r = verify_proof(self.segment(self.act("attestation", role="client"), tamper=True))
        self.assertFalse(r["ok"])
        self.assertFalse(r["acts"][0]["intact"])

    def test_a_reformatted_event_text_is_noted_not_failed(self):
        p = self.segment(self.act("statement"))
        entry = p["chain"][1]
        entry["canonical"] = json.dumps(json.loads(entry["canonical"]), separators=(",", ":"))
        entry["chain_hash"] = sha256_hex(entry["canonical"])
        r = verify_proof(p)
        self.assertTrue(r["ok"], failed(r))
        notes = [s for s in r["steps"] if s["kind"] == "note"]
        self.assertEqual(len(notes), 1)
        self.assertIsNone(notes[0]["ok"])
        self.assertIn("#3", notes[0]["detail"])


class TokenFiles(unittest.TestCase):
    def test_tsr_and_root_for_openssl(self):
        p = real()
        files = tsr_files(p)
        self.assertEqual(files["seal.tsr"], base64.b64decode(p["anchor"]["tsa_response_der_b64"]))
        self.assertEqual(files["root.txt"], p["anchor"]["merkle_root"].encode())
        self.assertEqual(openssl_commands(p)[-1],
                         "openssl ts -verify -in seal.tsr -data root.txt -CAfile cacert.pem -untrusted tsa.crt")
        self.assertEqual(openssl_commands(p)[0], "curl -s -o tsa.crt https://freetsa.org/files/tsa.crt")


if __name__ == "__main__":
    unittest.main()
