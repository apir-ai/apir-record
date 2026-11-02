import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from apir_record.cli import main

HERE = os.path.dirname(os.path.abspath(__file__))
PROOF = os.path.join(HERE, "fixtures", "seal-proof.json")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class VerifySeal(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_real_proof_checks_and_says_what_it_did_not_run(self):
        code, out, _ = run("verify-seal", PROOF, "--tsr-out", self.dir)
        self.assertEqual(code, 0)
        self.assertIn("CHECKS without APIR", out)
        self.assertIn("NOT RUN", out)
        self.assertIn("did not check it", out)
        self.assertIn("openssl ts -verify -in seal.tsr -data root.txt -CAfile cacert.pem -untrusted tsa.crt", out)
        self.assertIn("APIR did not determine how the work was made.", out)
        self.assertNotIn("FAIL", out)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "seal.tsr")))
        with open(os.path.join(self.dir, "root.txt"), "rb") as f:
            self.assertEqual(f.read(), b"fa143627a9664ddd76b5d900c2d026ae61f4dd0a36f6836ff7379b46ba11ef8b")

    def test_tampered_proof_exits_1(self):
        with open(PROOF, encoding="utf-8") as f:
            p = json.load(f)
        p["declaration_canonical"] = p["declaration_canonical"].replace("Slav", "Slaw")
        path = os.path.join(self.dir, "p.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(p, f)
        code, out, _ = run("verify-seal", path)
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertIn("DOES NOT CHECK", out)

    def test_a_file_not_on_the_seal_exits_1(self):
        other = os.path.join(self.dir, "other.txt")
        with open(other, "w") as f:
            f.write("not the sealed file")
        code, out, _ = run("verify-seal", PROOF, other)
        self.assertEqual(code, 1)
        self.assertIn("is not one of the sealed or process files", out)

    def test_require_anchor(self):
        with open(PROOF, encoding="utf-8") as f:
            p = json.load(f)
        p["anchor"] = None
        path = os.path.join(self.dir, "p.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(p, f)
        self.assertEqual(run("verify-seal", path)[0], 0)
        code, out, _ = run("verify-seal", path, "--require-anchor")
        self.assertEqual(code, 1)
        self.assertIn("NOT YET DATED", out)

    def test_json(self):
        code, out, _ = run("verify-seal", PROOF, "--json")
        self.assertEqual(code, 0)
        r = json.loads(out)
        self.assertTrue(r["ok"])
        self.assertFalse(r["signature_check"]["run"])
        self.assertIn("openssl", r["signature_check"]["commands"][-1])

    def test_unreadable_proof_exits_2(self):
        path = os.path.join(self.dir, "bad.json")
        with open(path, "w") as f:
            f.write("{not json")
        self.assertEqual(run("verify-seal", path)[0], 2)
        self.assertEqual(run("verify-seal")[0], 2)


class Hash(unittest.TestCase):
    def test_prints_sha256(self):
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "x.txt")
            with open(path, "wb") as f:
                f.write(b"abc")
            code, out, _ = run("hash", path)
            self.assertEqual(code, 0)
            self.assertEqual(out, f"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  {path}\n")
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
