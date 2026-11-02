import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from apir_record import APIRError, EventsClient, make_event, sha256_hex
from apir_record.events import EVENT_TYPES, MAX_BATCH

AGENT = "88f94b9c-47da-4bd5-89b1-97218d8f6c4f"


class FakeAPIR:
    """A local stand-in for POST /api/v1/events: records each request and answers from a script."""

    def __init__(self, answers=None):
        self.requests = []
        self.answers = list(answers or [])
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                fake.requests.append({"path": self.path, "headers": dict(self.headers), "body": json.loads(body)})
                status, answer = fake.answers.pop(0) if fake.answers else (201, None)
                if answer is None:
                    events = fake.requests[-1]["body"]["events"]
                    answer = {"recorded": len(events), "agent_id": AGENT, "events": [
                        {"id": f"id-{len(fake.requests)}-{i}", "sequence": i + 1, "chain_hash": "ab" * 32,
                         "type": e["type"], "at": "2026-11-01T00:00:00+00:00"} for i, e in enumerate(events)]}
                raw = json.dumps(answer).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/api/v1/events"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class MakeEvent(unittest.TestCase):
    def test_content_is_hashed_and_never_kept(self):
        e = make_event("decision", "  Approved refund #4521 under the agent's limit  ", input="the prompt", output=b"the answer",
                       data={"tool": "refunds"})
        self.assertEqual(e, {"type": "decision", "summary": "Approved refund #4521 under the agent's limit",
                             "input_hash": sha256_hex("the prompt"), "output_hash": sha256_hex(b"the answer"),
                             "data": {"tool": "refunds"}})
        self.assertNotIn("the prompt", json.dumps(e))

    def test_types_are_the_endpoints(self):
        self.assertEqual(EVENT_TYPES, {"action", "decision", "tool_call", "input", "output", "reasoning", "data_access", "error"})
        self.assertEqual(make_event(" TOOL_CALL ", "x")["type"], "tool_call")
        for bad in ("tool_use", "registration", "kill_switch", "", None):
            with self.subTest(bad):
                with self.assertRaises(ValueError):
                    make_event(bad, "x")

    def test_summary_rules(self):
        with self.assertRaises(ValueError):
            make_event("action", "   ")
        make_event("action", "x" * 1000)
        with self.assertRaises(ValueError):
            make_event("action", "x" * 1001)
        with self.assertRaises(ValueError):  # 501 astral characters are 1,002 UTF-16 units, as the endpoint counts
            make_event("action", "\U0001F600" * 501)

    def test_hash_rules(self):
        self.assertEqual(make_event("action", "x", input_hash="AB" * 32)["input_hash"], "ab" * 32)
        self.assertIsNone(make_event("action", "x", input_hash="")["input_hash"])
        for bad in ("ab" * 31, "zz" * 32, "ab" * 32 + "\n", 5):
            with self.subTest(bad):
                with self.assertRaises(ValueError):
                    make_event("action", "x", input_hash=bad)
        with self.assertRaises(ValueError):
            make_event("action", "x", input="a", input_hash="ab" * 32)
        with self.assertRaises(TypeError):
            make_event("action", "x", input={"not": "bytes"})

    def test_data_rules(self):
        self.assertEqual(make_event("action", "x")["data"], {})
        with self.assertRaises(ValueError):
            make_event("action", "x", data=["not", "an", "object"])
        make_event("action", "x", data={"k": "v" * (8192 - 8)})
        with self.assertRaises(ValueError):
            make_event("action", "x", data={"k": "v" * (8192 - 7)})


class Client(unittest.TestCase):
    def test_key_and_agent_required(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                EventsClient(AGENT)
        with self.assertRaises(ValueError):
            EventsClient("not-a-uuid", "key")
        with mock.patch.dict(os.environ, {"APIR_API_KEY": "from-env"}):
            self.assertEqual(EventsClient(AGENT)._key, "from-env")

    def test_key_is_not_in_repr(self):
        self.assertNotIn("secret-key", repr(EventsClient(AGENT, "secret-key")))

    def test_one_event_on_the_wire(self):
        with FakeAPIR() as api:
            r = EventsClient(AGENT, "k_test", url=api.url).record("tool_call", "Searched the supplier register",
                                                                   input="query text", data={"tool": "search"})
        self.assertEqual(r["recorded"], 1)
        req = api.requests[0]
        self.assertEqual(req["path"], "/api/v1/events")
        self.assertEqual(req["headers"]["Authorization"], "Bearer k_test")
        self.assertEqual(req["headers"]["Content-Type"], "application/json")
        self.assertTrue(req["headers"]["User-Agent"].startswith("apir-record/"))
        self.assertEqual(req["body"], {"agent_id": AGENT, "events": [
            {"type": "tool_call", "summary": "Searched the supplier register", "input_hash": sha256_hex("query text"),
             "output_hash": None, "data": {"tool": "search"}}]})

    def test_batches_of_fifty_in_order(self):
        events = [make_event("action", f"step {i}") for i in range(MAX_BATCH * 2 + 20)]
        with FakeAPIR() as api:
            r = EventsClient(AGENT, "k", url=api.url).send(events)
        self.assertEqual([len(q["body"]["events"]) for q in api.requests], [50, 50, 20])
        self.assertEqual(r["recorded"], 120)
        self.assertEqual([q["body"]["events"][0]["summary"] for q in api.requests], ["step 0", "step 50", "step 100"])

    def test_every_event_checked_before_anything_is_sent(self):
        with FakeAPIR() as api:
            with self.assertRaises(ValueError):
                EventsClient(AGENT, "k", url=api.url).send([make_event("action", "fine"), {"type": "action", "summary": ""}])
        self.assertEqual(api.requests, [])

    def test_raw_content_keys_are_refused(self):
        with self.assertRaises(ValueError):
            EventsClient(AGENT, "k").send([{"type": "action", "summary": "x", "input": "the raw prompt"}])

    def test_refusal_carries_the_reason(self):
        with FakeAPIR([(401, {"error": "A valid API key is required."})]) as api:
            with self.assertRaises(APIRError) as ctx:
                EventsClient(AGENT, "bad", url=api.url).record("action", "x")
        self.assertEqual(ctx.exception.status, 401)
        self.assertIn("A valid API key is required.", str(ctx.exception))
        self.assertEqual(ctx.exception.recorded, 0)

    def test_partial_recording_is_counted(self):
        answers = [(201, None), (207, {"error": "Recording stopped at this event; the ones before it are on the record.",
                                       "recorded": 7, "failed_at": 7})]
        events = [make_event("action", f"step {i}") for i in range(80)]
        with FakeAPIR(answers) as api:
            with self.assertRaises(APIRError) as ctx:
                EventsClient(AGENT, "k", url=api.url).send(events)
        self.assertEqual(ctx.exception.status, 207)
        self.assertEqual(ctx.exception.recorded, 57)
        self.assertEqual(len(ctx.exception.events), 50)

    def test_no_answer(self):
        with self.assertRaises(APIRError) as ctx:
            EventsClient(AGENT, "k", url="http://127.0.0.1:9/api/v1/events", timeout=2).record("action", "x")
        self.assertIsNone(ctx.exception.status)
        self.assertIn("may or may not be on the record", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
