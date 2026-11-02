import copy
import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from apir_record import chain_hash, event_canonical, jsonb_text, load_json, sha256_hex, stable_stringify, verify_chain
from apir_record.canonical import EVENT_FIELDS, pg_timestamp_text

HERE = os.path.dirname(os.path.abspath(__file__))


def fixture(name):
    with open(os.path.join(HERE, "fixtures", name), "rb") as f:
        return f.read().decode("utf-8")


VECTORS = json.loads(fixture("canonical-vectors.json"))


def event_from(v):
    e = dict(v["event"])
    e["data_accessed"] = load_json(v["data_accessed_json"])
    return e


class PostgresVectors(unittest.TestCase):
    def test_canonical_text_is_what_postgres_printed(self):
        for v in VECTORS["postgres"]:
            with self.subTest(v["name"]):
                self.assertEqual(event_canonical(event_from(v)), v["canonical"])
                self.assertEqual(chain_hash(event_from(v)), v["chain_hash"])

    def test_recorded_events_recompute_to_their_stored_hash(self):
        for v in VECTORS["recorded"]:
            with self.subTest(v["name"]):
                self.assertEqual(chain_hash(event_from(v)), v["chain_hash"])

    def test_the_sealed_event_in_the_proof_rebuilds_from_its_own_fields(self):
        proof = json.loads(fixture("seal-proof.json"))
        entry = proof["chain"][0]
        fields = load_json(entry["canonical"])
        self.assertEqual(set(fields), set(EVENT_FIELDS))
        self.assertEqual(event_canonical(fields), entry["canonical"])
        self.assertEqual(chain_hash(fields), entry["chain_hash"])

    def test_one_changed_field_changes_the_hash(self):
        v = VECTORS["recorded"][0]
        e = event_from(v)
        e["reasoning_summary"] = e["reasoning_summary"].replace("8", "9", 1)
        self.assertNotEqual(chain_hash(e), v["chain_hash"])


class JsonbRendering(unittest.TestCase):
    def test_keys_shorter_first_then_by_utf8_bytes(self):
        self.assertEqual(jsonb_text({"bb": 1, "a": 2, "é": 3, "ab": 4, "": 5}),
                         '{"": 5, "a": 2, "ab": 4, "bb": 1, "é": 3}')

    def test_separators_and_empty_containers(self):
        self.assertEqual(jsonb_text({"a": [1, [], {}], "b": None}), '{"a": [1, [], {}], "b": null}')

    def test_string_escapes(self):
        self.assertEqual(jsonb_text('q" b\\ /\n\t\x01\x7fü'), '"q\\" b\\\\ /\\n\\t\\u0001\x7fü"')

    def test_numbers_print_as_numeric(self):
        parsed = load_json("[1.50, 1e3, -0, 1E-7, -1.5e+2, 2.5E1, 0.10, 12345678901234567890123]")
        self.assertEqual(jsonb_text(parsed), "[1.50, 1000, 0, 0.0000001, -150, 25, 0.10, 12345678901234567890123]")

    def test_python_floats_print_by_their_shortest_text(self):
        self.assertEqual(jsonb_text([0.95, 1e-07, 1e21, 100.0]), "[0.95, 0.0000001, 1000000000000000000000, 100.0]")

    def test_refuses_what_jsonb_cannot_hold(self):
        for bad in (float("nan"), float("inf"), "a\x00b", "\ud800", {1: "x"}, object()):
            with self.subTest(repr(bad)):
                with self.assertRaises((ValueError, TypeError)):
                    jsonb_text(bad)

    def test_load_json_refuses_nan(self):
        with self.assertRaises(ValueError):
            load_json("[NaN]")


class Timestamps(unittest.TestCase):
    def test_forms_that_name_the_same_instant(self):
        want = "2026-09-18T07:30:09.596951+00:00"
        for text in ("2026-09-18T07:30:09.596951+00:00", "2026-09-18 07:30:09.596951+00", "2026-09-18T07:30:09.596951Z",
                     "2026-09-18T17:00:09.596951+09:30"):
            with self.subTest(text):
                self.assertEqual(pg_timestamp_text(text), want)

    def test_seventh_digit_rounds_as_postgres_rounds_it(self):
        # What Postgres 17 printed for to_jsonb(<text>::timestamptz) in a UTC session, 2026-11-01.
        printed = {
            "2026-09-18 07:30:09.5969505+00": "2026-09-18T07:30:09.59695+00:00",
            "2026-09-18 07:30:09.5969515+00": "2026-09-18T07:30:09.596952+00:00",
            "2026-09-18 07:30:09.0000005+00": "2026-09-18T07:30:09+00:00",
            "2026-09-18 07:30:09.0000015+00": "2026-09-18T07:30:09.000002+00:00",
            "2026-09-18 07:30:09.0000025+00": "2026-09-18T07:30:09.000002+00:00",
            "2026-09-18 07:30:09.9999995+00": "2026-09-18T07:30:10+00:00",
            "2026-09-18 07:30:09.12345649+00": "2026-09-18T07:30:09.123456+00:00",
            "2026-09-18 07:30:09.1234565+00": "2026-09-18T07:30:09.123456+00:00",
            "2026-09-18 07:30:09.1234575+00": "2026-09-18T07:30:09.123458+00:00",
        }
        for text, want in printed.items():
            with self.subTest(text):
                self.assertEqual(pg_timestamp_text(text), want)

    def test_fraction_trailing_zeros_dropped_and_whole_seconds_bare(self):
        self.assertEqual(pg_timestamp_text("2026-05-21T00:01:19.984780+00:00"), "2026-05-21T00:01:19.98478+00:00")
        self.assertEqual(pg_timestamp_text("2026-03-04 05:06:07+00"), "2026-03-04T05:06:07+00:00")

    def test_datetimes(self):
        aware = datetime(2026, 1, 2, 3, 4, 5, 500000, tzinfo=timezone(timedelta(hours=9, minutes=30)))
        self.assertEqual(pg_timestamp_text(aware), "2026-01-01T17:34:05.5+00:00")
        self.assertEqual(pg_timestamp_text(datetime(2026, 1, 1)), "2026-01-01T00:00:00+00:00")

    def test_refuses_what_is_not_a_timestamp(self):
        with self.assertRaises(ValueError):
            pg_timestamp_text("yesterday")


class EventFields(unittest.TestCase):
    def test_agent_id_normalised_and_extra_keys_ignored(self):
        v = VECTORS["postgres"][0]
        e = event_from(v)
        e["agent_id"] = e["agent_id"].lower()
        e["chain_hash"] = "ignored"
        e["id"] = "ignored"
        self.assertEqual(event_canonical(e), v["canonical"])

    def test_missing_field(self):
        e = event_from(VECTORS["recorded"][0])
        del e["timestamp"]
        with self.assertRaises(KeyError):
            event_canonical(e)

    def test_bad_types(self):
        base = event_from(VECTORS["recorded"][0])
        for field, bad in (("sequence_number", True), ("sequence_number", 2 ** 63), ("event_type", 5), ("agent_id", "nope")):
            e = dict(base)
            e[field] = bad
            with self.subTest(field=field, bad=bad):
                with self.assertRaises((TypeError, ValueError)):
                    event_canonical(e)


def make_chain(n):
    events, prev = [], None
    for i in range(1, n + 1):
        e = {"agent_id": "00000000-0000-4000-8000-0000000000aa", "sequence_number": i, "event_type": "action",
             "input_hash": sha256_hex(f"in {i}"), "output_hash": None, "reasoning_summary": f"step {i}",
             "data_accessed": {"i": i}, "timestamp": f"2026-11-01T00:00:{i:02d}+00:00", "prev_chain_hash": prev}
        e["chain_hash"] = chain_hash(e)
        prev = e["chain_hash"]
        events.append(e)
    return events


class VerifyChain(unittest.TestCase):
    def test_intact(self):
        r = verify_chain(make_chain(4))
        self.assertTrue(r["ok"])
        self.assertEqual(r["total_events"], 4)

    def test_changed_content_is_named(self):
        events = make_chain(4)
        events[2]["reasoning_summary"] = "step three, edited"
        r = verify_chain(events)
        self.assertFalse(r["content_intact"])
        self.assertEqual(r["tampered_sequences"], [3])
        self.assertTrue(r["links_intact"])

    def test_rewritten_hash_breaks_the_next_link(self):
        events = make_chain(4)
        events[1]["reasoning_summary"] = "rewritten"
        events[1]["chain_hash"] = chain_hash(events[1])
        r = verify_chain(events)
        self.assertTrue(r["content_intact"])
        self.assertEqual(r["broken_link_sequences"], [3])

    def test_removed_event_is_a_gap(self):
        events = make_chain(4)
        del events[1]
        r = verify_chain(events)
        self.assertEqual(r["sequence_gap_at"], 3)
        self.assertFalse(r["ok"])

    def test_empty_is_not_ok(self):
        self.assertFalse(verify_chain([])["ok"])


class ActForm(unittest.TestCase):
    def test_matches_stableStringify_under_node(self):
        for v in VECTORS["act_form"]:
            with self.subTest(v["json"][:40]):
                self.assertEqual(stable_stringify(load_json(v["json"])), v["stable_stringify"])

    def test_keys_in_utf16_order(self):
        self.assertEqual(stable_stringify({"￿": 1, "\U0001F600": 2}), '{"\U0001F600":2,"￿":1}')

    def test_numbers_as_javascript_prints_them(self):
        cases = {1.5: "1.5", 1e21: "1e+21", 1e-7: "1e-7", 100.0: "100", 0.000001: "0.000001", 2.5e20: "250000000000000000000",
                 -0.0: "0", 5e-324: "5e-324", 1.23e-18: "1.23e-18"}
        for value, want in cases.items():
            with self.subTest(value):
                self.assertEqual(stable_stringify(value), want)
        self.assertEqual(stable_stringify(Decimal("1.50")), "1.5")
        self.assertEqual(stable_stringify(9007199254740993), "9007199254740992")
        self.assertEqual(stable_stringify(float("nan")), "null")

    def test_does_not_mutate(self):
        value = {"b": [3, 1], "a": {"d": 1, "c": 2}}
        before = copy.deepcopy(value)
        stable_stringify(value)
        self.assertEqual(value, before)


if __name__ == "__main__":
    unittest.main()
