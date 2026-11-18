from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

from prototype import (
    AggregatingOP, Binding, CP, KeyPair, OP, RP, make_server, receive, verify,
)


class CollectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workspace = TemporaryDirectory()
        cls.addClassCleanup(workspace.cleanup)
        directory = Path(workspace.name)
        cls.cp_key = KeyPair.generate(directory, "cp")
        cls.op_key = KeyPair.generate(directory, "op")
        cls.server, cls.tls = make_server(directory, cls.cp_key.private)
        cls.addClassCleanup(cls.server.server_close)
        thread = Thread(target=cls.server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(thread.join)
        cls.addClassCleanup(cls.server.shutdown)

    def setUp(self):
        self.alice = Binding("op-alice", CP, "cp-alice")
        self.op = AggregatingOP(
            f"https://127.0.0.1:{self.server.server_port}/claims",
            self.tls, self.cp_key.public, self.op_key.private,
            {"op-alice": self.alice},
            {(self.alice, RP): {"birthdate"}},
        )

    def deliver_to_rp(self):
        presentation = self.op.deliver("op-alice", RP)
        self.assertEqual(
            receive(presentation, self.op_key.public, self.cp_key.public, "op-alice"),
            {"birthdate": "1990-01-01"},
        )
        return verify(presentation, self.op_key.public, "JWT", OP, RP)

    def test_successful_collection_and_delivery(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])
        self.assertEqual(record.binding, self.alice)
        result = self.deliver_to_rp()
        self.assertEqual(result["_claim_sources"], {"cp1": {"JWT": record.jwt}})
        self.assertNotIn("account_ref", result)
        self.assertNotIn("nonce", result)

    def test_empty_result_creates_no_record_and_preserves_cached_jwt(self):
        self.assertIsNone(self.op.collect("op-alice", "fixture-alice", ["address"]))
        self.assertEqual(self.op.records, {})
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])
        self.assertIsNone(self.op.collect("op-alice", "fixture-alice", ["address"]))
        self.assertIs(self.op.records[self.alice], record)

    def test_redisclosure_preserves_exact_jwt_without_cp_contact(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])
        before = self.server.collections
        first = self.deliver_to_rp()
        second = self.deliver_to_rp()
        self.assertEqual(first["_claim_sources"], second["_claim_sources"])
        self.assertEqual(second["_claim_sources"]["cp1"]["JWT"], record.jwt)
        self.assertEqual(self.server.collections, before)

    def test_wrong_cp_account_is_rejected_without_replacing_binding_or_jwt(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])
        with self.assertRaisesRegex(ValueError, "CP account binding mismatch"):
            self.op.collect("op-alice", "fixture-bob", ["birthdate"])
        self.assertEqual(self.op.bindings["op-alice"], self.alice)
        self.assertIs(self.op.records[self.alice], record)
        self.assertEqual(self.op.pending, {})
        self.deliver_to_rp()


if __name__ == "__main__":
    unittest.main(verbosity=2)
