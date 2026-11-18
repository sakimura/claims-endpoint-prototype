from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from prototype import (
    AggregatingOP, Binding, CLAIM_SET_TYPE, CP, ClaimsEndpoint, Collection,
    KeyPair, OP, RP, b64, json_bytes, make_server, openssl, parse_object,
    receive, sign, timestamps, verify, verify_claim_set,
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
            {self.alice: {"birthdate"}},
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

    def test_bearer_token_and_scope_errors_are_distinct_from_empty_success(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])
        cases = (
            ("fixture-invalid", 401, "invalid_token"),
            ("fixture-alice-no-claims-scope", 403, "insufficient_scope"),
        )
        for token, status, error in cases:
            with self.subTest(error=error):
                with self.assertRaises(HTTPError) as rejected:
                    self.op.collect("op-alice", token, ["birthdate"])
                with rejected.exception as response:
                    self.assertEqual(response.code, status)
                    self.assertEqual(response.headers["WWW-Authenticate"], f'Bearer error="{error}"')
                    self.assertEqual(parse_object(response.read()), {"error": error})
                self.assert_previous_state(record)

        self.assertIsNone(self.op.collect("op-alice", "fixture-alice", ["address"]))
        self.assert_previous_state(record)

    def test_partial_result_delivers_only_requested_and_authorized_attributes(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate", "address"])
        presentation = self.deliver_to_rp()
        self.assertEqual(presentation["_claim_names"], {"birthdate": "cp1"})
        embedded = presentation["_claim_sources"]["cp1"]["JWT"]
        self.assertEqual(embedded, record.jwt)
        self.assertEqual(verify_claim_set(embedded, self.cp_key.public), {
            "birthdate": "1990-01-01",
        })

    def test_rp_does_not_complete_when_required_attribute_is_missing(self):
        self.op.collect("op-alice", "fixture-alice", ["birthdate", "address"])
        presentation = self.op.deliver("op-alice", RP)

        self.assertEqual(
            receive(presentation, self.op_key.public, self.cp_key.public, "op-alice",
                    required_claims={"birthdate"}),
            {"birthdate": "1990-01-01"},
        )
        with self.assertRaisesRegex(ValueError, "required claims unavailable"):
            receive(presentation, self.op_key.public, self.cp_key.public, "op-alice",
                    required_claims={"birthdate", "address"})

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

    def assert_previous_state(self, record):
        self.assertEqual(self.op.bindings, {"op-alice": self.alice})
        self.assertEqual(set(self.op.records), {self.alice})
        self.assertIs(self.op.records[self.alice], record)
        self.assertEqual(self.op.pending, {})
        result = self.deliver_to_rp()
        self.assertEqual(result["_claim_sources"]["cp1"]["JWT"], record.jwt)

    def collect_with_response(self, make_body, names=("birthdate",)):
        def respond(handler, status, body):
            payload = make_body(body["nonce"])
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Cache-Control", "no-store")
            handler.send_header("Content-Length", str(len(payload)))
            handler.end_headers()
            handler.wfile.write(payload)

        with patch.object(ClaimsEndpoint, "respond", respond):
            return self.op.collect("op-alice", "fixture-alice", names)

    def test_reject_invalid_acquisition_envelopes_without_changing_state(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])
        cases = (
            ("wrong nonce", lambda n: json_bytes({"nonce": n + "a"})),
            ("missing nonce", lambda n: b"{}"),
            ("empty nonce", lambda n: b'{"nonce":""}'),
            ("non-string nonce", lambda n: b'{"nonce":1}'),
            ("error in HTTP 200", lambda n: json_bytes({"nonce": n, "error": "invalid_request"})),
            ("account without Claim Set", lambda n: json_bytes({"nonce": n, "account_ref": "cp-alice"})),
            ("null Claim Set", lambda n: json_bytes({"nonce": n, "account_ref": "cp-alice", "claim_set": None})),
            ("empty Claim Set string", lambda n: json_bytes({"nonce": n, "account_ref": "cp-alice", "claim_set": ""})),
            ("Claim Set without account", lambda n: json_bytes({"nonce": n, "claim_set": record.jwt})),
            ("non-object response", lambda n: b"[]"),
            ("malformed JSON", lambda n: b"{"),
            ("duplicate decoded name", lambda n: b'{"nonce":' + json_bytes(n) + rb',"\u006eonce":"other"}'),
        )
        for name, make_body in cases:
            with self.subTest(name=name):
                before = self.server.collections
                with self.assertRaises(ValueError):
                    self.collect_with_response(make_body)
                self.assertEqual(self.server.collections, before + 1)
                self.assert_previous_state(record)

    def test_reject_responses_for_expired_and_completed_operations(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])
        now = time.monotonic()
        for name, deadline in (("expired", now - 1), ("completed", now + 60)):
            with self.subTest(name=name):
                response = {
                    "nonce": name,
                    "account_ref": "cp-alice",
                    "claim_set": record.jwt,
                }
                self.op.pending[name] = Collection(
                    self.alice, frozenset({"birthdate"}), frozenset({"birthdate"}), deadline,
                )
                if name == "completed":
                    self.assertIsNone(self.op.accept(name, {"nonce": name}))
                with self.assertRaisesRegex(ValueError, "invalid pending operation"):
                    self.op.accept(name, response)
                self.assert_previous_state(record)

    def test_ignore_unrecognized_response_members_and_do_not_disclose_them(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])

        def extended_response(nonce):
            envelope = json_bytes({"nonce": nonce, "account_ref": "cp-alice", "claim_set": record.jwt})
            return envelope[:-1] + b',"extension":{"a":1,"a":2}}'

        self.assertEqual(self.collect_with_response(extended_response).jwt, record.jwt)
        presentation = self.deliver_to_rp()
        self.assertEqual(presentation["_claim_sources"], {"cp1": {"JWT": record.jwt}})
        self.assertNotIn("extension", presentation)

    def test_json_request_validation(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])
        body = br'{"nonce":"?","claims":{"birthdate":null},"signing_alg":"RS256"}'
        cases = (
            ("unknown top-level member", body[:-1] + b',"extension":true}'),
            ("duplicate decoded top-level name", body[:-1] + rb',"\u006eonce":"?"}'),
            ("duplicate decoded claim name", body.replace(b"null", rb'null,"\u0062irthdate":null')),
            ("empty nonce", body.replace(b'"?"', b'""')),
            ("unsupported query value", body.replace(b"null", b'{"essential":true}')),
        )
        for name, invalid in cases:
            with self.subTest(name=name):
                request = Request(self.op.endpoint, data=invalid, headers={
                    "Content-Type": "application/json", "Authorization": "Bearer fixture-alice",
                })
                with self.assertRaises(HTTPError) as error:
                    urlopen(request, context=self.tls, timeout=5)
                with error.exception as response:
                    self.assertEqual(response.code, 400)
                    self.assertEqual(parse_object(response.read()), {"error": "invalid_request"})
                self.assert_previous_state(record)
        request = Request(self.op.endpoint, data=body, headers={
            "Content-Type": "application/json", "Authorization": "Bearer fixture-alice",
        })
        with urlopen(request, context=self.tls, timeout=5) as response:
            self.assertEqual(parse_object(response.read())["nonce"], "?")

    def test_jwt_rejection_by_op_and_rp_without_changing_state(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])
        claims = {"iss": CP, "aud": OP, **timestamps(), "birthdate": "2000-01-01"}
        issued = claims["iat"]
        pss_input = b".".join((
            b64(json_bytes({"typ": CLAIM_SET_TYPE, "alg": "PS256"})), b64(json_bytes(claims)),
        ))
        pss_signature = openssl(
            "dgst", "-sha256", "-sign", self.cp_key.private, "-sigopt", "rsa_padding_mode:pss",
            "-sigopt", "rsa_pss_saltlen:32", data=pss_input,
        )
        cases = (
            ("issuer", sign(self.cp_key.private, CLAIM_SET_TYPE, dict(claims, iss=OP))),
            ("audience", sign(self.cp_key.private, CLAIM_SET_TYPE, dict(claims, aud=RP))),
            ("multiple audiences", sign(self.cp_key.private, CLAIM_SET_TYPE, dict(claims, aud=[OP, RP]))),
            ("type", sign(self.cp_key.private, "other+jwt", claims)),
            ("algorithm", (pss_input + b"." + b64(pss_signature)).decode("ascii")),
            ("signature", sign(self.op_key.private, CLAIM_SET_TYPE, claims)),
            ("expiry", sign(self.cp_key.private, CLAIM_SET_TYPE, dict(claims, iat=issued - 20, exp=issued - 10))),
            ("future issuance", sign(self.cp_key.private, CLAIM_SET_TYPE, dict(claims, iat=issued + 90))),
            ("sub on Claim Set", sign(self.cp_key.private, CLAIM_SET_TYPE, dict(claims, sub="cp-alice"))),
            ("ID Token", sign(self.cp_key.private, "JWT", dict(claims, sub="cp-alice", nonce="setup-nonce"))),
            ("UserInfo JWT", sign(self.cp_key.private, "JWT", {
                "iss": CP, "aud": OP, "sub": "cp-alice", "birthdate": "2000-01-01",
            })),
        )
        for name, jwt in cases:
            with self.subTest(name=name):
                before = self.server.collections
                with self.assertRaises(ValueError):
                    self.collect_with_response(lambda nonce: json_bytes({
                        "nonce": nonce, "account_ref": "cp-alice", "claim_set": jwt,
                    }))
                presentation = sign(self.op_key.private, "JWT", {
                    "iss": OP, "aud": RP, "sub": "op-alice", **timestamps(),
                    "_claim_names": {"birthdate": "cp1"},
                    "_claim_sources": {"cp1": {"JWT": jwt}},
                })
                with self.assertRaises(ValueError):
                    receive(presentation, self.op_key.public, self.cp_key.public, "op-alice")
                self.assert_previous_state(record)
                self.assertEqual(self.server.collections, before + 1)

    def test_reject_empty_or_excess_claim_set_attributes_without_changing_state(self):
        record = self.op.collect("op-alice", "fixture-alice", ["birthdate"])
        protocol_claims = {"iss": CP, "aud": OP, **timestamps()}
        cases = (
            ("protocol-only JWT", {}, ["birthdate"], "unexpected attributes"),
            ("unrequested attribute", {"birthdate": "2000-01-01", "address": {}},
             ["birthdate"], "unexpected attributes"),
            ("requested but unauthorized attribute", {"birthdate": "2000-01-01", "address": {}},
             ["birthdate", "address"], "unauthorized attributes"),
        )
        for name, attributes, requested, error in cases:
            with self.subTest(name=name):
                jwt = sign(self.cp_key.private, CLAIM_SET_TYPE, {**protocol_claims, **attributes})
                with self.assertRaisesRegex(ValueError, error):
                    self.collect_with_response(lambda nonce: json_bytes({
                        "nonce": nonce, "account_ref": "cp-alice", "claim_set": jwt,
                    }), requested)
                self.assert_previous_state(record)


if __name__ == "__main__":
    unittest.main(verbosity=2)
