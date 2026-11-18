"""Local Claims Endpoint prototype with fixture grants and Setup bindings."""

import base64
from contextlib import closing
from dataclasses import dataclass
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
import ssl
import subprocess
from tempfile import TemporaryDirectory
import time
from urllib.request import Request, urlopen


CP = "https://cp.example"
OP = "https://op.example"
RP = "rp-client"
CLAIM_SET_TYPE = "claims-aggregation+jwt"
ALGORITHM = "RS256"
NO_STORE = "no-store"
PROTOCOL_CLAIMS = {"iss", "sub", "aud", "iat", "exp", "nbf", "jti"}


@dataclass(frozen=True)
class Grant:
    identifier: str
    subject: str
    attributes: dict
    claims_endpoint_allowed: bool = True


ALICE_GRANT = Grant("grant-alice", "cp-alice", {
    "birthdate": "1990-01-01", "given_name": "Alice",
})
GRANTS = {
    "fixture-alice": ALICE_GRANT,
    "fixture-alice-second": ALICE_GRANT,
    "fixture-bob": Grant("grant-bob", "cp-bob", {"birthdate": "1991-02-03"}),
    "fixture-alice-no-claims-scope": Grant(
        "grant-alice-limited", "cp-alice", {"birthdate": "1990-01-01"},
        claims_endpoint_allowed=False,
    ),
}


def object_members(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def parse_object(data):
    value = json.loads(data, object_pairs_hook=object_members)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def parse_response_object(data):
    class ObjectPairs(list):
        pass

    pairs = json.loads(data, object_pairs_hook=ObjectPairs)
    if not isinstance(pairs, ObjectPairs):
        raise ValueError("expected JSON object")
    # Only the envelope's member names are checked. Known envelope values must
    # be strings. Unknown values are ignored, including any nested objects.
    return object_members(pairs)


def json_bytes(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def unb64(data):
    decoded = base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))
    if b64(decoded) != data:
        raise ValueError("invalid base64url")
    return decoded


def openssl(*arguments, data=None):
    return subprocess.run(
        ["openssl", *map(str, arguments)], input=data,
        capture_output=True, check=True,
    ).stdout


@dataclass(frozen=True)
class KeyPair:
    private: Path
    public: Path

    @classmethod
    def generate(cls, directory, name):
        private = directory / f"{name}.pem"
        public = directory / f"{name}.pub.pem"
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                "-out", private)
        openssl("pkey", "-in", private, "-pubout", "-out", public)
        return cls(private, public)


def sign(key, token_type, claims):
    header = {"typ": token_type, "alg": ALGORITHM}
    signing_input = b".".join((b64(json_bytes(header)), b64(json_bytes(claims))))
    signature = openssl("dgst", "-sha256", "-sign", key, data=signing_input)
    return b".".join((signing_input, b64(signature))).decode("ascii")


def verify(jwt, keys, token_type, issuer, audience):
    header_part, payload_part, signature_part = jwt.encode("ascii").split(b".")
    header = parse_object(unb64(header_part))
    if header != {"typ": token_type, "alg": ALGORITHM}:
        raise ValueError("unexpected JWT type or signing algorithm")
    with TemporaryDirectory() as directory:
        signature = Path(directory) / "signature.bin"
        signature.write_bytes(unb64(signature_part))
        for key in keys:
            try:
                openssl("dgst", "-sha256", "-verify", key, "-signature", signature,
                        data=b".".join((header_part, payload_part)))
            except subprocess.CalledProcessError:
                continue
            break
        else:
            raise ValueError("no trusted key verified the JWT signature")
    claims = parse_object(unb64(payload_part))
    if claims.get("iss") != issuer or claims.get("aud") not in (audience, [audience]):
        raise ValueError("unexpected issuer or audience")
    issued, expiry = claims.get("iat"), claims.get("exp")
    if type(issued) is not int or type(expiry) is not int or not issued <= time.time() < expiry:
        raise ValueError("JWT outside validity period")
    return claims


def verify_claim_set(jwt, keys):
    claims = verify(jwt, keys, CLAIM_SET_TYPE, CP, OP)
    if "sub" in claims or "account_ref" in claims:
        raise ValueError("account identifier in Claim Set")
    if "nbf" in claims and (type(claims["nbf"]) is not int or claims["nbf"] > time.time()):
        raise ValueError("Claim Set not yet valid")
    return {name: value for name, value in claims.items() if name not in PROTOCOL_CLAIMS}


def timestamps():
    issued = int(time.time())
    return {"iat": issued, "exp": issued + 300}


class ClaimsEndpoint(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, status, body, challenge=None):
        payload = json_bytes(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", NO_STORE)
        self.send_header("Content-Length", str(len(payload)))
        if challenge:
            self.send_header("WWW-Authenticate", challenge)
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path != "/claims":
            self.send_error(404)
            return
        self.server.collections += 1
        auth = self.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else None
        grant = self.server.grants.get(token)
        if grant is None or grant.identifier in self.server.revoked_grants:
            self.respond(401, {"error": "invalid_token"}, 'Bearer error="invalid_token"')
            return
        if not grant.claims_endpoint_allowed:
            self.respond(403, {"error": "insufficient_scope"}, 'Bearer error="insufficient_scope"')
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096 or self.headers.get_content_type() != "application/json":
                raise ValueError("invalid request framing")
            request = parse_object(self.rfile.read(size))
            if set(request) != {"nonce", "claims", "signing_alg"}:
                raise ValueError("invalid request members")
            nonce = request["nonce"]
            selection = request["claims"]
            if not isinstance(nonce, str) or not nonce or request["signing_alg"] != ALGORITHM:
                raise ValueError("invalid nonce or algorithm")
            if (not isinstance(selection, dict) or not selection
                    or any(name in PROTOCOL_CLAIMS or value is not None
                           for name, value in selection.items())):
                raise ValueError("invalid claim selection")
        except ValueError:
            self.respond(400, {"error": "invalid_request"})
            return
        attributes = {name: grant.attributes[name] for name in selection if name in grant.attributes}
        response = {"nonce": nonce}
        if attributes:
            jwt = sign(self.server.signing_key, CLAIM_SET_TYPE, {
                "iss": CP, "aud": OP, **timestamps(), **attributes,
            })
            response.update(account_ref=grant.subject, claim_set=jwt)
        self.respond(200, response)


@dataclass(frozen=True)
class Binding:
    op_account: str
    cp_issuer: str
    cp_subject: str


@dataclass(frozen=True)
class Collection:
    binding: Binding
    claims: frozenset
    authorized_claims: frozenset
    deadline: float


@dataclass(frozen=True)
class StoredClaimSet:
    binding: Binding
    jwt: str
    collected_at: float


class ClaimStore:
    records_schema = """CREATE TABLE IF NOT EXISTS records (
        binding BLOB PRIMARY KEY NOT NULL, jwt TEXT NOT NULL,
        collected_at REAL NOT NULL, tag BLOB NOT NULL
    )"""

    def __init__(self, path, integrity_key):
        self.integrity_key = integrity_key
        self.db = sqlite3.connect(path)
        with self.db:
            self.db.execute(self.records_schema)
            self.db.execute("""CREATE TABLE IF NOT EXISTS deletions (
                binding BLOB NOT NULL, jwt_hash BLOB NOT NULL, PRIMARY KEY (binding, jwt_hash)
            )""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS withdrawals (
                binding BLOB NOT NULL, rp TEXT NOT NULL, PRIMARY KEY (binding, rp)
            )""")

    def close(self):
        self.db.close()

    @staticmethod
    def binding_key(binding):
        return json_bytes([binding.op_account, binding.cp_issuer, binding.cp_subject])

    def tag(self, binding_key, jwt, collected_at):
        message = json_bytes([binding_key.decode("utf-8"), jwt, collected_at])
        return hmac.digest(self.integrity_key, message, "sha256")

    def check_tag(self, binding_key, jwt, collected_at, tag):
        if not hmac.compare_digest(tag, self.tag(binding_key, jwt, collected_at)):
            raise ValueError("stored Claim Set binding or integrity mismatch")

    @staticmethod
    def jwt_hash(jwt):
        return hashlib.sha256(jwt.encode("ascii")).digest()

    def was_deleted(self, binding_key, jwt):
        return self.db.execute("SELECT 1 FROM deletions WHERE binding = ? AND jwt_hash = ?",
                               (binding_key, self.jwt_hash(jwt))).fetchone() is not None

    def save(self, record):
        key = self.binding_key(record.binding)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.was_deleted(key, record.jwt):
                raise ValueError("Claim Set was deleted")
            self.db.execute("INSERT OR REPLACE INTO records VALUES (?, ?, ?, ?)", (
                key, record.jwt, record.collected_at, self.tag(key, record.jwt, record.collected_at),
            ))

    def load(self, binding):
        key = self.binding_key(binding)
        row = self.db.execute("SELECT jwt, collected_at, tag FROM records WHERE binding = ?",
                              (key,)).fetchone()
        if row is None:
            return None
        jwt, collected_at, tag = row
        self.check_tag(key, jwt, collected_at, tag)
        if self.was_deleted(key, jwt):
            return None
        return StoredClaimSet(binding, jwt, collected_at)

    def delete(self, binding):
        key = self.binding_key(binding)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            record = self.load(binding)
            if record is not None:
                self.db.execute("INSERT INTO deletions VALUES (?, ?)", (key, self.jwt_hash(record.jwt)))
            self.db.execute("DELETE FROM records WHERE binding = ?", (key,))

    def withdraw(self, binding, *, rp=""):
        # An empty RP identifier denotes collection authorization.
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO withdrawals VALUES (?, ?)",
                            (self.binding_key(binding), rp))

    def withdrawn(self, binding, *, rp=""):
        return self.db.execute("SELECT 1 FROM withdrawals WHERE binding = ? AND rp = ?",
                               (self.binding_key(binding), rp)).fetchone() is not None

    def backup(self, path):
        with closing(sqlite3.connect(path)) as snapshot, snapshot:
            snapshot.execute(self.records_schema)
            snapshot.executemany("INSERT INTO records VALUES (?, ?, ?, ?)",
                                 self.db.execute("SELECT * FROM records"))

    def restore(self, path):
        # Merge only Claim Sets; the current deletion and withdrawal decisions
        # stay in the active database and cannot be rolled back by this API.
        source = path.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(source, uri=True)) as snapshot, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            for key, jwt, collected_at, tag in snapshot.execute("SELECT * FROM records"):
                self.check_tag(key, jwt, collected_at, tag)
                if not self.was_deleted(key, jwt):
                    self.db.execute("INSERT OR IGNORE INTO records VALUES (?, ?, ?, ?)",
                                    (key, jwt, collected_at, tag))


class AggregatingOP:
    def __init__(self, endpoint, tls_context, cp_keys, op_key, bindings,
                 collection_permissions, disclosures, store):
        self.endpoint = endpoint
        self.tls_context = tls_context
        self.cp_keys = cp_keys
        self.op_key = op_key
        self.bindings = bindings
        self.collection_permissions = collection_permissions
        self.disclosures = disclosures
        self.pending = {}
        self.store = store

    def collect(self, account, token, names):
        binding = self.bindings[account]
        if self.store.withdrawn(binding):
            raise ValueError("collection authorization withdrawn")
        if binding.cp_issuer != CP:
            raise ValueError("unexpected CP binding")
        nonce = secrets.token_urlsafe(16)
        while nonce in self.pending:
            nonce = secrets.token_urlsafe(16)
        self.pending[nonce] = Collection(
            binding, frozenset(names),
            frozenset(self.collection_permissions.get(binding, ())),
            time.monotonic() + 5,
        )
        request = Request(self.endpoint, data=json_bytes({
            "claims": dict.fromkeys(names), "nonce": nonce, "signing_alg": ALGORITHM,
        }), headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        try:
            with urlopen(request, context=self.tls_context, timeout=5) as reply:
                if (reply.status != 200 or reply.headers.get_content_type() != "application/json"
                        or reply.headers.get("Cache-Control") != NO_STORE):
                    raise ValueError("invalid Claims Endpoint response")
                envelope = parse_response_object(reply.read())
            return self.accept(nonce, envelope)
        finally:
            self.pending.pop(nonce, None)

    def accept(self, nonce, envelope):
        operation = self.pending.pop(nonce, None)
        if (operation is None or operation.deadline <= time.monotonic()
                or envelope.get("nonce") != nonce or "error" in envelope):
            raise ValueError("invalid pending operation response")
        if "claim_set" not in envelope:
            if "account_ref" in envelope:
                raise ValueError("invalid empty result")
            return None
        if envelope.get("account_ref") != operation.binding.cp_subject:
            raise ValueError("CP account binding mismatch")
        jwt = envelope["claim_set"]
        if not isinstance(jwt, str) or not jwt:
            raise ValueError("missing Claim Set")
        if self.store.withdrawn(operation.binding):
            raise ValueError("collection authorization withdrawn")
        attributes = verify_claim_set(jwt, self.cp_keys)
        if not attributes or not attributes.keys() <= operation.claims:
            raise ValueError("unexpected attributes")
        if not attributes.keys() <= operation.authorized_claims:
            raise ValueError("unauthorized attributes")
        record = StoredClaimSet(operation.binding, jwt, time.time())
        self.store.save(record)
        return record

    def deliver(self, account, rp):
        binding = self.bindings[account]
        if self.store.withdrawn(binding, rp=rp):
            raise ValueError("disclosure authorization withdrawn")
        record = self.store.load(binding)
        if record is None:
            raise ValueError("no stored Claim Set")
        attributes = verify_claim_set(record.jwt, self.cp_keys)
        if not attributes.keys() <= self.disclosures.get((binding, rp), set()):
            raise ValueError("disclosure not authorized")
        return sign(self.op_key, "JWT", {
            "iss": OP, "sub": account, "aud": rp, **timestamps(),
            "_claim_names": dict.fromkeys(attributes, "cp1"),
            "_claim_sources": {"cp1": {"JWT": record.jwt}},
        })


def receive(enclosing, op_key, cp_keys, expected_account, *, required_claims=()):
    response = verify(enclosing, (op_key,), "JWT", OP, RP)
    if response.get("sub") != expected_account:
        raise ValueError("unexpected OP subject")
    sources = response["_claim_sources"]
    verified = {
        name: verify_claim_set(source["JWT"], cp_keys) for name, source in sources.items()
    }
    attributes = {name: verified[source][name] for name, source in response["_claim_names"].items()}
    if set(required_claims).difference(attributes):
        raise ValueError("required claims unavailable")
    return attributes


def make_server(directory, signing_key):
    certificate = directory / "tls.crt"
    private = directory / "tls.pem"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", private, "-out", certificate)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private)
    server = HTTPServer(("127.0.0.1", 0), ClaimsEndpoint)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.collections = 0
    server.signing_key = signing_key
    server.grants = GRANTS.copy()
    server.revoked_grants = set()
    client_context = ssl.create_default_context(cafile=str(certificate))
    return server, client_context
