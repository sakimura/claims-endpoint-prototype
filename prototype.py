"""Local Claims Endpoint prototype with fixture grants and Setup bindings."""

import base64
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
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
GRANTS = {
    "fixture-alice": ("cp-alice", {"birthdate": "1990-01-01"}),
    "fixture-bob": ("cp-bob", {"birthdate": "1991-02-03"}),
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


def verify(jwt, key, token_type, issuer, audience):
    header_part, payload_part, signature_part = jwt.encode("ascii").split(b".")
    header = parse_object(unb64(header_part))
    if header != {"typ": token_type, "alg": ALGORITHM}:
        raise ValueError("unexpected JWT type or signing algorithm")
    with TemporaryDirectory() as directory:
        signature = Path(directory) / "signature.bin"
        signature.write_bytes(unb64(signature_part))
        try:
            openssl("dgst", "-sha256", "-verify", key, "-signature", signature,
                    data=b".".join((header_part, payload_part)))
        except subprocess.CalledProcessError as exc:
            raise ValueError("invalid JWT signature") from exc
    claims = parse_object(unb64(payload_part))
    if claims.get("iss") != issuer or claims.get("aud") not in (audience, [audience]):
        raise ValueError("unexpected issuer or audience")
    issued, expiry = claims.get("iat"), claims.get("exp")
    if type(issued) is not int or type(expiry) is not int or not issued <= time.time() < expiry:
        raise ValueError("JWT outside validity period")
    return claims


def verify_claim_set(jwt, key):
    claims = verify(jwt, key, CLAIM_SET_TYPE, CP, OP)
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
        grant = GRANTS.get(auth.removeprefix("Bearer ")) if auth.startswith("Bearer ") else None
        if grant is None:
            self.respond(401, {"error": "invalid_token"}, 'Bearer error="invalid_token"')
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
        account_ref, allowed = grant
        attributes = {name: allowed[name] for name in selection if name in allowed}
        response = {"nonce": nonce}
        if attributes:
            jwt = sign(self.server.signing_key, CLAIM_SET_TYPE, {
                "iss": CP, "aud": OP, **timestamps(), **attributes,
            })
            response.update(account_ref=account_ref, claim_set=jwt)
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
    deadline: float


@dataclass(frozen=True)
class StoredClaimSet:
    binding: Binding
    jwt: str
    collected_at: float


class AggregatingOP:
    def __init__(self, endpoint, tls_context, cp_key, op_key, bindings, disclosures):
        self.endpoint = endpoint
        self.tls_context = tls_context
        self.cp_key = cp_key
        self.op_key = op_key
        self.bindings = bindings
        self.disclosures = disclosures
        self.pending = {}
        self.records = {}

    def collect(self, account, token, names):
        binding = self.bindings[account]
        if binding.cp_issuer != CP:
            raise ValueError("unexpected CP binding")
        nonce = secrets.token_urlsafe(16)
        while nonce in self.pending:
            nonce = secrets.token_urlsafe(16)
        self.pending[nonce] = Collection(binding, frozenset(names), time.monotonic() + 5)
        request = Request(self.endpoint, data=json_bytes({
            "claims": dict.fromkeys(names), "nonce": nonce, "signing_alg": ALGORITHM,
        }), headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        try:
            with urlopen(request, context=self.tls_context, timeout=5) as reply:
                if (reply.status != 200 or reply.headers.get_content_type() != "application/json"
                        or reply.headers.get("Cache-Control") != NO_STORE):
                    raise ValueError("invalid Claims Endpoint response")
                envelope = parse_object(reply.read())
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
        attributes = verify_claim_set(jwt, self.cp_key)
        if not attributes or not attributes.keys() <= operation.claims:
            raise ValueError("unexpected attributes")
        record = StoredClaimSet(operation.binding, jwt, time.time())
        self.records[operation.binding] = record
        return record

    def deliver(self, account, rp):
        binding = self.bindings[account]
        record = self.records[binding]
        if record.binding != binding:
            raise ValueError("stored account binding mismatch")
        attributes = verify_claim_set(record.jwt, self.cp_key)
        if not attributes.keys() <= self.disclosures.get((binding, rp), set()):
            raise ValueError("disclosure not authorized")
        return sign(self.op_key, "JWT", {
            "iss": OP, "sub": account, "aud": rp, **timestamps(),
            "_claim_names": dict.fromkeys(attributes, "cp1"),
            "_claim_sources": {"cp1": {"JWT": record.jwt}},
        })


def receive(enclosing, op_key, cp_key, expected_account):
    response = verify(enclosing, op_key, "JWT", OP, RP)
    if response.get("sub") != expected_account:
        raise ValueError("unexpected OP subject")
    sources = response["_claim_sources"]
    verified = {
        name: verify_claim_set(source["JWT"], cp_key) for name, source in sources.items()
    }
    return {name: verified[source][name] for name, source in response["_claim_names"].items()}


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
    client_context = ssl.create_default_context(cafile=str(certificate))
    return server, client_context
