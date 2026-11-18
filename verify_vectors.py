"""Regenerate or verify the public RS256 Claim Set test vectors."""

import argparse
import json
from pathlib import Path
from unittest.mock import patch

from prototype import CLAIM_SET_TYPE, CP, OP, RP, receive, sign, verify_claim_set


DIRECTORY = Path(__file__).resolve().parent / "vectors"
VECTORS = DIRECTORY / "rs256.json"
CP_PRIVATE = DIRECTORY / "cp-test-private.pem"
CP_PUBLIC = DIRECTORY / "cp-test-public.pem"
OP_PRIVATE = DIRECTORY / "op-test-private.pem"
OP_PUBLIC = DIRECTORY / "op-test-public.pem"
ACCOUNT = "op-vector-subject"
VERIFY_AT = 1893456000  # 2030-01-01T00:00:00Z
ATTRIBUTES = {"birthdate": "1990-01-01"}


def generate():
    claims = {"iss": CP, "aud": OP, "iat": VERIFY_AT - 60, "exp": VERIFY_AT + 240,
              **ATTRIBUTES}
    cases = (
        ("valid", CP_PRIVATE, CLAIM_SET_TYPE, claims, None),
        ("wrong-issuer", CP_PRIVATE, CLAIM_SET_TYPE, dict(claims, iss="https://other.example"),
         "unexpected issuer or audience"),
        ("wrong-audience", CP_PRIVATE, CLAIM_SET_TYPE, dict(claims, aud=RP),
         "unexpected issuer or audience"),
        ("id-token-type", CP_PRIVATE, "JWT", dict(claims, sub="cp-vector-subject"),
         "unexpected JWT type or signing algorithm"),
        ("wrong-signing-key", OP_PRIVATE, CLAIM_SET_TYPE, claims,
         "no trusted key verified the JWT signature"),
        ("expired", CP_PRIVATE, CLAIM_SET_TYPE, dict(claims, exp=VERIFY_AT),
         "JWT outside validity period"),
        ("forbidden-sub", CP_PRIVATE, CLAIM_SET_TYPE, dict(claims, sub="cp-vector-subject"),
         "account identifier in Claim Set"),
    )
    vectors = []
    for name, key, token_type, payload, error in cases:
        claim_set = sign(key, token_type, payload)
        presentation = sign(OP_PRIVATE, "JWT", {
            "iss": OP, "sub": ACCOUNT, "aud": RP, "iat": VERIFY_AT - 1, "exp": VERIFY_AT + 60,
            "_claim_names": {"birthdate": "cp1"},
            "_claim_sources": {"cp1": {"JWT": claim_set}},
        })
        expected = {"error": error} if error else {"attributes": ATTRIBUTES}
        vectors.append({"id": name, "claim_set": claim_set, "presentation": presentation,
                        "expected": expected})
    return {"verification_time": VERIFY_AT, "op_subject": ACCOUNT, "vectors": vectors}


def verify_vectors(document):
    for vector in document["vectors"]:
        name = vector["id"]
        op_input = (vector["claim_set"], (CP_PUBLIC,))
        rp_input = (vector["presentation"], OP_PUBLIC, (CP_PUBLIC,), document["op_subject"])
        for role, verify, arguments in (("OP", verify_claim_set, op_input),
                                        ("RP", receive, rp_input)):
            try:
                result = {"attributes": verify(*arguments)}
            except ValueError as exc:
                result = {"error": str(exc)}
            if result != vector["expected"]:
                raise SystemExit(f"{name} ({role}): expected {vector['expected']}, got {result}")
        outcome = vector["expected"].get("error", "accepted")
        print(f"{name}: OP and RP: {outcome}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="rewrite the vector file")
    args = parser.parse_args()
    generated = json.dumps(generate(), indent=2) + "\n"
    if args.write:
        VECTORS.write_bytes(generated.encode("utf-8"))
    elif VECTORS.read_bytes() != generated.encode("utf-8"):
        raise SystemExit("The checked-in vector file differs from the regenerated vectors")
    document = json.loads(VECTORS.read_bytes())
    with patch("prototype.time.time", return_value=document["verification_time"]):
        verify_vectors(document)
    print(f"{len(document['vectors'])} vectors verified at the OP and RP")


if __name__ == "__main__":
    main()
