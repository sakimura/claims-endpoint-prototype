# Claims Endpoint prototype

This prototype exercises the Claims Endpoint in the OpenID Connect Claims
Aggregation working draft at [`265905b9c0aee925c52a2bd75a8c55b2716fbaf8`](https://github.com/openid/claims-aggregation/blob/265905b9c0aee925c52a2bd75a8c55b2716fbaf8/openid-connect-claims-aggregation-1_0.md).

Run from the repository root with Python 3.9 or later and OpenSSL on PATH. The
tests start a CP on a loopback HTTPS port and generate a temporary test TLS
certificate and separate CP and OP RSA keys. The client verifies the local
certificate. Each run exercises real RS256 signing and verification.

```sh
python3 -B test_prototype.py
```

## Reproducible RS256 vectors

The [vector file](vectors/rs256.json) contains standalone CP Claim Sets, OP-signed
presentations embedding those exact Claim Sets, and the expected result for
both verifiers. The four PEM files in `vectors/` are a dedicated CP and OP test
key pair. **Both private keys are intentionally public and are for tests only.**

Use Python 3.9+ and OpenSSL on PATH. The verifier regenerates the vectors
byte for byte, compares them with the checked-in file, and checks the OP's
Claim Set verifier and the RP's full signed presentation verifier at
`2030-01-01T00:00:00Z` (`1893456000`). No HTTPS server is needed for this check.

```sh
python3 -B verify_vectors.py
```

To regenerate the checked-in JSON using the same fixture keys:

```sh
python3 -B verify_vectors.py --write
git diff --exit-code -- vectors/rs256.json
```

| Vector | Expected at the OP and RP |
| --- | --- |
| Valid | Accept and return `birthdate` |
| Wrong issuer | Reject the CP issuer |
| Wrong audience | Reject the CP audience |
| ID Token type | Reject a CP-signed JWT without the Claim Set type |
| Wrong signing key | Reject a Claim Set signed with the OP key |
| Expired | Reject at the JWT's exact expiry time |
| Forbidden `sub` | Reject a Claim Set containing a CP subject identifier |

## HTTPS prototype tests

The CP maps fixture bearer tokens to CP subjects and permitted attributes.
The OP starts with a fixture for the binding that Setup would establish.
It obtains the CP response over HTTPS, checks the pending operation and
account association, verifies the JWT, and retains the exact JWT with
its binding in a local SQLite database. The RP function verifies the
enclosing OP JWT and the embedded CP JWT before reading the attribute.

The tests cover successful acquisition and delivery, empty results, cached
disclosure without CP contact, and rejection of a different CP subject. They
also cover malformed JSON and acquisition envelopes, expired and completed
operations, invalid or substituted JWTs, and attributes outside the request
or collection authorization. Rejected acquisitions preserve the existing
account binding and exact stored JWT.

The CP distinguishes bearer token and scope errors from a successful empty
result. The partial-result tests check the actual embedded JWT for attributes
outside the request or grant and exercise the RP's local required-claim policy.

The storage tests reopen the database, attempt cross-account record substitution,
and restore an older Claim Set snapshot. An HMAC authenticates the JWT, account
binding, and acquisition time. The current deletion and withdrawal decisions
stay in the active database when restoring a snapshot. The fixture keeps the
integrity key outside SQLite and the database and snapshots in a private
temporary directory. The prototype assumes the decisions database is trusted
and current and does not implement encryption at rest or whole-database rollback
protection.

The lifecycle tests also exercise redisclosure after CP bearer token or grant
revocation and verification during and after CP signing-key rotation. They
use fixture authorization and preconfigured issuer keys. Setup, OAuth token
issuance, discovery, and independent implementations are tracked in
[Issue #55](https://github.com/openid/claims-aggregation/issues/55).
