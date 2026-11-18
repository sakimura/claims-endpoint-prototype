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

The CP maps fixture bearer tokens to CP subjects and permitted attributes.
The OP starts with a fixture for the binding that Setup would establish.
It obtains the CP response over HTTPS, checks the pending operation and
account association, verifies the JWT, and retains the exact JWT with
its binding in trusted in-process memory. The RP function verifies the
enclosing OP JWT and the embedded CP JWT before reading the attribute.

The tests cover successful acquisition and delivery, empty results, cached
disclosure without CP contact, and rejection of a different CP subject. They
also cover malformed JSON and acquisition envelopes, expired and completed
operations, invalid or substituted JWTs, and attributes outside the request
or collection authorization. Rejected acquisitions preserve the existing
account binding and exact stored JWT.
The fixture supplies authorization and preconfigured issuer keys. Setup,
OAuth token issuance, discovery, persistent storage, and independent
implementations are tracked in [Issue #55](https://github.com/openid/claims-aggregation/issues/55).
