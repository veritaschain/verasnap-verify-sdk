#!/usr/bin/env python3
"""Reference HTTP service for a claims system (standard library only).

NOT for production: there is no authentication, TLS or rate limiting. The
account reference is taken from an `X-Account-Ref` header to stand in for
your own authenticated session — never trust it from a client in production.

    python3 examples/insurer_server.py --registry keys.sqlite \
        --android-package org.example.claims --android-cert-sha256 <hex> \
        --apple-app-id ABCDE12345.org.example.claims

Endpoints
    POST /v1/enroll/challenge          -> {"challenge_id", "challenge", "expires_at"}
    POST /v1/enroll                    body: enrollment request JSON (docs/ENROLLMENT.md)
    POST /v1/verify                    body: {"proof": <JSON object or Base64>, "media": <Base64>}
"""

from __future__ import annotations

import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from verasnap_verify import SqliteKeyRegistry, Verifier
from verasnap_verify.enroll import AndroidPolicy, ApplePolicy, Enroller, EnrollmentError, EnrollmentPolicy

MAX_BODY = 64 * 1024 * 1024


def make_handler(enroller: Enroller, verifier: Verifier):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_BODY:
                raise ValueError("body too large")
            return json.loads(self.rfile.read(length) or b"{}")

        def do_POST(self):  # noqa: N802
            account = self.headers.get("X-Account-Ref", "")
            try:
                if self.path == "/v1/enroll/challenge":
                    if not account:
                        return self._send(401, {"error": "X-Account-Ref required"})
                    return self._send(200, enroller.issue_challenge(account).to_wire())
                if self.path == "/v1/enroll":
                    record = enroller.enroll(self._body(), account)
                    return self._send(200, {"fingerprint": record.fingerprint, "security_level": record.security_level})
                if self.path == "/v1/verify":
                    body = self._body()
                    proof = body.get("proof")
                    if isinstance(proof, str):
                        proof = base64.b64decode(proof)
                    media = base64.b64decode(body["media"]) if body.get("media") else None
                    return self._send(200, verifier.verify(proof, media).to_dict())
                return self._send(404, {"error": "not found"})
            except EnrollmentError as exc:
                return self._send(400, {"error": exc.code, "message": exc.message})
            except (ValueError, KeyError) as exc:
                return self._send(400, {"error": "bad_request", "message": str(exc)})

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", default="keys.sqlite")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--android-package", action="append", default=[])
    ap.add_argument("--android-cert-sha256", action="append", default=[])
    ap.add_argument("--apple-app-id", action="append", default=[])
    args = ap.parse_args()

    registry = SqliteKeyRegistry(args.registry)
    policy = EnrollmentPolicy(
        android=AndroidPolicy(
            package_names=args.android_package,
            signing_cert_sha256=[bytes.fromhex(h) for h in args.android_cert_sha256],
        )
        if args.android_package
        else None,
        apple=ApplePolicy(app_ids=args.apple_app_id) if args.apple_app_id else None,
    )
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(Enroller(policy, registry), Verifier(registry=registry)))
    print(f"listening on http://127.0.0.1:{args.port}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
