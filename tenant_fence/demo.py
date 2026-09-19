"""Deliberately flawed synthetic fixtures. Never expose these servers publicly."""

import json
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from .core import evaluate

SPEC = {
    "tenants": [
        {
            "id": "alpha",
            "resource": "record-alpha",
            "marker": "SYNTHETIC-ALPHA-RECORD",
            "token_env": "TENANT_ALPHA_TOKEN",
        },
        {
            "id": "beta",
            "resource": "record-beta",
            "marker": "SYNTHETIC-BETA-RECORD",
            "token_env": "TENANT_BETA_TOKEN",
        },
    ],
    "detail": "/records/{id}",
    "collection": "/records",
}
TOKENS = {
    "TENANT_ALPHA_TOKEN": "synthetic-alpha-token-only",
    "TENANT_BETA_TOKEN": "synthetic-beta-token-only",
}


@contextmanager
def fixture(mode="secure"):
    cache = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            owner = next(
                (t for t in SPEC["tenants"] if TOKENS[t["token_env"]] == token), None
            )
            if mode == "denied" or not owner:
                return self.reply(403, {"error": "denied"})
            if mode == "leaky-cache" and self.path in cache:
                return self.reply(200, cache[self.path])
            if mode == "unavailable":
                return self.reply(503, {"error": "unavailable"})
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/")
                self.end_headers()
                return
            hinted = next(
                (
                    t
                    for t in SPEC["tenants"]
                    if t["id"] == self.headers.get("X-Tenant-ID")
                ),
                owner,
            )
            active = hinted if mode == "header-trust" else owner
            if self.path == "/records":
                rows = SPEC["tenants"] if mode == "leaky-list" else [active]
                return self.reply(
                    200, {"records": [{"marker": t["marker"]} for t in rows]}
                )
            found = next(
                (
                    t
                    for t in SPEC["tenants"]
                    if self.path == "/records/" + t["resource"]
                ),
                None,
            )
            if not found:
                return self.reply(404, {"error": "not found"})
            if found["id"] != active["id"] and mode != "broken-object":
                return self.reply(
                    403,
                    {"error": found["marker"] if mode == "leaky-error" else "denied"},
                )
            body = {"marker": found["marker"]}
            if mode == "leaky-cache":
                cache[self.path] = body
            return self.reply(200, body)

        def reply(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def run():
    output = []
    for mode in ["broken-object", "header-trust", "leaky-list", "secure", "denied"]:
        with fixture(mode) as base:
            result = evaluate(base, SPEC, TOKENS)
        result["experiment"] = mode
        output.append(result)
    return output
