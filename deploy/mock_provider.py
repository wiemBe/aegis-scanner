"""Local mock of the OpenAI Responses API for topology validation ONLY.

This server impersonates api.openai.com (via a Docker network alias) behind the SAME egress proxy
ACLs the real provider would sit behind. It lets the full path
control-plane -> llm-gateway -> egress-proxy -> (CONNECT api.openai.com:443) -> provider be
exercised locally with ZERO real external calls, while TLS verification stays ON: it serves a
certificate for api.openai.com signed by the local test CA, which the gateway verifies.

It ignores the Authorization header and returns a fixed, schema-valid Responses completion. It is
never a substitute for a real acceptance run and must not be exposed outside local validation.
"""

import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CERT = os.environ.get("MOCK_CERT", "/certs/server.crt")
KEY = os.environ.get("MOCK_KEY", "/certs/server.key")
PORT = int(os.environ.get("MOCK_PORT", "443"))

# A minimal, schema-valid Responses API completion whose output text is a valid AgentDecision.
_DECISION = json.dumps({"action": "stop", "summary": "Mock provider stop.", "hypothesis": None})
_RESPONSE = {
    "id": "resp_mock",
    "object": "response",
    "status": "completed",
    "model": "gpt-5-mini",
    "output": [
        {
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": _DECISION}],
        }
    ],
    "usage": {"input_tokens": 42, "output_tokens": 8, "total_tokens": 50},
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict[str, object]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._send(200, {"status": "ok", "mock": True})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)  # Drain and ignore the request body.
        if self.path.rstrip("/").endswith("/responses"):
            self._send(200, _RESPONSE)
        else:
            self._send(404, {"error": "not_found"})

    def log_message(self, fmt: str, *args: object) -> None:
        # Never log request bodies or headers (which would carry the Authorization value).
        return


def main() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT, keyfile=KEY)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)  # noqa: S104 - container-internal only
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"mock-provider listening on :{PORT} as api.openai.com (test cert)", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
