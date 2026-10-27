"""Local detection server for the PhishGuard extension (stdlib only).

Run:  python server.py            (listens on 127.0.0.1:8765)
POST /analyze  {"url": "...", "html": "..."?}  ->  verdict JSON
GET  /health
Bound to localhost only: page HTML never leaves the machine.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from engine import analyze

HOST, PORT = "127.0.0.1", 8765
MAX_BODY = 2_000_000


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/analyze":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n <= 0 or n > MAX_BODY:
                return self._send(413, {"error": "bad body size"})
            data = json.loads(self.rfile.read(n))
            url = data["url"]
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                return self._send(400, {"error": "url must be http(s)"})
            html = data.get("html")
            self._send(200, analyze(url, html if isinstance(html, str) else None))
        except (KeyError, ValueError):
            self._send(400, {"error": "invalid request"})

    def log_message(self, fmt, *args):
        sys.stderr.write("[phishguard] " + fmt % args + "\n")


if __name__ == "__main__":
    print(f"PhishGuard engine on http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
