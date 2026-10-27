"""Tiny demo web server for the PhishGuard demonstration pages.

Run:  python demo/serve.py        (serves this folder on 127.0.0.1:8080)
Visit pages through different host names (see README) so the engine sees
domains that do not belong to the brand shown on the page.
POST /collect is a harmless sink: it discards the body and stores nothing.
"""
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

os.chdir(os.path.dirname(os.path.abspath(__file__)))


class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        self.rfile.read(min(n, 100_000))  # read and discard
        body = b"Demo collector: this is where a real phishing kit would receive your data. Nothing was stored."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print("Demo pages on http://127.0.0.1:8080  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
