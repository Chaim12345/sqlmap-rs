"""Minimal HTTP forward proxy for tests.

Usage: python3 tests/tinyproxy.py <port> <logfile>

Handles requests in absolute URI form (what proxy clients send), forwards
them to the origin, and appends one "METHOD <absolute-uri>" line per request
to the log file so tests can prove traffic flowed through the proxy.
stdlib only.
"""

import http.client
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = None
LOG_LOCK = threading.Lock()

# Headers that must not be copied hop-by-hop.
HOP_BY_HOP = {"proxy-connection", "connection", "keep-alive", "te",
              "trailer", "transfer-encoding", "upgrade"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _log(self, line):
        with LOG_LOCK:
            with open(LOG_PATH, "a") as fh:
                fh.write(line + "\n")

    def _relay(self):
        url = urllib.parse.urlsplit(self.path)
        if not url.hostname:
            self.send_error(400, "proxy expects absolute URIs")
            return
        port = url.port or 80
        body = None
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            body = self.rfile.read(length)
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in HOP_BY_HOP and k.lower() != "host"}
        target = f"{url.path or '/'}" + (f"?{url.query}" if url.query else "")
        conn = http.client.HTTPConnection(url.hostname, port, timeout=10)
        try:
            conn.request(self.command, target, body=body, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
        except OSError:
            self.send_error(502, "origin unreachable")
            return
        finally:
            conn.close()
        referer = (self.headers.get("Referer") or "").replace("\r", " ").replace("\n", " ")
        self._log(f"{self.command} {self.path} referer={referer}")
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() in HOP_BY_HOP or k.lower() == "content-length":
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = _relay
    do_POST = _relay
    do_HEAD = _relay
    do_PUT = _relay
    do_DELETE = _relay

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    LOG_PATH = sys.argv[2]
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
