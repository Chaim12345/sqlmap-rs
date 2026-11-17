#!/usr/bin/env python3
"""Tiny TLS origin for proxy/CONNECT tests.

Serves 200 "TLS-ORIGIN" on every request over HTTPS with the test's
certificate and key. Every request's headers are logged as
"proxy-auth=present/absent" so tests can prove Proxy-Authorization never
crosses the tunnel into the origin.

Usage: tinyhttps.py PORT CERT_PEM KEY_PEM LOG_PATH
"""

import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = None


class Handler(BaseHTTPRequestHandler):
    def _log(self, line):
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")

    def _serve(self):
        seen = "present" if self.headers.get("Proxy-Authorization") else "absent"
        self._log(f"{self.command} {self.path} proxy-auth={seen}")
        body = b"TLS-ORIGIN"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _serve
    do_POST = _serve
    do_HEAD = _serve

    def log_message(self, *args):
        pass


def main():
    global LOG_PATH
    port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    LOG_PATH = sys.argv[4]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
