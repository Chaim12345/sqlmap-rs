"""Minimal HTTP forward proxy for tests.

Usage: python3 tests/tinyproxy.py <port> <logfile> [--auth user:pass]

Handles requests in absolute URI form (what proxy clients send), forwards
them to the origin, and appends one "METHOD <absolute-uri>" line per request
to the log file so tests can prove traffic flowed through the proxy.
With --auth, requests without a matching Proxy-Authorization: Basic header
get a 407 and never reach the origin; the log line records auth=ok/missing.
stdlib only.
"""

import http.client
import socket
import threading
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = None
AUTH = None
LOG_LOCK = threading.Lock()

# Headers that must not be copied hop-by-hop.
HOP_BY_HOP = {"proxy-connection", "connection", "keep-alive", "te",
              "trailer", "transfer-encoding", "upgrade",
              # RFC 7235: Proxy-Authorization is hop-by-hop. The proxy
              # consumes it for its own 407 check and must never relay it
              # to the origin.
              "proxy-authorization"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _log(self, line):
        with LOG_LOCK:
            with open(LOG_PATH, "a") as fh:
                fh.write(line + "\n")

    def _check_auth(self):
        if AUTH is None:
            return True
        import base64
        want = "Basic " + base64.b64encode(AUTH.encode()).decode()
        supplied = (self.headers.get("Proxy-Authorization") or "").split()
        # HTTP authentication schemes are case-insensitive. ureq emits
        # lowercase basic on CONNECT, while other clients use Basic.
        if (len(supplied) == 2 and supplied[0].lower() == "basic"
                and supplied[1] == want.split(" ", 1)[1]):
            return True
        self._log(f"{self.command} {self.path} auth=missing")
        self.send_response(407)
        self.send_header("Proxy-Authenticate", 'Basic realm="tinyproxy"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _relay(self):
        if not self._check_auth():
            return
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
        auth_note = " auth=ok" if AUTH is not None else ""
        self._log(f"{self.command} {self.path} referer={referer}{auth_note}")
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

    def do_CONNECT(self):
        # RFC 7231 tunnel: Proxy-Authorization is consumed here (407 without
        # it) and can never reach the origin - after CONNECT the proxy
        # shuttles opaque TLS bytes and sees nothing inside the tunnel.
        if not self._check_auth():
            return
        host, _, port = self.path.partition(":")
        try:
            upstream = socket.create_connection((host, int(port or 443)), timeout=10)
        except OSError:
            self.send_error(502, "origin unreachable")
            return
        self._log(f"CONNECT {self.path} auth=ok")
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.connection.settimeout(None)

        def pump(src, dst):
            try:
                while True:
                    chunk = src.recv(65536)
                    if not chunk:
                        break
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t = threading.Thread(target=pump, args=(self.connection, upstream), daemon=True)
        t.start()
        pump(upstream, self.connection)
        t.join(timeout=5)
        upstream.close()
        self.close_connection = True

    def log_message(self, *args):
        pass


def main():
    global LOG_PATH, AUTH
    args = sys.argv[1:]
    if "--auth" in args:
        i = args.index("--auth")
        AUTH = args[i + 1]
        del args[i:i + 2]
    LOG_PATH = args[1]
    port = int(args[0])
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
