#!/usr/bin/env python3
"""Deliberately vulnerable test target for sqlmap-rs integration tests.

Emulates a MySQL-backed PHP app with a numeric injection point (?id=) and a
string injection point (?name=). Supports just enough SQL evaluation for the
ported detection techniques: AND boolean conditions, SLEEP(), ExtractValue()
error echo, and syntax errors on unbalanced quotes.

Localhost use only. Usage: python3 tests/vulnapp.py [port]
"""
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qsl, unquote_plus

NORMAL = "<html><body><h1>Item 1</h1><p>Widget - in stock: 12</p></body></html>"
EMPTY = "<html><body><h1>No results</h1></body></html>"


def mysql_error(fragment: str) -> str:
    return (
        "<html><body><b>Warning</b>: mysql_fetch_array() expects parameter 1 to be "
        "resource, boolean given in <b>/var/www/item.php</b> on line <b>12</b><br/>"
        "You have an error in your SQL syntax; check the manual that corresponds to "
        "your MySQL server version for the right syntax to use near '" + fragment +
        "' at line 1</body></html>"
    )


def xpath_error(marker: str) -> str:
    return (
        "<html><body>XPATH syntax error: '~" + marker + "'<br/>"
        "You have an error in your SQL syntax; check the manual that corresponds to "
        "your MySQL server version</body></html>"
    )


def eval_value(value: str) -> str:
    """Decide the page for an injected parameter value."""
    # MySQL treats /**/ as whitespace (tamper space2comment); keywords are
    # case-insensitive (tamper randomcase) - our regexes below are already re.I.
    value = value.replace("/**/", " ")
    # Error-based: ExtractValue(1,CONCAT(0x7e,<marker>)) echoes the marker.
    m = re.search(r"ExtractValue\(1,\s*CONCAT\(0x7e,\s*([A-Za-z0-9]+)\)\)", value, re.I)
    if m:
        return xpath_error(m.group(1))
    # Unbalanced quotes -> syntax error echoing the tail of the value.
    if value.count("'") % 2 == 1 or value.count('"') % 2 == 1:
        return mysql_error(value[-12:])
    # Time-based: SLEEP(n) anywhere.
    m = re.search(r"SLEEP\((\d+)\)", value, re.I)
    if m:
        time.sleep(int(m.group(1)))
        return NORMAL
    # Boolean: every AND <a>=<b> (numeric or quoted) must hold.
    conds = re.findall(r"AND\s+(\d+)\s*=\s*(\d+)", value, re.I)
    conds += re.findall(r"AND\s*'([^']*)'\s*=\s*'([^']*)", value, re.I)
    if conds:
        return NORMAL if all(a == b for a, b in conds) else EMPTY
    return NORMAL


class Handler(BaseHTTPRequestHandler):
    def _handle(self):
        u = urlparse(self.path)
        params = dict(parse_qsl(u.query))
        page = NORMAL
        if u.path == "/get":
            page = eval_value(unquote_plus(params.get("id", "1")))
        elif u.path == "/item":
            page = eval_value(unquote_plus(params.get("name", "widget")))
        elif u.path == "/session":
            cookies = dict(
                c.strip().split("=", 1) for c in (self.headers.get("Cookie") or "").split(";") if "=" in c
            )
            page = eval_value(unquote_plus(cookies.get("sid", "abc123")))
        body = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle

    def _handle_post(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        u = urlparse(self.path)
        params = dict(parse_qsl(body))
        page = NORMAL
        if u.path == "/login":
            page = eval_value(unquote_plus(params.get("user", "admin")))
        out = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_POST = _handle_post

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8734
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
