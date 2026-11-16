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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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



# --- Fake in-memory "database" the emulated MySQL server holds --------------
# The exfiltration half of the port runs information_schema / dump subqueries
# through blind bisection; the emulator evaluates exactly those query shapes
# against this state, so end-to-end tests assert real recovered values.
SCHEMATA = ["information_schema", "mysql", "shop"]
TABLES = {
    "information_schema": ["columns", "schemata", "tables"],
    "mysql": ["db", "user"],
    "shop": ["products", "users"],
}
COLUMNS = {
    ("information_schema", "columns"): ["table_schema", "table_name", "column_name"],
    ("information_schema", "schemata"): ["schema_name"],
    ("information_schema", "tables"): ["table_schema", "table_name"],
    ("mysql", "db"): ["host", "db", "user"],
    ("mysql", "user"): ["host", "user", "password"],
    ("shop", "products"): ["id", "name", "price"],
    ("shop", "users"): ["id", "username", "password"],
}
ROWS = {
    ("shop", "products"): [("1", "widget", "9.99"), ("2", "gadget", "19.99")],
    ("shop", "users"): [
        ("1", "admin", "s3cr3t-pass"),
        ("2", "alice", "hunter2"),
        ("3", "bob", "qwerty"),
    ],
    ("mysql", "user"): [("localhost", "root", "mysql-native-hash")],
    ("mysql", "db"): [("localhost", "shop", "app")],
}


def name_token(tok):
    """Decode a SQL identifier literal: 0x hex string or 'quoted'."""
    tok = tok.strip()
    m = re.fullmatch(r"0x([0-9a-fA-F]+)", tok)
    if m:
        return bytes.fromhex(m.group(1)).decode("utf-8", "replace")
    m = re.fullmatch(r"'([^']*)'", tok)
    if m:
        return m.group(1)
    return tok


def eval_scalar(q):
    """Evaluate the fixed set of subqueries the port issues for enumeration
    against the fake in-memory DB. Returns str/int, or None if unrecognized."""
    q = re.sub(r"\s+", " ", q.strip())
    m = re.fullmatch(r"SELECT GROUP_CONCAT\(schema_name SEPARATOR 0x3a\) FROM information_schema\.schemata", q, re.I)
    if m:
        return ":".join(SCHEMATA)
    m = re.fullmatch(r"SELECT GROUP_CONCAT\(table_name SEPARATOR 0x3a\) FROM information_schema\.tables WHERE table_schema=(\S+)", q, re.I)
    if m:
        return ":".join(TABLES.get(name_token(m.group(1)), []))
    m = re.fullmatch(r"SELECT GROUP_CONCAT\(column_name SEPARATOR 0x3a\) FROM information_schema\.columns WHERE table_schema=(\S+) AND table_name=(\S+)", q, re.I)
    if m:
        return ":".join(COLUMNS.get((name_token(m.group(1)), name_token(m.group(2))), []))
    if re.fullmatch(r"SELECT COUNT\(schema_name\) FROM information_schema\.schemata", q, re.I):
        return len(SCHEMATA)
    m = re.fullmatch(r"SELECT schema_name FROM information_schema\.schemata LIMIT (\d+),1", q, re.I)
    if m:
        i = int(m.group(1))
        return SCHEMATA[i] if i < len(SCHEMATA) else ""
    m = re.fullmatch(r"SELECT COUNT\(table_name\) FROM information_schema\.tables WHERE table_schema=(\S+)", q, re.I)
    if m:
        return len(TABLES.get(name_token(m.group(1)), []))
    m = re.fullmatch(r"SELECT table_name FROM information_schema\.tables WHERE table_schema=(\S+) LIMIT (\d+),1", q, re.I)
    if m:
        lst = TABLES.get(name_token(m.group(1)), [])
        i = int(m.group(2))
        return lst[i] if i < len(lst) else ""
    m = re.fullmatch(r"SELECT COUNT\(column_name\) FROM information_schema\.columns WHERE table_schema=(\S+) AND table_name=(\S+)", q, re.I)
    if m:
        return len(COLUMNS.get((name_token(m.group(1)), name_token(m.group(2))), []))
    m = re.fullmatch(r"SELECT column_name FROM information_schema\.columns WHERE table_schema=(\S+) AND table_name=(\S+) LIMIT (\d+),1", q, re.I)
    if m:
        lst = COLUMNS.get((name_token(m.group(1)), name_token(m.group(2))), [])
        i = int(m.group(3))
        return lst[i] if i < len(lst) else ""
    m = re.fullmatch(r"SELECT COUNT\(\*\) FROM (\w+)\.(\w+)", q, re.I)
    if m:
        return len(ROWS.get((m.group(1).lower(), m.group(2).lower()), []))
    m = re.fullmatch(r"SELECT CONCAT_WS\(0x3a,([\w,]+)\) FROM (\w+)\.(\w+) LIMIT (\d+),1", q, re.I)
    if m:
        rows = ROWS.get((m.group(2).lower(), m.group(3).lower()), [])
        i = int(m.group(4))
        return ":".join(rows[i]) if i < len(rows) else ""
    return None


def balanced(s, i):
    """s[i] must be '('; return (content, index after matching ')')."""
    if i >= len(s) or s[i] != "(":
        return None, -1
    depth = 0
    for j in range(i, len(s)):
        if s[j] == "(":
            depth += 1
        elif s[j] == ")":
            depth -= 1
            if depth == 0:
                return s[i + 1 : j], j + 1
    return None, -1


def exfil_conditions(full):
    """Collect (value, op, num) triples from blind-exfil condition shapes:
    ASCII(SUBSTRING((q),P,1))<op>N, LENGTH((q))<op>N, (SELECT COUNT...)<op>N."""
    out = []
    for m in re.finditer(r"ASCII\s*\(\s*SUBSTRING\s*\(\s*", full, re.I):
        if m.end() >= len(full) or full[m.end()] != "(":
            continue
        scalar, end = balanced(full, m.end())
        m2 = re.match(r"\s*,\s*(\d+)\s*,\s*1\s*\)\s*\)\s*(>=|<=|=|>|<)\s*(\d+)", full[end:])
        if scalar is None or not m2:
            continue
        val = eval_scalar(scalar)
        if val is None:
            continue
        pos = int(m2.group(1))
        s = str(val)
        ch = s[pos - 1] if 0 < pos <= len(s) else ""
        out.append((ord(ch) if ch else 0, m2.group(2), int(m2.group(3))))
    for m in re.finditer(r"LENGTH\s*\(\s*", full, re.I):
        if m.end() >= len(full) or full[m.end()] != "(":
            continue
        scalar, end = balanced(full, m.end())
        m2 = re.match(r"\s*\)\s*(>=|<=|=|>|<)\s*(\d+)", full[end:])
        if scalar is None or not m2:
            continue
        val = eval_scalar(scalar)
        if val is None:
            continue
        out.append((len(str(val)), m2.group(1), int(m2.group(2))))
    for m in re.finditer(r"AND\s*\(", full, re.I):
        inner, end = balanced(full, m.end() - 1)
        if inner is None or not re.match(r"\s*SELECT\s+COUNT", inner, re.I):
            continue
        m2 = re.match(r"\s*(>=|<=|=|>|<)\s*(\d+)", full[end:])
        if not m2:
            continue
        val = eval_scalar(inner)
        if val is None:
            continue
        out.append((int(val), m2.group(1), int(m2.group(2))))
    return out


def split_top_commas(s):
    """Split on commas at paren depth 0."""
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def eval_union_item(item):
    """Evaluate one UNION SELECT list item against the fake DB.
    Returns the rendered cell text, or None when unrecognized."""
    item = item.strip()
    if re.fullmatch(r"NULL", item, re.I):
        return ""
    if re.fullmatch(r"\d+", item):
        return item
    m = re.fullmatch(r"CONCAT\((.*)\)", item, re.I | re.S)
    if m:
        out = ""
        for part in split_top_commas(m.group(1)):
            part = part.strip()
            if re.fullmatch(r"0x[0-9a-fA-F]+", part):
                out += bytes.fromhex(part[2:]).decode("utf-8", "replace")
            elif part.startswith("("):
                scalar, _ = balanced(part, 0)
                if scalar is None:
                    return None
                v = eval_scalar(scalar)
                out += "" if v is None else str(v)
            else:
                return None
        return out
    if item.startswith("("):
        scalar, _ = balanced(item, 0)
        if scalar is None:
            return None
        v = eval_scalar(scalar)
        return None if v is None else str(v)
    return None


def union_page(vals):
    """The injected UNION row rendered the way the app renders table rows."""
    return (
        "<html><body><h1>Item " + vals[0] + "</h1><p>" + vals[1] +
        " - in stock: " + vals[2] + "</p></body></html>"
    )


def strip_dash_comments(s):
    """MySQL '--' comments: '--' + whitespace starts a comment that runs to
    the end of the line (not past it). Returns the statement with comments
    replaced by a single space. Handles space2mysqldash's --%0A sequences."""
    out = []
    i = 0
    while i < len(s):
        if s[i : i + 2] == "--" and i + 2 < len(s) and s[i + 2].isspace():
            j = i + 2
            while j < len(s) and s[j] != "\n":
                j += 1
            out.append(" ")
            i = j  # the newline itself survives (it terminates the comment)
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def compare(value, op, num):
    if op == ">":
        return value > num
    if op == "<":
        return value < num
    if op == ">=":
        return value >= num
    if op == "<=":
        return value <= num
    return value == num


def eval_value(value: str, quoted: bool = False) -> str:
    """Decide the page for an injected parameter value.

    Emulates a real query template: the app wraps string params in quotes,
    and "-- " comments out the remainder of the statement.
    """
    value = value.replace("/**/", " ")
    value = re.sub(r"#[^\n]*\n", " ", value)  # MySQL '#' comment (tamper space2hash)
    full = ("'" + value + "'") if quoted else value
    full = strip_dash_comments(full)
    # Error-based: ExtractValue(1,CONCAT(0x7e,<marker>)) echoes the marker.
    m = re.search(r"ExtractValue\(1,\s*CONCAT\(0x7e,\s*([A-Za-z0-9]+)\)\)", full, re.I)
    if m:
        return xpath_error(m.group(1))
    # Time-based: SLEEP(n) anywhere.
    m = re.search(r"SLEEP\((\d+)\)", full, re.I)
    if m:
        time.sleep(int(m.group(1)))
        return NORMAL
    # UNION SELECT: the emulated table has 3 columns; the injected row is
    # rendered through the app's row template.
    m = re.search(r"UNION\s+(ALL\s+)?SELECT\s", full, re.I)
    if m:
        items = split_top_commas(full[m.end():])
        if len(items) != 3:
            return mysql_error("The used SELECT statements have a different number of columns")
        vals = [eval_union_item(it) for it in items]
        if any(v is None for v in vals):
            return mysql_error("Illegal mix of collations for operation 'UNION'")
        return union_page(vals)
    # UNION probing: ORDER BY n fails for n beyond the table's 3 columns.
    m = re.search(r"ORDER\s+BY\s+(\d+)", full, re.I)
    if m:
        n = int(m.group(1))
        if n > 3:
            return mysql_error("Unknown column '%d' in 'order clause'" % n)
        return NORMAL
    # Quote balance with '' as an escaped quote inside strings.
    in_str = False
    i = 0
    while i < len(full):
        if full[i] == "'":
            if in_str and i + 1 < len(full) and full[i + 1] == "'":
                i += 2
                continue
            in_str = not in_str
        i += 1
    if in_str or full.count('"') % 2 == 1:
        return mysql_error(full[-12:])
    # Boolean: every AND <a>=<b> (numeric or quoted) must hold.
    conds = re.findall(r"AND\s+(\d+)\s*=\s*(\d+)", full, re.I)
    conds += re.findall(r"AND\s*'([^']*)'\s*=\s*'([^']*)", full, re.I)
    ok = all(a == b for a, b in conds) if conds else True
    xconds = exfil_conditions(full)
    if xconds:
        ok = ok and all(compare(v, op, n) for v, op, n in xconds)
    if conds or xconds:
        return NORMAL if ok else EMPTY
    return NORMAL


class Handler(BaseHTTPRequestHandler):
    def _handle(self):
        u = urlparse(self.path)
        params = dict(parse_qsl(u.query))
        page = NORMAL
        status = 200
        extra_headers = []
        if u.path == "/":
            # Link hub for crawler tests: same-host links at depth 1, one
            # off-site link, non-http schemes, a fragment, a static asset.
            page = (
                "<html><body><h1>Index</h1>"
                '<a href="/search">search</a>'
                '<a href="/get?id=1">item by id</a>'
                '<a href="/item?name=widget">item by name</a>'
                '<a href="/detail">detail</a>'
                '<a href="http://example.com/offsite">external</a>'
                '<a href="javascript:void(0)">js</a>'
                '<a href="#frag">fragment</a>'
                '<a href="/static/logo.png">logo</a>'
                "</body></html>"
            )
        elif u.path == "/detail":
            # Depth-2 page plus a cycle back to the index.
            page = (
                "<html><body><h1>Detail</h1>"
                '<a href="/deep">deep</a>'
                '<a href="/">home</a>'
                '<a href="/search">search again</a>'
                "</body></html>"
            )
        elif u.path == "/deep":
            page = "<html><body><h1>Deep</h1></body></html>"
        elif u.path == "/wafed":
            # ModSecurity emulation: attack-looking requests get a 406.
            if re.search(r"UNION|<script|\.\./", self.path, re.I):
                status = 406
                page = (
                    "<html><head><title>406 Not Acceptable</title></head><body>"
                    "<h1>Not Acceptable</h1><p>This error was generated by "
                    "Mod_Security.</p></body></html>"
                )
        elif u.path == "/cdn":
            # Cloudflare emulation: attack-looking requests get its 403 page.
            if re.search(r"UNION|<script|\.\./", self.path, re.I):
                status = 403
                extra_headers = [("Server", "cloudflare")]
                page = (
                    "<html><head><title>Attention Required! | Cloudflare</title>"
                    "</head><body><h1>Sorry, you have been blocked</h1>"
                    "</body></html>"
                )
        elif u.path == "/search":
            page = (
                "<html><body>"
                '<form action="/item" method="get">'
                '<input type="text" name="name" value="widget">'
                '<input type="submit" value="Search">'
                "</form>"
                '<form action="/login" method="post">'
                '<input type="text" name="user" value="admin">'
                '<input type="password" name="pass">'
                "</form>"
                "</body></html>"
            )
        elif u.path == "/get":
            page = eval_value(unquote_plus(params.get("id", "1")))
        elif u.path == "/item":
            page = eval_value(unquote_plus(params.get("name", "widget")), quoted=True)
        elif u.path == "/track":
            page = eval_value(unquote_plus(self.headers.get("User-Agent", "")), quoted=True)
        elif u.path == "/session":
            cookies = dict(
                c.strip().split("=", 1) for c in (self.headers.get("Cookie") or "").split(";") if "=" in c
            )
            page = eval_value(unquote_plus(cookies.get("sid", "abc123")), quoted=True)
        body = page.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for k, v in extra_headers:
            self.send_header(k, v)
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
            page = eval_value(unquote_plus(params.get("user", "admin")), quoted=True)
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
    # Threaded so worker-pool concurrency tests measure real parallelism.
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
