"""Minimal SOCKS5 (no-auth) proxy for tests.

Usage: python3 tests/tinysocks.py <port> <logfile>

Implements just enough of RFC 1928 for a proxy client: the method
negotiation (always picks no-auth), a CONNECT request (IPv4 and domain
forms), then a bidirectional byte relay. Appends one "CONNECT <host:port>"
line per accepted tunnel to the log file so tests can prove traffic flowed
through the SOCKS proxy. stdlib only.
"""

import socket
import struct
import sys
import threading

LOG_PATH = None
LOG_LOCK = threading.Lock()


def log(line):
    with LOG_LOCK:
        with open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def relay(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(conn):
    try:
        ver, nmethods = struct.unpack("BB", recv_exact(conn, 2))
        if ver != 5:
            return
        recv_exact(conn, nmethods)
        conn.sendall(b"\x05\x00")  # no authentication required
        ver, cmd, _rsv, atyp = struct.unpack("BBBB", recv_exact(conn, 4))
        if ver != 5 or cmd != 1:  # CONNECT only
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        if atyp == 1:  # IPv4
            host = socket.inet_ntoa(recv_exact(conn, 4))
        elif atyp == 3:  # domain
            (ln,) = struct.unpack("B", recv_exact(conn, 1))
            host = recv_exact(conn, ln).decode()
        else:
            conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        (port,) = struct.unpack(">H", recv_exact(conn, 2))
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return
        log(f"CONNECT {host}:{port}")
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        t = threading.Thread(target=relay, args=(conn, upstream), daemon=True)
        t.start()
        relay(upstream, conn)
        t.join(timeout=5)
    except (ConnectionError, OSError, struct.error):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    global LOG_PATH
    port = int(sys.argv[1])
    LOG_PATH = sys.argv[2]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
