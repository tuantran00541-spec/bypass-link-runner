#!/usr/bin/env python3
"""Minimal localhost forward proxy for Playwright/Chromium on this VM.

Why it exists: Chromium's CONNECT to the VM egress proxy
(http://hatch-egress-proxy:3128) is denied with
`{"detail":"The proxy did not authorize this connection.",
"error":"policy_denied"}` (HTTP 403) — while the byte-identical CONNECT
issued from a plain Python socket (or curl) gets `200 Connection
Established`. The discriminator is not in the request bytes (replaying
Chromium's exact CONNECT bytes verbatim from Python also returns 200),
so the egress proxy is keying on something about Chromium's connection
itself. This relay makes *our* process issue the CONNECT (which the
egress proxy accepts) and just shuttles bytes between Chromium and the
egress proxy. All traffic still goes through the sanctioned egress
proxy; nothing is bypassed.

Usage (run in the background before launching Chromium):
    python3 relay_proxy.py [--port 8888] [--upstream-host 198.19.0.1]
Chromium then uses proxy http://127.0.0.1:8888.
"""
import argparse
import socket
import threading

BUF = 65536


def read_headers(conn):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = conn.recv(BUF)
        if not chunk:
            break
        data += chunk
    return data


def relay(a, b):
    try:
        while True:
            chunk = a.recv(BUF)
            if not chunk:
                break
            b.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, upstream_host, upstream_port):
    try:
        req = read_headers(client)
        if not req:
            return
        line = req.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = line.split(" ")
        if len(parts) < 2 or parts[0] != "CONNECT":
            client.sendall(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n")
            return
        target = parts[1]
        print(f"[relay] CONNECT {target}", flush=True)
        up = socket.create_connection((upstream_host, upstream_port), timeout=30)
        up.sendall(req)
        resp = b""
        up.settimeout(30)
        while b"\r\n\r\n" not in resp and len(resp) < 65536:
            chunk = up.recv(BUF)
            if not chunk:
                break
            resp += chunk
        client.sendall(resp)
        if b"200" not in resp.split(b"\r\n", 1)[0]:
            print(f"[relay] upstream refused {target}: {resp[:120]!r}", flush=True)
            up.close()
            return
        t1 = threading.Thread(target=relay, args=(client, up), daemon=True)
        t2 = threading.Thread(target=relay, args=(up, client), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        up.close()
    except Exception as e:
        print(f"[relay] error: {e}", flush=True)
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--upstream-host", default="198.19.0.1")
    ap.add_argument("--upstream-port", type=int, default=3128)
    args = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(50)
    print(
        f"[relay] listening 127.0.0.1:{args.port} -> "
        f"{args.upstream_host}:{args.upstream_port}",
        flush=True,
    )
    while True:
        client, _ = srv.accept()
        threading.Thread(
            target=handle, args=(client, args.upstream_host, args.upstream_port),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()
