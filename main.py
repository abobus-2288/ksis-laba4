from __future__ import annotations

import argparse
import html
import re
import socket
import threading
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

DEFAULT_PORT = 8888
DEFAULT_CONFIG = "blacklist.txt"
READ_BUF = 65536
HEADER_END = b"\r\n\r\n"


@dataclass
class ParsedRequest:
    method: str
    request_target: str
    http_version: str
    headers_raw: bytes
    body: bytes
    lines: list[str]


def load_blacklist(path: str) -> tuple[list[str], list[str]]:
    domains: list[str] = []
    url_prefixes: list[str] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                low = line.lower()
                if "://" in low:
                    url_prefixes.append(low)
                else:
                    domains.append(low)
    except OSError:
        pass
    return domains, url_prefixes


def host_matches_rule(host: str, rule_domain: str) -> bool:
    h = host.lower()
    r = rule_domain.lower().strip()
    if not r:
        return False
    return h == r or h.endswith("." + r)


def is_blocked(
    full_client_url: str,
    upstream_host: str,
    domains: list[str],
    url_prefixes: list[str],
) -> bool:
    fu = full_client_url.lower()
    for p in url_prefixes:
        if fu.startswith(p):
            return True
    for d in domains:
        if host_matches_rule(upstream_host, d):
            return True
    return False


def blocked_response_html(blocked_url: str) -> bytes:
    safe = html.escape(blocked_url, quote=True)
    page = f"""<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><title>Доступ запрещён</title></head>
<body>
<h1>403 Forbidden</h1>
<p>Доступ к адресу заблокирован прокси-сервером (чёрный список).</p>
<p><strong>URL:</strong> {safe}</p>
</body>
</html>
""".encode("utf-8")
    head = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(page)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    return head + page


def read_until(sock: socket.socket, end_marker: bytes, max_size: int = 1024 * 1024) -> bytes:
    buf = b""
    while end_marker not in buf:
        if len(buf) > max_size:
            raise ValueError("headers too large")
        chunk = sock.recv(READ_BUF)
        if not chunk:
            break
        buf += chunk
    return buf


def parse_request_head(raw: bytes) -> tuple[bytes, bytes]:
    idx = raw.find(HEADER_END)
    if idx < 0:
        return raw, b""
    head = raw[: idx + len(HEADER_END)]
    rest = raw[idx + len(HEADER_END) :]
    return head, rest


def parse_http_request(head: bytes) -> Optional[ParsedRequest]:
    try:
        text = head.decode("iso-8859-1", errors="replace")
    except Exception:
        return None
    if not text.strip():
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    first = lines[0]
    m = re.match(r"^(\S+)\s+(\S+)\s+(HTTP/\d\.\d)\s*$", first)
    if not m:
        return None
    method, target, ver = m.group(1), m.group(2), m.group(3)
    headers_lines = lines[1:]
    headers_raw = ("\r\n".join(headers_lines)).encode("iso-8859-1", errors="replace")
    if headers_lines:
        headers_raw = headers_raw + b"\r\n\r\n"
    else:
        headers_raw = b"\r\n"
    return ParsedRequest(
        method=method.upper(),
        request_target=target,
        http_version=ver,
        headers_raw=headers_raw,
        body=b"",
        lines=lines,
    )


def parse_headers_dict(lines: list[str]) -> dict[str, str]:
    d: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        d[k.strip().lower()] = v.strip()
    return d


def build_forward_request(
    pr: ParsedRequest,
) -> tuple[Optional[bytes], Optional[str], Optional[int], str, Optional[str]]:
    method = pr.method
    target = pr.request_target
    ver = pr.http_version
    hdrs = parse_headers_dict(pr.lines)

    if method == "CONNECT":
        return None, None, None, "", "CONNECT not supported"

    if target.startswith("http://") or target.startswith("HTTP://"):
        p = urlparse(target)
        host = p.hostname
        if not host:
            return None, None, None, target, "bad URL"
        port = p.port or 80
        path = p.path or "/"
        if p.query:
            path = path + "?" + p.query
        new_line = f"{method} {path} {ver}"
        out_lines = [new_line]
        for line in pr.lines[1:]:
            if not line:
                continue
            lk = line.split(":", 1)[0].strip().lower()
            if lk == "host":
                hostport = host if port == 80 else f"{host}:{port}"
                out_lines.append(f"Host: {hostport}")
            elif lk == "proxy-connection":
                continue
            else:
                out_lines.append(line)
        if not any(
            line.split(":", 1)[0].strip().lower() == "host" for line in pr.lines[1:] if ":" in line
        ):
            hostport = host if port == 80 else f"{host}:{port}"
            out_lines.insert(1, f"Host: {hostport}")
        raw = ("\r\n".join(out_lines) + "\r\n\r\n").encode("iso-8859-1", errors="replace")
        log_url = target if target.lower().startswith("http://") else f"http://{host}{path}"
        return raw + pr.body, host, port, log_url, None

    host = hdrs.get("host")
    if not host:
        return None, None, None, target, "missing Host"
    if ":" in host:
        hpart, ppart = host.rsplit(":", 1)
        try:
            port = int(ppart)
            host = hpart
        except ValueError:
            port = 80
    else:
        port = 80
    new_line = f"{method} {target} {ver}"
    out_lines = [new_line] + pr.lines[1:]
    raw = ("\r\n".join(out_lines) + "\r\n\r\n").encode("iso-8859-1", errors="replace")
    netloc = hdrs.get("host", "")
    log_url = "http://" + netloc + (target if target.startswith("/") else "/" + target)
    return raw + pr.body, host, port, log_url, None


def read_request_body(sock: socket.socket, headers: dict[str, str], already: bytes) -> bytes:
    body = already
    cl = headers.get("content-length")
    if cl is None:
        return body
    try:
        need = int(cl)
    except ValueError:
        return body
    while len(body) < need:
        chunk = sock.recv(min(READ_BUF, need - len(body)))
        if not chunk:
            break
        body += chunk
    return body


def forward_response_and_log(
    client_sock: socket.socket,
    server_sock: socket.socket,
    log_url: str,
) -> bool:
    buf = read_until(server_sock, HEADER_END)
    if HEADER_END not in buf:
        client_sock.sendall(buf)
        return True
    head, body_rest = parse_request_head(buf)
    try:
        head_text = head.decode("iso-8859-1", errors="replace")
    except Exception:
        client_sock.sendall(buf)
        return True
    lines = head_text.split("\r\n")
    status_line = lines[0] if lines else ""
    code = "???"
    m = re.match(r"^HTTP/\d\.\d\s+(\d{3})", status_line)
    if m:
        code = m.group(1)
    print(f"{log_url} -> {code}", flush=True)

    rh: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        rh[k.strip().lower()] = v.strip()

    client_sock.sendall(head)

    te = rh.get("transfer-encoding", "").lower()
    cl = rh.get("content-length")

    resp_conn_close = rh.get("connection", "").lower() == "close"

    if "chunked" in te:
        forward_chunked(server_sock, client_sock, body_rest)
        return resp_conn_close

    if cl is not None:
        try:
            n = int(cl)
        except ValueError:
            client_sock.sendall(body_rest)
            pump_all(server_sock, client_sock)
            return True
        remaining = n - len(body_rest)
        if body_rest:
            client_sock.sendall(body_rest)
        while remaining > 0:
            chunk = server_sock.recv(min(READ_BUF, remaining))
            if not chunk:
                break
            client_sock.sendall(chunk)
            remaining -= len(chunk)
        return resp_conn_close

    if body_rest:
        client_sock.sendall(body_rest)
    pump_all(server_sock, client_sock)
    return True


def forward_chunked(src: socket.socket, dst: socket.socket, initial: bytes) -> None:
    buf = initial
    while True:
        while b"\r\n" not in buf:
            more = src.recv(READ_BUF)
            if not more:
                if buf:
                    dst.sendall(buf)
                return
            buf += more
        line, _, buf = buf.partition(b"\r\n")
        ext = line.split(b";", 1)[0].strip()
        try:
            size = int(ext, 16)
        except ValueError:
            dst.sendall(line + b"\r\n" + buf)
            pump_all(src, dst)
            return
        while len(buf) < size + 2:
            more = src.recv(READ_BUF)
            if not more:
                if buf:
                    dst.sendall(buf)
                return
            buf += more
        chunk_data = buf[:size]
        crlf = buf[size : size + 2]
        buf = buf[size + 2 :]
        if crlf != b"\r\n":
            dst.sendall(line + b"\r\n" + chunk_data + crlf + buf)
            pump_all(src, dst)
            return
        dst.sendall(line + b"\r\n" + chunk_data + b"\r\n")
        if size == 0:
            if b"\r\n\r\n" in buf:
                i = buf.index(b"\r\n\r\n") + 4
                dst.sendall(buf[:i])
                return
            if buf:
                while b"\r\n\r\n" not in buf:
                    more = src.recv(READ_BUF)
                    if not more:
                        dst.sendall(buf)
                        return
                    buf += more
                i = buf.index(b"\r\n\r\n") + 4
                dst.sendall(buf[:i])
            return


def pump_all(src: socket.socket, dst: socket.socket) -> None:
    while True:
        data = src.recv(READ_BUF)
        if not data:
            break
        dst.sendall(data)


def handle_client(
    client_sock: socket.socket,
    addr: tuple,
    domains: list[str],
    url_prefixes: list[str],
) -> None:
    client_sock.settimeout(300)
    try:
        while True:
            resp_close = True
            raw = read_until(client_sock, HEADER_END)
            if not raw:
                break
            if HEADER_END not in raw:
                break
            head, rest = parse_request_head(raw)
            pr = parse_http_request(head)
            if not pr:
                break

            hdrs = parse_headers_dict(pr.lines)
            pr.body = read_request_body(client_sock, hdrs, rest)

            if pr.method == "CONNECT":
                client_sock.sendall(
                    b"HTTP/1.1 501 Not Implemented\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Connection: close\r\n\r\n"
                    b"HTTPS (CONNECT) is not supported.\r\n"
                )
                print(f"(CONNECT отклонён) клиент {addr}", flush=True)
                break

            fwd, host, port, log_url, err = build_forward_request(pr)
            if err or not host or fwd is None:
                print(f"Ошибка запроса от {addr}: {err or 'unknown'}", flush=True)
                break

            if is_blocked(log_url, host, domains, url_prefixes):
                print(f"{log_url} -> 403 (чёрный список)", flush=True)
                client_sock.sendall(blocked_response_html(log_url))
                break

            try:
                server_sock = socket.create_connection((host, port), timeout=30)
            except OSError as e:
                print(f"{log_url} -> (ошибка соединения: {e})", flush=True)
                msg = (
                    "HTTP/1.1 502 Bad Gateway\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    "Connection: close\r\n\r\n"
                    f"Cannot connect to upstream: {e}\r\n"
                ).encode("utf-8", errors="replace")
                try:
                    client_sock.sendall(msg)
                except OSError:
                    pass
                break

            try:
                server_sock.settimeout(None)
                server_sock.sendall(fwd)
                resp_close = forward_response_and_log(client_sock, server_sock, log_url)
            finally:
                try:
                    server_sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                server_sock.close()

            conn = hdrs.get("connection", "").lower()
            if conn == "close" or resp_close:
                break
    except (socket.timeout, BrokenPipeError, ConnectionResetError, OSError) as e:
        print(f"Соединение {addr}: {e}", flush=True)
    finally:
        try:
            client_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        client_sock.close()


def serve(bind: str, port: int, blacklist_path: str) -> None:
    domains, url_prefixes = load_blacklist(blacklist_path)
    if domains or url_prefixes:
        print(
            f"Чёрный список: {blacklist_path!r} — {len(domains)} домен(ов), {len(url_prefixes)} URL-префикс(ов).",
            flush=True,
        )
    else:
        print("Чёрный список не загружен или пуст.", flush=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, port))
    srv.listen(128)
    print(f"HTTP-прокси слушает {bind}:{port}", flush=True)
    while True:
        c, a = srv.accept()
        t = threading.Thread(
            target=handle_client,
            args=(c, a, domains, url_prefixes),
            daemon=True,
        )
        t.start()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-b", "--bind", default="127.0.0.1")
    ap.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    args = ap.parse_args()
    serve(args.bind, args.port, args.config)


if __name__ == "__main__":
    main()
