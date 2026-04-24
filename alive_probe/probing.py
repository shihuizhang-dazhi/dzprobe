import ssl
import time
import random
import json
import base64
import socket
import struct
import re
import errno
import os
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .constants import (
    DEFAULT_ACCEPT_LANGUAGE,
    DEFAULT_REFERER,
    DEFAULT_USER_AGENTS,
    TITLE_RE,
    load_service_mapping,
)
from .models import ProbeResult


DEFAULT_MAX_FINGERPRINT_HITS = 3


# 从响应 HTML 中提取 <title>，用于结果展示。
def extract_title(html: str) -> str:
    match = TITLE_RE.search(html)
    if not match:
        return ""
    return " ".join(match.group(1).split())[:80]


# 将输入目标展开为待尝试 URL 列表（默认先 https 后 http）。
def expand_candidate_urls(target: str, https_first: bool = True) -> List[str]:
    value = target.strip()
    if not value:
        return []
    if value.startswith(("http://", "https://")):
        return [value]
    schemes = ["https", "http"] if https_first else ["http", "https"]
    return [f"{scheme}://{value}" for scheme in schemes]


# 组装请求头：默认随机 UA，可通过参数覆盖语言和来源页。
def build_request_headers(
    user_agent: Optional[str],
    accept_language: Optional[str],
    referer: Optional[str],
) -> Dict[str, str]:
    ua = user_agent if user_agent else random.choice(DEFAULT_USER_AGENTS)
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": accept_language or DEFAULT_ACCEPT_LANGUAGE,
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    if referer is not None and referer != "":
        headers["Referer"] = referer
    elif referer is None:
        headers["Referer"] = DEFAULT_REFERER
    return headers


def _flatten_headers(headers: Dict[str, str]) -> str:
    pairs = [f"{k.lower()}:{v.lower()}" for k, v in headers.items()]
    return "\n".join(pairs)


ASCII_WORD_RE = re.compile(r"^[a-z0-9_\-]+$")


def _keyword_match(text: str, keyword: str, strict: bool) -> bool:
    if not strict:
        return keyword in text
    if not keyword:
        return False
    # 严格模式：纯英文单词按边界匹配，避免 isite 命中 visited 这类误报。
    if ASCII_WORD_RE.match(keyword):
        pattern = rf"(?<![a-z0-9_\-]){re.escape(keyword)}(?![a-z0-9_\-])"
        return re.search(pattern, text) is not None
    return keyword in text


KeywordRule = Tuple[str, str, List[str]]
FaviconRule = Tuple[str, int]
UDPStatus = str
SignatureRule = Tuple[str, re.Pattern]

COMMON_HTTP_PORTS = {
    80,
    81,
    443,
    4443,
    5000,
    7001,
    7002,
    7777,
    8000,
    8001,
    8008,
    8080,
    8081,
    8088,
    8090,
    8161,
    8232,
    8443,
    8444,
    8888,
    9000,
}

HTTPS_LIKELY_PORTS = {443, 4443, 8443, 8444, 9443}
WEB_LIKELY_PORTS = COMMON_HTTP_PORTS | {3000, 5001, 5601, 6443, 7474, 8082, 9090, 9200, 15672}

MAX_ACTIVE_SERVICE_PROBES = 3

TLS_CLIENT_HELLO = bytes.fromhex(
    "160301002f0100002b030300000000000000000000000000000000000000000000000000000000000000"
    "000002002f01000000"
)


def _normalize_server_header(value: str) -> str:
    cleaned = (value or "").strip()
    if cleaned.lower() in {"", "none", "null", "unknown", "n/a", "na", "-"}:
        return ""
    return cleaned


def _should_try_http_enrich(candidate: str, port: int, mapped_service: str, service_probe: str) -> bool:
    probe_hint = service_probe.strip().lower() if service_probe else ""
    if candidate.startswith(("http://", "https://")):
        return True
    if port in COMMON_HTTP_PORTS:
        return True
    if mapped_service.startswith("http") or "web" in mapped_service:
        return True
    return service_probe.startswith("http:") or service_probe.startswith("tls:")


def _should_try_http_fingerprint(target: str, port: int, mapped_service: str, service_probe: str) -> bool:
    # Only perform HTTP fingerprint probing when the endpoint is likely web.
    if target.startswith(("http://", "https://")):
        return True
    if port in WEB_LIKELY_PORTS:
        return True
    if mapped_service.startswith("http") or "web" in mapped_service:
        return True
    return service_probe.startswith("http:") or service_probe.startswith("tls:")


def _prefer_https_for_target(target: str) -> bool:
    value = target.strip().lower()
    if value.startswith("https://"):
        return True
    if value.startswith("http://"):
        return False

    host, port = parse_host_port(target, "")
    if host and port > 0 and port in COMMON_HTTP_PORTS:
        return port in HTTPS_LIKELY_PORTS
    return True


def _collect_light_web_hints(server_header: str, title: str, body: str) -> str:
    text = " ".join([server_header.lower(), title.lower(), body.lower()])
    hints: List[str] = []

    if "tomcat" in text:
        hints.append("Apache Tomcat")
    if "nginx" in text:
        hints.append("nginx")
    if "confluence" in text:
        hints.append("Confluence")
    if "login" in text:
        hints.append("Login")

    # 去重并保持顺序。
    seen: Set[str] = set()
    unique_hints = [item for item in hints if not (item in seen or seen.add(item))]
    return ",".join(unique_hints)


@lru_cache(maxsize=8)
def load_external_fingerprint_rules(db_path: str) -> Tuple[List[KeywordRule], List[FaviconRule]]:
    if not db_path:
        return [], []
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return [], []

    keyword_rules: List[KeywordRule] = []
    favicon_rules: List[FaviconRule] = []
    if not isinstance(raw, list):
        return keyword_rules, favicon_rules

    for item in raw:
        if not isinstance(item, dict):
            continue
        cms = str(item.get("cms", "")).strip()
        method = str(item.get("method", "")).strip().lower()
        location = str(item.get("location", "body")).strip().lower()
        keywords = item.get("keyword", [])

        if not cms or not isinstance(keywords, list):
            continue
        if method == "keyword" and location in ("body", "header"):
            normalized = [str(keyword).lower() for keyword in keywords if str(keyword).strip()]
            if normalized:
                keyword_rules.append((cms, location, normalized))
            continue
        if method == "faviconhash":
            for keyword in keywords:
                text = str(keyword).strip()
                if not text:
                    continue
                try:
                    favicon_rules.append((cms, int(text)))
                except ValueError:
                    continue

    return keyword_rules, favicon_rules


# FOFA 常见规则基于 favicon 的 base64 文本做 MurmurHash3(32-bit) 计算。
def murmurhash3_32(data: bytes, seed: int = 0) -> int:
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF

    rounded_end = length & ~0x3
    for i in range(0, rounded_end, 4):
        k1 = struct.unpack_from("<I", data, i)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[rounded_end:]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    if h1 & 0x80000000:
        return -((~h1 + 1) & 0xFFFFFFFF)
    return h1


def compute_favicon_hash(icon_bytes: bytes) -> int:
    b64_content = base64.encodebytes(icon_bytes)
    return murmurhash3_32(b64_content)


def fetch_favicon_hash(url: str, timeout: float, ssl_context: ssl.SSLContext, headers: Dict[str, str]) -> Optional[int]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None

    favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
    req = Request(favicon_url, headers=headers)
    try:
        with urlopen(req, timeout=timeout, context=ssl_context) as resp:
            icon_data = resp.read(512 * 1024)
            if not icon_data:
                return None
            return compute_favicon_hash(icon_data)
    except Exception:
        return None


# 基于外部指纹库匹配 header/body 关键词与 faviconhash。
def detect_fingerprint(
    headers: Dict[str, str],
    body: str,
    favicon_hash: Optional[int],
    fingerprint_db: str,
    strict: bool,
    denylist: Set[str],
    max_hits: int,
) -> str:
    header_corpus = _flatten_headers(headers)
    body_corpus = body.lower() if body else ""
    hits: List[str] = []
    keyword_rules, favicon_rules = load_external_fingerprint_rules(fingerprint_db)

    for cms, location, keywords in keyword_rules:
        if cms.lower() in denylist:
            continue
        text = body_corpus if location == "body" else header_corpus
        if text and all(_keyword_match(text, keyword, strict) for keyword in keywords) and cms not in hits:
            hits.append(cms)
        if len(hits) >= max_hits:
            break

    if len(hits) < max_hits and favicon_hash is not None:
        for cms, expected_hash in favicon_rules:
            if cms.lower() in denylist:
                continue
            if expected_hash == favicon_hash and cms not in hits:
                hits.append(cms)
            if len(hits) >= max_hits:
                break

    return ",".join(hits)


# 对单个 URL 发起请求并返回探测结果。
def probe_url(
    url: str,
    timeout: float,
    ssl_context: ssl.SSLContext,
    user_agent: Optional[str],
    accept_language: Optional[str],
    referer: Optional[str],
    enable_fingerprint: bool,
    fingerprint_db: str,
    strict_fingerprint: bool,
    denylist: Set[str],
    max_fingerprint_hits: int,
) -> ProbeResult:
    start = time.perf_counter()
    headers = build_request_headers(user_agent, accept_language, referer)
    req = Request(
        url,
        headers=headers,
    )
    try:
        with urlopen(req, timeout=timeout, context=ssl_context) as resp:
            data = resp.read(16384)
            content = data.decode("utf-8", errors="ignore")
            latency_ms = int((time.perf_counter() - start) * 1000)
            headers = {key: value for key, value in resp.headers.items()}
            server_header = _normalize_server_header(headers.get("Server", ""))
            favicon_hash = None
            if enable_fingerprint:
                _, favicon_rules = load_external_fingerprint_rules(fingerprint_db)
                if favicon_rules:
                    favicon_hash = fetch_favicon_hash(resp.geturl(), timeout, ssl_context, headers)
            title = extract_title(content)
            fingerprint_value = (
                detect_fingerprint(
                    headers,
                    content,
                    favicon_hash,
                    fingerprint_db,
                    strict_fingerprint,
                    denylist,
                    max_fingerprint_hits,
                )
                if enable_fingerprint
                else _collect_light_web_hints(server_header, title, content)
            )
            return ProbeResult(
                target=url,
                final_url=resp.geturl(),
                status=getattr(resp, "status", 0),
                latency_ms=latency_ms,
                http_server=server_header,
                title=title,
                fingerprint=fingerprint_value,
                alive=True,
            )
    except HTTPError as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        data = exc.read(16384)
        content = data.decode("utf-8", errors="ignore") if data else ""
        code = getattr(exc, "code", 0)
        headers = {key: value for key, value in exc.headers.items()} if exc.headers else {}
        server_header = _normalize_server_header(headers.get("Server", ""))
        title = extract_title(content)
        fingerprint_value = (
            detect_fingerprint(
                headers,
                content,
                None,
                fingerprint_db,
                strict_fingerprint,
                denylist,
                max_fingerprint_hits,
            )
            if enable_fingerprint
            else _collect_light_web_hints(server_header, title, content)
        )
        return ProbeResult(
            target=url,
            final_url=getattr(exc, "url", url),
            status=code,
            latency_ms=latency_ms,
            http_server=server_header,
            title=title,
            fingerprint=fingerprint_value,
            alive=True,
            error=str(exc),
        )
    except Exception as exc:
        latency_ms = int((time.perf_counter() - start) * 1000)
        return ProbeResult(
            target=url,
            final_url="",
            status=0,
            latency_ms=latency_ms,
            title="",
            fingerprint="",
            alive=False,
            error=str(exc),
        )


def parse_host_port(target: str, final_url: str) -> Tuple[str, int]:
    source = final_url or target
    if source.startswith(("http://", "https://")):
        parsed = urlparse(source)
        if not parsed.hostname:
            return "", 0
        if parsed.port:
            return parsed.hostname, parsed.port
        return parsed.hostname, (443 if parsed.scheme == "https" else 80)

    if ":" in source:
        host, maybe_port = source.rsplit(":", 1)
        if host and maybe_port.isdigit():
            port = int(maybe_port)
            if 1 <= port <= 65535:
                return host, port

    return source.strip(), 80


def _resolve_ipv4(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


@lru_cache(maxsize=4096)
def _resolve_endpoint(host: str, port: int) -> Optional[Tuple[str, int]]:
    ip = _resolve_ipv4(host)
    if not ip:
        return None
    return ip, port


def _get_local_ip_for_target(dst_ip: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((dst_ip, 53))
        return s.getsockname()[0]


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _build_ipv4_header(src_ip: str, dst_ip: str, total_len: int, ident: int = 54321) -> bytes:
    version_ihl = (4 << 4) + 5
    tos = 0
    flags_frag = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        proto,
        checksum,
        src,
        dst,
    )
    checksum = _checksum(header)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        proto,
        checksum,
        src,
        dst,
    )


def _build_tcp_syn_segment(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int = 0) -> bytes:
    ack_seq = 0
    data_offset = 5
    flags = 0x02  # SYN
    offset_res_flags = (data_offset << 12) | flags
    window = 64240
    checksum = 0
    urg_ptr = 0
    tcp_header = struct.pack(
        "!HHLLHHHH",
        src_port,
        dst_port,
        seq,
        ack_seq,
        offset_res_flags,
        window,
        checksum,
        urg_ptr,
    )

    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_header),
    )
    checksum = _checksum(pseudo_header + tcp_header)
    return struct.pack(
        "!HHLLHHHH",
        src_port,
        dst_port,
        seq,
        ack_seq,
        offset_res_flags,
        window,
        checksum,
        urg_ptr,
    )


def probe_tcp_syn(host: str, port: int, timeout: float, retries: int, retry_interval: float) -> Tuple[bool, int, str, bool]:
    dst_ip = _resolve_ipv4(host)
    if not dst_ip:
        return False, 0, "resolve failed", False

    attempts = max(1, retries)
    last_error = ""
    best_latency = 0
    for attempt in range(attempts):
        start = time.perf_counter()
        send_sock: Optional[socket.socket] = None
        recv_sock: Optional[socket.socket] = None
        try:
            src_ip = _get_local_ip_for_target(dst_ip)
            src_port = 40000 + (os.getpid() + attempt) % 20000
            seq = int(time.time() * 1000) & 0xFFFFFFFF

            tcp_segment = _build_tcp_syn_segment(src_ip, dst_ip, src_port, port, seq)
            ip_header = _build_ipv4_header(src_ip, dst_ip, 20 + len(tcp_segment), ident=(54321 + attempt) & 0xFFFF)
            packet = ip_header + tcp_segment

            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            recv_sock.settimeout(timeout)

            send_sock.sendto(packet, (dst_ip, 0))
            end_time = time.perf_counter() + timeout

            while time.perf_counter() < end_time:
                remaining = max(0.01, end_time - time.perf_counter())
                recv_sock.settimeout(remaining)
                data, _ = recv_sock.recvfrom(65535)
                if len(data) < 40:
                    continue
                ihl = (data[0] & 0x0F) * 4
                ip_proto = data[9]
                src = socket.inet_ntoa(data[12:16])
                if ip_proto != socket.IPPROTO_TCP or src != dst_ip:
                    continue
                tcp = data[ihl:ihl + 20]
                if len(tcp) < 20:
                    continue
                r_src_port, r_dst_port, _, _, offset_flags, _, _, _ = struct.unpack("!HHLLHHHH", tcp)
                if r_src_port != port or r_dst_port != src_port:
                    continue
                flags = offset_flags & 0x3F
                latency_ms = int((time.perf_counter() - start) * 1000)
                if flags & 0x12 == 0x12:  # SYN+ACK
                    return True, latency_ms, "", True
                if flags & 0x04:  # RST
                    return False, latency_ms, "connection refused", True

            latency_ms = int((time.perf_counter() - start) * 1000)
            last_error = "syn timeout"
            if best_latency == 0 or latency_ms < best_latency:
                best_latency = latency_ms
        except PermissionError:
            return False, 0, "syn requires root/admin; fallback to connect", False
        except OSError as exc:
            if exc.errno in (errno.EPERM, errno.EACCES):
                return False, 0, "syn requires root/admin; fallback to connect", False
            latency_ms = int((time.perf_counter() - start) * 1000)
            if best_latency == 0 or latency_ms < best_latency:
                best_latency = latency_ms
            last_error = str(exc)
        except Exception as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)
            if best_latency == 0 or latency_ms < best_latency:
                best_latency = latency_ms
            last_error = str(exc)
        finally:
            if send_sock is not None:
                send_sock.close()
            if recv_sock is not None:
                recv_sock.close()
        if attempt < attempts - 1 and retry_interval > 0:
            time.sleep(retry_interval)

    return False, best_latency, last_error or "syn timeout", True


def probe_tcp(host: str, port: int, timeout: float, retries: int, retry_interval: float) -> Tuple[bool, int, str]:
    endpoint = _resolve_endpoint(host, port)
    if not endpoint:
        return False, 0, "resolve failed"

    attempts = max(1, retries)
    last_error = ""
    best_latency = 0
    for attempt in range(attempts):
        start = time.perf_counter()
        try:
            with socket.create_connection(endpoint, timeout=timeout):
                latency_ms = int((time.perf_counter() - start) * 1000)
                return True, latency_ms, ""
        except Exception as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)
            if best_latency == 0 or latency_ms < best_latency:
                best_latency = latency_ms
            last_error = str(exc)
            if attempt < attempts - 1 and retry_interval > 0:
                time.sleep(retry_interval)
    return False, best_latency, last_error


UDP_PROBES: Dict[int, bytes] = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
    123: b"\x1b" + b"\x00" * 47,
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\x5b\x5f\x65\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
}


def probe_udp(host: str, port: int, timeout: float, retries: int, retry_interval: float) -> Tuple[UDPStatus, int, str]:
    endpoint = _resolve_endpoint(host, port)
    if not endpoint:
        return "open|filtered", 0, "resolve failed"

    attempts = max(1, retries)
    payload = UDP_PROBES.get(port, b"\x00")
    best_latency = 0
    last_error = ""
    for attempt in range(attempts):
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.connect(endpoint)
            sock.send(payload)
            data = sock.recv(512)
            latency_ms = int((time.perf_counter() - start) * 1000)
            if data:
                return "open", latency_ms, ""
            return "open|filtered", latency_ms, ""
        except socket.timeout:
            latency_ms = int((time.perf_counter() - start) * 1000)
            if best_latency == 0 or latency_ms < best_latency:
                best_latency = latency_ms
            last_error = "udp timeout"
        except ConnectionRefusedError:
            latency_ms = int((time.perf_counter() - start) * 1000)
            return "closed", latency_ms, "connection refused"
        except OSError as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)
            if getattr(exc, "errno", None) == errno.ECONNREFUSED:
                return "closed", latency_ms, str(exc)
            if best_latency == 0 or latency_ms < best_latency:
                best_latency = latency_ms
            last_error = str(exc)
        finally:
            sock.close()

        if attempt < attempts - 1 and retry_interval > 0:
            time.sleep(retry_interval)

    return "open|filtered", best_latency, last_error


def _short_text(data: bytes, max_len: int = 120) -> str:
    text = data[:max_len].decode("latin-1", errors="ignore")
    return " ".join(text.split())


@lru_cache(maxsize=2)
def load_probe_signatures(path: str = "probe_signatures.json") -> List[SignatureRule]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return []

    if not isinstance(raw, list):
        return []

    rules: List[SignatureRule] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        protocol = str(item.get("protocol", "")).strip().lower()
        pattern = str(item.get("pattern", "")).strip()
        if not protocol or not pattern:
            continue
        try:
            rules.append((protocol, re.compile(pattern, re.IGNORECASE)))
        except re.error:
            continue
    return rules


def infer_protocol_from_response(data: bytes) -> str:
    if not data:
        return ""

    text = data.decode("latin-1", errors="ignore")
    lower = text.lower()

    if data.startswith(b"SSH-"):
        return f"ssh:{_short_text(data)}"
    if lower.startswith("http/"):
        return f"http:{_short_text(data)}"
    if lower.startswith("+ok"):
        return f"pop3:{_short_text(data)}"
    if lower.startswith("* ok"):
        return f"imap:{_short_text(data)}"
    if lower.startswith("220"):
        if "smtp" in lower or "esmtp" in lower:
            return f"smtp:{_short_text(data)}"
        if "ftp" in lower:
            return f"ftp:{_short_text(data)}"
        return f"banner:{_short_text(data)}"
    if data.startswith((b"+PONG", b"-NOAUTH", b"-ERR")):
        return f"redis:{_short_text(data)}"
    if data.startswith((b"VERSION", b"STAT", b"ERROR\r\n", b"CLIENT_ERROR", b"SERVER_ERROR")):
        return f"memcached:{_short_text(data)}"
    if data.startswith(b"AMQP"):
        return f"amqp:{_short_text(data)}"
    if data.startswith(b"imok"):
        return f"zookeeper:{_short_text(data)}"
    if len(data) >= 4 and data[0] == 0x20 and data[1] == 0x02:
        return "mqtt:connack"
    if len(data) >= 2 and data[0] == 0x30:
        return f"ldap:{_short_text(data)}"
    if len(data) >= 5 and data[4] in range(8, 12):
        return f"mysql:{_short_text(data)}"
    if data[:1] in (b"S", b"N", b"E", b"R") and len(data) >= 1:
        return f"postgres:{_short_text(data)}"
    if len(data) >= 4 and data[0] == 0x03 and data[1] == 0x00:
        return "rdp:x224"
    if len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03:
        return "tls:server-hello"
    if len(data) >= 3 and data[0] == 0x15 and data[1] == 0x03:
        return "tls:alert"

    # External extensible signature rules.
    for protocol, pattern in load_probe_signatures():
        if pattern.search(text):
            return f"{protocol}:{_short_text(data)}"

    return ""


def _build_service_probes(host: str, port: int) -> List[bytes]:
    http_probe = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii", errors="ignore")
    probes: List[bytes] = []

    # HTTPS/Web ports are high-volume in real scans; keep probes minimal first.
    if port in HTTPS_LIKELY_PORTS:
        probes.append(TLS_CLIENT_HELLO)
    elif port in WEB_LIKELY_PORTS:
        probes.append(http_probe)

    # Port-targeted probes have higher signal than generic cross-protocol payloads.
    if port == 6379:
        probes.append(b"*1\r\n$4\r\nPING\r\n")
    if port == 5432:
        probes.append(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
    if port in (3388, 3389):
        probes.append(bytes.fromhex("030000130ee000000000000100080003000000"))
    if port == 11211:
        probes.append(b"stats\r\n")
    if port == 2181:
        probes.append(b"ruok")
    if port == 5672:
        probes.append(b"AMQP\x00\x00\x09\x01")
    if port == 1883:
        probes.append(b"\x10\x0e\x00\x04MQTT\x04\x02\x00\x03\x00\x02dz")
    if port in (389, 636):
        probes.append(b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00")
    if port == 53:
        probes.append(b"\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")

    # Unknown ports get lightweight generic probes for broad coverage.
    if not probes:
        probes.extend(
            [
                http_probe,
                b"*1\r\n$4\r\nPING\r\n",
                b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
            ]
        )

    # De-duplicate while preserving order and cap payload count per port.
    unique_probes: List[bytes] = []
    seen: Set[bytes] = set()
    for payload in probes:
        if payload in seen:
            continue
        seen.add(payload)
        unique_probes.append(payload)

    return unique_probes[:MAX_ACTIVE_SERVICE_PROBES]


def probe_service(host: str, port: int, timeout: float, budget: float) -> str:
    endpoint = _resolve_endpoint(host, port)
    if not endpoint:
        return ""

    try:
        with socket.create_connection(endpoint, timeout=timeout) as sock:
            started = time.perf_counter()
            deadline = started + max(0.1, budget)

            def _remaining() -> float:
                return max(0.01, deadline - time.perf_counter())

            sock.settimeout(min(_remaining(), min(timeout, 0.25)))

            # 1) 先尝试被动读取 banner，尽量直接根据返回内容识别协议。
            try:
                banner = sock.recv(256)
                identified = infer_protocol_from_response(banner)
                if identified:
                    return identified
            except Exception:
                pass

            # 2) 再做主动探测，根据响应内容识别协议。
            probes = _build_service_probes(host, port)

            for payload in probes:
                if time.perf_counter() >= deadline:
                    break
                try:
                    sock.settimeout(min(_remaining(), min(timeout, 0.2)))
                    sock.sendall(payload)
                    data = sock.recv(256)
                except Exception:
                    continue
                identified = infer_protocol_from_response(data)
                if identified:
                    return identified

            # 3) 无法识别时按端口服务映射兜底，支持 services.json 自定义覆盖。
            mapped = load_service_mapping().get(port, "")
            if mapped:
                return f"{mapped}:open"
    except Exception:
        return ""

    return ""


# 对单个目标按候选协议依次探测，任一命中即返回存活。
def probe_target(
    target: str,
    timeout: float,
    ssl_context: ssl.SSLContext,
    user_agent: Optional[str],
    accept_language: Optional[str],
    referer: Optional[str],
    enable_fingerprint: bool,
    fingerprint_db: str,
    strict_fingerprint: bool,
    denylist: Set[str],
    max_fingerprint_hits: int,
    tcp_timeout: float,
    tcp_retries: int,
    tcp_retry_interval: float,
    use_tcp_syn: bool,
    enable_udp: bool,
    udp_only: bool,
    udp_timeout: float,
    udp_retries: int,
    udp_retry_interval: float,
    enable_service_probe: bool,
    service_probe_budget: float,
    web_enrich: bool,
    web_enrich_timeout: float,
) -> ProbeResult:
    candidates = expand_candidate_urls(target, https_first=_prefer_https_for_target(target))
    last_http_error = ""
    last_tcp_error = ""
    tcp_checked = False
    tcp_alive_any = False
    tcp_latency_ms = 0
    tcp_method = "syn" if use_tcp_syn else "connect"
    udp_checked = False
    udp_status = ""
    udp_latency_ms = 0
    service_probe = ""
    endpoint_tcp_alive: Dict[Tuple[str, int], bool] = {}

    base = ProbeResult(target=target)

    for candidate in candidates:
        host, port = parse_host_port(candidate, "")
        endpoint_key = (host, port)
        mapped_service = load_service_mapping().get(port, "unknown") if port > 0 else "unknown"

        if udp_only:
            if not enable_udp:
                continue
            if not host or port <= 0:
                continue
            udp_checked = True
            state, udp_ms, udp_error = probe_udp(
                host,
                port,
                udp_timeout,
                udp_retries,
                udp_retry_interval,
            )
            udp_status = state
            udp_latency_ms = udp_ms
            return ProbeResult(
                target=target,
                final_url=candidate,
                alive=(state in ("open", "open|filtered")),
                tcp_method=tcp_method,
                tcp_checked=False,
                tcp_alive=False,
                tcp_latency_ms=0,
                udp_checked=True,
                udp_status=state,
                udp_latency_ms=udp_ms,
                service_probe="",
                error=udp_error,
            )

        tcp_alive = False
        if host and port > 0 and endpoint_key not in endpoint_tcp_alive:
            tcp_checked = True
            syn_supported = True
            if use_tcp_syn:
                tcp_alive, tcp_latency_ms_single, tcp_error, syn_supported = probe_tcp_syn(
                    host,
                    port,
                    tcp_timeout,
                    tcp_retries,
                    tcp_retry_interval,
                )
                if not syn_supported:
                    tcp_method = "connect"
                    tcp_alive, tcp_latency_ms_single, tcp_error = probe_tcp(
                        host,
                        port,
                        tcp_timeout,
                        tcp_retries,
                        tcp_retry_interval,
                    )
            else:
                tcp_alive, tcp_latency_ms_single, tcp_error = probe_tcp(
                    host,
                    port,
                    tcp_timeout,
                    tcp_retries,
                    tcp_retry_interval,
                )
            endpoint_tcp_alive[endpoint_key] = tcp_alive
            if tcp_alive:
                tcp_alive_any = True
                if tcp_latency_ms == 0 or tcp_latency_ms_single < tcp_latency_ms:
                    tcp_latency_ms = tcp_latency_ms_single
            else:
                last_tcp_error = tcp_error

            if enable_udp:
                udp_checked = True
                state, udp_ms, udp_error = probe_udp(
                    host,
                    port,
                    udp_timeout,
                    udp_retries,
                    udp_retry_interval,
                )
                udp_status = state
                udp_latency_ms = udp_ms
                if udp_error and not last_tcp_error:
                    last_tcp_error = udp_error

            if enable_service_probe and tcp_alive and host:
                detected = probe_service(host, port, tcp_timeout, service_probe_budget)
                if detected:
                    service_probe = detected
        elif endpoint_key in endpoint_tcp_alive:
            tcp_alive = endpoint_tcp_alive[endpoint_key]

        # 端口不通则不继续尝试该候选协议的 HTTP 请求。
        if not tcp_alive:
            continue

        if not enable_fingerprint:
            if web_enrich and _should_try_http_enrich(candidate, port, mapped_service, service_probe):
                enriched = probe_url(
                    candidate,
                    min(timeout, max(0.1, web_enrich_timeout)),
                    ssl_context,
                    user_agent,
                    accept_language,
                    referer,
                    False,
                    "",
                    True,
                    set(),
                    1,
                )
                if enriched.status > 0:
                    enriched.target = target
                    enriched.tcp_method = tcp_method
                    enriched.tcp_checked = tcp_checked
                    enriched.tcp_alive = tcp_alive_any
                    enriched.tcp_latency_ms = tcp_latency_ms
                    enriched.udp_checked = udp_checked
                    enriched.udp_status = udp_status
                    enriched.udp_latency_ms = udp_latency_ms
                    enriched.service_probe = service_probe
                    enriched.alive = tcp_alive_any
                    return enriched
                if enriched.error:
                    last_http_error = enriched.error
                continue

            return ProbeResult(
                target=target,
                final_url=candidate,
                alive=True,
                tcp_method=tcp_method,
                tcp_checked=tcp_checked,
                tcp_alive=tcp_alive_any,
                tcp_latency_ms=tcp_latency_ms,
                udp_checked=udp_checked,
                udp_status=udp_status,
                udp_latency_ms=udp_latency_ms,
                service_probe=service_probe,
            )

        if not _should_try_http_fingerprint(target, port, mapped_service, service_probe):
            return ProbeResult(
                target=target,
                final_url=candidate,
                alive=True,
                tcp_method=tcp_method,
                tcp_checked=tcp_checked,
                tcp_alive=tcp_alive_any,
                tcp_latency_ms=tcp_latency_ms,
                udp_checked=udp_checked,
                udp_status=udp_status,
                udp_latency_ms=udp_latency_ms,
                service_probe=service_probe,
            )

        result = probe_url(
            candidate,
            timeout,
            ssl_context,
            user_agent,
            accept_language,
            referer,
            enable_fingerprint,
            fingerprint_db,
            strict_fingerprint,
            denylist,
            max_fingerprint_hits,
        )
        if result.alive:
            result.target = target
            result.tcp_method = tcp_method
            result.tcp_checked = tcp_checked
            result.tcp_alive = tcp_alive_any
            result.tcp_latency_ms = tcp_latency_ms
            result.udp_checked = udp_checked
            result.udp_status = udp_status
            result.udp_latency_ms = udp_latency_ms
            result.service_probe = service_probe
            result.alive = tcp_alive_any
            return result
        last_http_error = result.error

    base.tcp_checked = tcp_checked
    base.tcp_method = tcp_method
    base.tcp_alive = tcp_alive_any
    base.tcp_latency_ms = tcp_latency_ms
    base.udp_checked = udp_checked
    base.udp_status = udp_status
    base.udp_latency_ms = udp_latency_ms
    base.service_probe = service_probe
    base.alive = tcp_alive_any
    base.error = last_http_error or last_tcp_error or "connection failed"
    return base
