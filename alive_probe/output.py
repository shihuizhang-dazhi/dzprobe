import os
import sys
import csv
import json
from typing import Iterable, List
from pathlib import Path
import unicodedata
from urllib.parse import urlparse

from .constants import load_service_mapping
from .models import ProbeResult


class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    WHITE = "\033[97m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    DIM = "\033[2m"


SERVICE_STYLE_MAP = {
    "http": Style.BLUE,
    "https": Style.BLUE,
    "http-alt": Style.BLUE,
    "ssh": Style.CYAN,
    "ftp": Style.CYAN,
    "smtp": Style.MAGENTA,
    "imap": Style.MAGENTA,
    "pop3": Style.MAGENTA,
    "dns": Style.YELLOW,
    "redis": Style.RED,
    "mysql": Style.YELLOW,
    "postgres": Style.YELLOW,
    "mongodb": Style.GREEN,
    "rdp": Style.GREEN,
}

SERVER_COLUMN_WIDTH = 26
TARGET_COLUMN_WIDTH = 32


# 判断终端是否支持彩色输出，支持时再应用 ANSI 颜色。
def color_enabled() -> bool:
    if os.getenv("FORCE_COLOR") is not None:
        return True
    if os.getenv("NO_COLOR") is not None:
        return False
    if os.name == "nt":
        return bool(getattr(sys.stdout, "isatty", lambda: False)())
    term = os.getenv("TERM", "")
    return term not in ("", "dumb")


# 给文本包裹颜色样式；不支持颜色时返回原文。
def colorize(text: str, code: str) -> str:
    if not color_enabled():
        return text
    return f"{code}{text}{Style.RESET}"


def colorize_cell(text: str, width: int, code: str) -> str:
    padded = fit_display(text, width)
    return colorize(padded, code)


def style_for_service(service: str) -> str:
    key = (service or "").strip().lower()
    if key in SERVICE_STYLE_MAP:
        return SERVICE_STYLE_MAP[key]
    if "http" in key:
        return Style.BLUE
    if "ssh" in key:
        return Style.CYAN
    if "redis" in key:
        return Style.RED
    if "mysql" in key or "postgres" in key:
        return Style.YELLOW
    if key == "unknown":
        return Style.DIM
    return Style.WHITE


def is_web_service(service: str) -> bool:
    key = (service or "").strip().lower()
    if not key:
        return False
    return ("http" in key) or ("web" in key)


def style_for_status(status: int) -> str:
    if status <= 0:
        return Style.DIM
    if 200 <= status < 400:
        return Style.GREEN
    if 400 <= status < 500:
        return Style.YELLOW
    if 500 <= status < 600:
        return Style.RED
    return Style.WHITE


def display_http_status(status: int, web_row: bool) -> str:
    if not web_row or status <= 0:
        return "-"
    return str(status)


def style_for_latency(latency_ms: int) -> str:
    if latency_ms <= 0:
        return Style.DIM
    if latency_ms < 80:
        return Style.GREEN
    if latency_ms < 300:
        return Style.YELLOW
    return Style.RED


def display_width(text: str) -> int:
    total = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        total += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return total


def fit_display(text: str, width: int) -> str:
    current = 0
    out = []
    for ch in text:
        ch_w = 0 if unicodedata.combining(ch) else (2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
        if current + ch_w > width:
            break
        out.append(ch)
        current += ch_w
    return "".join(out) + " " * max(0, width - current)


def truncate_display(text: str, width: int) -> str:
    value = text or ""
    if display_width(value) <= width:
        return fit_display(value, width)
    if width <= 3:
        return fit_display(value, width)
    target = width - 3
    current = 0
    out = []
    for ch in value:
        ch_w = 0 if unicodedata.combining(ch) else (2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
        if current + ch_w > target:
            break
        out.append(ch)
        current += ch_w
    return fit_display("".join(out) + "...", width)


# 根据协议推断默认端口，用于服务名识别。
def default_port_for_scheme(scheme: str) -> int:
    if scheme == "https":
        return 443
    return 80


# 基于目标和最终 URL 的端口映射常见服务名。
def pick_service_label(target: str, final_url: str) -> str:
    raw = final_url or target
    parsed = urlparse(raw if raw.startswith(("http://", "https://")) else f"http://{raw}")
    if not parsed.hostname:
        return "unknown"
    port = parsed.port or default_port_for_scheme(parsed.scheme or "http")
    return load_service_mapping().get(port, "unknown")


def infer_service_from_probe(service_probe: str) -> str:
    if not service_probe:
        return ""
    value = service_probe.strip().lower()
    if not value:
        return ""
    if ":" in value:
        value = value.split(":", 1)[0]
    # Preserve probe-derived protocol labels when they are simple identifiers.
    if not value:
        return ""
    if all(ch.isalnum() or ch in ("-", "_") for ch in value):
        return value
    return ""


def display_target(target: str, final_url: str) -> str:
    raw = final_url or target
    parsed = urlparse(raw if raw.startswith(("http://", "https://")) else f"http://{raw}")
    if parsed.hostname:
        if parsed.port:
            return f"{parsed.hostname}:{parsed.port}"

        # If URL does not explicitly include port, try keep original target port first.
        target_parsed = urlparse(target if target.startswith(("http://", "https://")) else f"http://{target}")
        if target_parsed.port:
            return f"{parsed.hostname}:{target_parsed.port}"

        return f"{parsed.hostname}:{default_port_for_scheme(parsed.scheme or 'http')}"
    return target


# 将探测结果打印为终端表格（含颜色和状态高亮）。
def print_results(results: Iterable[ProbeResult]) -> None:
    rows = list(results)
    show_udp = any(row.udp_checked for row in rows)
    show_probe = any(bool(row.service_probe) for row in rows)
    show_finger = any(bool(row.fingerprint) for row in rows)
    display_meta = []
    for row in rows:
        inferred = infer_service_from_probe(row.service_probe)
        if inferred:
            service = inferred
        else:
            service = pick_service_label(row.target, row.final_url)
        web_row = is_web_service(service)
        display_meta.append((service, web_row))

    show_status = any(row.status > 0 and meta[1] for row, meta in zip(rows, display_meta))
    show_server = any(bool(row.http_server) for row in rows)

    header_parts = [
        fit_display("目标", TARGET_COLUMN_WIDTH),
        fit_display("服务", 10),
        fit_display("存活", 4),
        fit_display("TCP", 4),
        fit_display("方式", 7),
        fit_display("T延迟", 5),
    ]
    if show_status:
        header_parts.append(fit_display("状态", 5))
    if show_server:
        header_parts.append(fit_display("Server", SERVER_COLUMN_WIDTH))
    if show_udp:
        header_parts.extend([fit_display("UDP", 12), fit_display("U延迟", 5)])
    if show_probe:
        header_parts.append(fit_display("探针证据", 24))
    if show_finger:
        header_parts.append(fit_display("指纹", 16))
    header_parts.append("标题")
    header = " ".join(header_parts)
    print(colorize(header, Style.BOLD + Style.CYAN))
    print(colorize("-" * display_width(header), Style.DIM))
    for result, meta in zip(rows, display_meta):
        host = display_target(result.target, result.final_url)
        service, web_row = meta

        alive_raw = "yes" if result.alive else "no"
        alive = colorize_cell(alive_raw, 4, Style.GREEN if result.alive else Style.RED)

        tcp_raw = "-"
        if result.tcp_checked:
            tcp_raw = "yes" if result.tcp_alive else "no"
        tcp_cell = colorize_cell(tcp_raw, 4, Style.GREEN if tcp_raw == "yes" else (Style.RED if tcp_raw == "no" else Style.DIM))

        tcp_method_raw = result.tcp_method or "-"
        tcp_method_color = Style.BLUE if tcp_method_raw == "syn" else (Style.WHITE if tcp_method_raw == "connect" else Style.DIM)
        tcp_method = colorize_cell(tcp_method_raw, 7, tcp_method_color)

        udp_raw = result.udp_status if result.udp_checked else "-"
        udp_color = Style.DIM
        if udp_raw == "open":
            udp_color = Style.GREEN
        elif udp_raw == "closed":
            udp_color = Style.RED
        elif udp_raw == "open|filtered":
            udp_color = Style.YELLOW
        udp_cell = colorize_cell(udp_raw, 12, udp_color)

        tcp_ms = str(result.tcp_latency_ms) if result.tcp_latency_ms else "-"
        udp_ms = str(result.udp_latency_ms) if result.udp_latency_ms else "-"
        if result.title:
            text = result.title
        elif web_row and result.error:
            text = result.error[:60]
        elif web_row:
            text = "no-title"
        else:
            text = "-"
        host_cell = colorize_cell(truncate_display(host, TARGET_COLUMN_WIDTH), TARGET_COLUMN_WIDTH, Style.CYAN)
        service_cell = colorize_cell(truncate_display(service, 10), 10, style_for_service(service))
        tcp_ms_cell = colorize_cell(tcp_ms, 5, style_for_latency(result.tcp_latency_ms))

        row_parts = [
            host_cell,
            service_cell,
            alive,
            tcp_cell,
            tcp_method,
            tcp_ms_cell,
        ]
        if show_status:
            status_text = display_http_status(result.status, web_row)
            status_code = style_for_status(result.status) if status_text != "-" else Style.DIM
            row_parts.append(colorize_cell(status_text, 5, status_code))
        if show_server:
            row_parts.append(
                colorize_cell(
                    truncate_display(result.http_server or "-", SERVER_COLUMN_WIDTH),
                    SERVER_COLUMN_WIDTH,
                    Style.BLUE,
                )
            )
        if show_udp:
            udp_ms_cell = colorize_cell(udp_ms, 5, style_for_latency(result.udp_latency_ms))
            row_parts.extend([udp_cell, udp_ms_cell])
        if show_probe:
            row_parts.append(colorize_cell(truncate_display(result.service_probe or "-", 24), 24, Style.MAGENTA))
        if show_finger:
            row_parts.append(colorize_cell(truncate_display(result.fingerprint or "-", 16), 16, Style.YELLOW))
        title_code = Style.WHITE if result.title else (Style.RED if web_row and result.error else Style.DIM)
        row_parts.append(colorize_cell(truncate_display(text, 40), 40, title_code))
        print(" ".join(row_parts))


# 打印总计统计信息。
def print_summary(results: Iterable[ProbeResult], shown_total: int = None) -> None:
    rows: List[ProbeResult] = list(results)
    total = len(rows)
    overall_alive = sum(1 for row in rows if row.alive)
    tcp_alive = sum(1 for row in rows if row.tcp_alive)
    udp_open = sum(1 for row in rows if row.udp_status == "open")
    udp_open_filtered = sum(1 for row in rows if row.udp_status == "open|filtered")
    has_udp = any(row.udp_checked for row in rows)
    summary = f"Total: {total}  Alive: {overall_alive}  Dead: {total - overall_alive}  TCP_OK: {tcp_alive}"
    if shown_total is not None and shown_total != total:
        summary += f"  Shown: {shown_total}"
    if has_udp:
        summary += f"  UDP_OPEN: {udp_open}  UDP_O|F: {udp_open_filtered}"
    print(colorize("-" * max(40, display_width(summary)), Style.DIM))
    print(colorize(summary, Style.BOLD))


# 将 ProbeResult 转为可导出的字典行。
def _result_to_row(result: ProbeResult) -> dict:
    service = pick_service_label(result.target, result.final_url)
    if service == "unknown":
        inferred = infer_service_from_probe(result.service_probe)
        if inferred:
            service = inferred
    return {
        "目标": result.target,
        "最终URL": result.final_url,
        "服务": service,
        "综合存活": result.alive,
        "HTTP状态码": result.status,
        "HTTP Server": result.http_server,
        "TCP方式": result.tcp_method,
        "TCP探测": result.tcp_checked,
        "TCP存活": result.tcp_alive,
        "指纹": result.fingerprint,
        "TCP延迟毫秒": result.tcp_latency_ms,
        "UDP探测": result.udp_checked,
        "UDP状态": result.udp_status,
        "UDP延迟毫秒": result.udp_latency_ms,
        "服务探针": result.service_probe,
        "标题": result.title,
        "错误": result.error,
    }


# 自动推断导出格式：按参数或文件后缀决定 csv/json。
def _infer_format(output_path: str, export_format: str) -> str:
    if export_format != "auto":
        return export_format

    suffix = Path(output_path).suffix.lower()
    if suffix == ".json":
        return "json"
    return "csv"


# 导出结果到 CSV 或 JSON，并返回输出路径。
def export_results(results: Iterable[ProbeResult], output_path: str, export_format: str = "auto") -> str:
    fmt = _infer_format(output_path, export_format)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [_result_to_row(result) for result in results]

    if fmt == "json":
        with path.open("w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
        return str(path)

    fieldnames = [
        "目标",
        "最终URL",
        "服务",
        "综合存活",
        "HTTP状态码",
        "HTTP Server",
        "TCP方式",
        "TCP探测",
        "TCP存活",
        "指纹",
        "TCP延迟毫秒",
        "UDP探测",
        "UDP状态",
        "UDP延迟毫秒",
        "服务探针",
        "标题",
        "错误",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return str(path)
