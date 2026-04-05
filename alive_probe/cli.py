import argparse
from collections import deque
import concurrent.futures
import random
import ssl
import time
from typing import List, Set

try:
    from colorama import just_fix_windows_console
except Exception:
    def just_fix_windows_console() -> None:
        return None

from .models import ProbeResult
from .output import Style, color_enabled, colorize, export_results, print_results, print_summary
from .probing import probe_target
from .targets import iter_targets_by_ports, load_targets, parse_ports
from .constants import DEFAULT_FINGER_DENYLIST


TOOL_NAME = "DZProbe"

SCAN_PROFILES = {
    "stealth": {
        "threads": 40,
        "timeout": 2.2,
        "tcp_timeout": 1.2,
        "tcp_retries": 2,
        "tcp_retry_interval": 0.12,
        "udp_timeout": 1.6,
        "udp_retries": 2,
        "udp_retry_interval": 0.15,
        "service_probe_budget": 0.45,
        "web_enrich_timeout": 0.6,
        "adaptive_pacing": True,
        "submit_jitter_ms": 25.0,
        "adaptive_window": 80,
    },
    "balanced": {
        "threads": 140,
        "timeout": 1.0,
        "tcp_timeout": 0.5,
        "tcp_retries": 1,
        "tcp_retry_interval": 0.03,
        "udp_timeout": 0.8,
        "udp_retries": 1,
        "udp_retry_interval": 0.05,
        "service_probe_budget": 0.35,
        "web_enrich_timeout": 0.5,
        "adaptive_pacing": True,
        "submit_jitter_ms": 8.0,
        "adaptive_window": 80,
    },
    "aggressive": {
        "threads": 320,
        "timeout": 0.6,
        "tcp_timeout": 0.25,
        "tcp_retries": 1,
        "tcp_retry_interval": 0.0,
        "udp_timeout": 0.35,
        "udp_retries": 1,
        "udp_retry_interval": 0.0,
        "service_probe_budget": 0.2,
        "web_enrich_timeout": 0.3,
        "adaptive_pacing": False,
        "submit_jitter_ms": 0.0,
        "adaptive_window": 60,
    },
}


class ZhArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        help_text = super().format_help()
        return (
            help_text.replace("usage:", "用法:")
            .replace("optional arguments:", "可选参数:")
            .replace("options:", "可选参数:")
        )


# 打印启动横幅，仅用于增强命令行体验。
def print_banner() -> None:
    art_lines = [
        "DDDD   ZZZZZ  PPPP   RRRR    OOO   BBBB   EEEEE",
        "D   D     Z   P   P  R   R  O   O  B   B  E    ",
        "D   D    Z    PPPP   RRRR   O   O  BBBB   EEEE ",
        "D   D   Z     P      R  R   O   O  B   B  E    ",
        "DDDD   ZZZZZ  P      R   R   OOO   BBBB   EEEEE",
    ]
    title = "DZPROBE"
    subtitle = "快速 TCP 资产存活探测与指纹识别工具"

    width = max(len(line) for line in art_lines + [title, subtitle])
    top = "+" + "=" * (width + 2) + "+"
    separator = "+" + "-" * (width + 2) + "+"

    def boxed(line: str) -> str:
        return f"| {line.ljust(width)} |"

    if not color_enabled():
        print(top)
        for line in art_lines:
            print(boxed(line))
        print(separator)
        print(boxed(title))
        print(boxed(subtitle))
        print(top)
        return

    print(colorize(top, Style.BOLD + Style.CYAN))
    palette = [Style.CYAN, Style.BLUE, Style.MAGENTA, Style.BLUE, Style.CYAN]
    for index, line in enumerate(art_lines):
        color = palette[index % len(palette)]
        print(colorize(boxed(line), Style.BOLD + color))
    print(colorize(separator, Style.BOLD + Style.WHITE))
    print(colorize(boxed(title), Style.BOLD + Style.WHITE))
    print(colorize(boxed(subtitle), Style.WHITE))
    print(colorize(top, Style.BOLD + Style.CYAN))


# 构建命令行参数解析器，集中定义所有可用参数。
def build_parser() -> argparse.ArgumentParser:
    parser = ZhArgumentParser(
        prog=TOOL_NAME,
        description="快速 TCP 资产存活探测与指纹识别工具",
        epilog=(
            "使用示例:\n"
            "  DZProbe -u example.com\n"
            "  DZProbe -f targets.txt -p 80,443,8080\n"
            "  DZProbe -f targets.txt -p 1-1024 -t 50 --timeout 5\n"
            "  DZProbe -f targets.txt -p 1-1024 --tcp-syn\n"
            "  DZProbe -f targets.txt -p 53,161 --udp\n"
            "  DZProbe -f targets.txt --finger --finger-db finger.json\n"
            "  DZProbe -f targets.txt --only-alive -o output.csv"
        ),
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-h", "--help", action="help", help="显示帮助信息并退出")
    parser.add_argument("-u", "--url", help="单个待探测域名或 URL")
    parser.add_argument("-f", "--file", help="目标文件路径，每行一个目标")
    parser.add_argument(
        "-p",
        "--ports",
        help="端口范围：80,443 或 1-1024 或 -（全部端口）；带协议的完整 URL 将忽略此参数",
    )
    parser.add_argument("-t", "--threads", type=int, default=100, help="并发工作线程数")
    parser.add_argument(
        "--scan-profile",
        choices=["custom", "stealth", "balanced", "aggressive"],
        default="custom",
        help="扫描参数预设（custom=使用手动参数，stealth/balanced/aggressive=自动套用）",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="请求超时时间（秒）")
    parser.add_argument(
        "--adaptive-pacing",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="根据超时比例动态调节在途任务（默认开启，可用 --no-adaptive-pacing 关闭）",
    )
    parser.add_argument(
        "--submit-jitter-ms",
        type=float,
        default=0.0,
        help="任务提交随机抖动上限（毫秒），用于降低节奏特征（默认 0）",
    )
    parser.add_argument(
        "--adaptive-window",
        type=int,
        default=80,
        help="自适应节奏统计窗口大小（默认 80）",
    )
    parser.add_argument("--tcp-syn", action="store_true", help="使用 TCP SYN 探测（需 root 权限，不满足时回退 connect）")
    parser.add_argument("--tcp-timeout", type=float, default=None, help="TCP 探测超时时间（秒），默认沿用 --timeout")
    parser.add_argument("--tcp-retries", type=int, default=1, help="TCP 连接重试次数（默认 1）")
    parser.add_argument("--tcp-retry-interval", type=float, default=0.0, help="TCP 重试间隔（秒）")
    parser.add_argument("--udp", action="store_true", help="开启 UDP 探测（结果为 open/open|filtered/closed）")
    parser.add_argument("--udp-only", action="store_true", help="仅进行 UDP 探测，不执行 TCP 探测")
    parser.add_argument("--udp-timeout", type=float, default=None, help="UDP 探测超时时间（秒），默认沿用 --timeout")
    parser.add_argument("--udp-retries", type=int, default=1, help="UDP 重试次数（默认 1）")
    parser.add_argument("--udp-retry-interval", type=float, default=0.0, help="UDP 重试间隔（秒）")
    parser.add_argument(
        "--service-probe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="对开放 TCP 端口尝试服务/版本探测（默认开启，可用 --no-service-probe 关闭）",
    )
    parser.add_argument(
        "--service-probe-budget",
        type=float,
        default=0.8,
        help="单端口服务探测总耗时预算（秒，默认 0.8）",
    )
    parser.add_argument(
        "--web-enrich",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="对疑似 Web 服务补充抓取状态码/标题/Server（默认开启，可用 --no-web-enrich 关闭）",
    )
    parser.add_argument(
        "--web-enrich-timeout",
        type=float,
        default=0.8,
        help="Web 富化请求超时（秒，默认 0.8）",
    )
    parser.add_argument(
        "--finger",
        "--fingerprint",
        dest="fingerprint",
        action="store_true",
        help="开启指纹识别",
    )
    parser.add_argument(
        "--finger-strict",
        dest="finger_strict",
        action="store_true",
        default=True,
        help="严格指纹匹配（默认开启）",
    )
    parser.add_argument("--finger-loose", dest="finger_strict", action="store_false", help="关闭严格指纹匹配")
    parser.add_argument(
        "--finger-deny",
        default=",".join(DEFAULT_FINGER_DENYLIST),
        help="忽略指纹名（逗号分隔，默认已内置常见误报）",
    )
    parser.add_argument("--max-finger-hits", type=int, default=3, help="单目标最多输出指纹数量")
    parser.add_argument(
        "--finger-db",
        default="finger.json",
        help="外部指纹库路径（默认：finger.json，仅在 --finger/--fingerprint 时生效）",
    )
    parser.add_argument("--user-agent", help="设置固定 User-Agent；默认从内置池中随机选择")
    parser.add_argument(
        "--accept-language",
        default=None,
        help="自定义 Accept-Language 请求头，例如 zh-CN,zh;q=0.9,en;q=0.8",
    )
    parser.add_argument(
        "--referer",
        default=None,
        help="自定义 Referer 请求头；传空字符串可禁用 Referer",
    )
    parser.add_argument("-o", "--output", help="导出文件路径，例如 result.csv 或 result.json")
    parser.add_argument(
        "--only-alive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="仅展示/导出存活结果（默认开启，可用 --no-only-alive 显示全部）",
    )
    parser.add_argument(
        "--format",
        choices=["auto", "csv", "json"],
        default="auto",
        help="导出格式（默认：根据文件扩展名自动判断）",
    )
    return parser


def apply_scan_profile(args: argparse.Namespace) -> argparse.Namespace:
    profile = getattr(args, "scan_profile", "custom")
    if profile == "custom":
        return args

    preset = SCAN_PROFILES[profile]
    for key, value in preset.items():
        setattr(args, key, value)
    return args


def _is_timeout_text(error_text: str) -> bool:
    value = (error_text or "").lower()
    timeout_markers = ["timeout", "timed out", "time-out", "syn timeout", "udp timeout"]
    return any(marker in value for marker in timeout_markers)


def _adaptive_inflight_limit(base_limit: int, min_limit: int, max_limit: int, timeout_ratio: float) -> int:
    if timeout_ratio >= 0.65:
        return max(min_limit, int(base_limit * 0.5))
    if timeout_ratio >= 0.45:
        return max(min_limit, int(base_limit * 0.7))
    if timeout_ratio <= 0.15:
        return min(max_limit, int(base_limit * 1.2))
    return base_limit


# 主调度流程：读取目标、并发探测、收集并排序结果。
def run_probe(args: argparse.Namespace) -> List[ProbeResult]:
    targets = load_targets(args.url, args.file)
    if not targets:
        raise ValueError("请通过 -u 或 -f 提供待探测目标")

    ports = parse_ports(args.ports)

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    tcp_timeout = args.tcp_timeout if args.tcp_timeout is not None else args.timeout
    udp_timeout = args.udp_timeout if args.udp_timeout is not None else args.timeout
    denylist = {item.strip().lower() for item in args.finger_deny.split(",") if item.strip()}
    max_finger_hits = max(1, args.max_finger_hits)
    tcp_retries = max(1, args.tcp_retries)
    udp_retries = max(1, args.udp_retries)

    results: List[ProbeResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.threads)) as executor:
        max_workers = max(1, args.threads)
        base_in_flight_limit = max_workers * 2
        min_in_flight_limit = max(2, max_workers)
        max_in_flight_limit = max(base_in_flight_limit, max_workers * 4)
        in_flight_limit = base_in_flight_limit
        pending: Set[concurrent.futures.Future] = set()
        timeout_window = deque(maxlen=max(20, args.adaptive_window))
        timeout_ratio = 0.0

        def apply_pacing_jitter() -> None:
            jitter_ms = max(0.0, args.submit_jitter_ms)
            if not args.adaptive_pacing and jitter_ms <= 0:
                return
            dynamic_ms = jitter_ms
            if args.adaptive_pacing and timeout_ratio > 0.45:
                dynamic_ms = max(dynamic_ms, 15.0) * (1.4 if timeout_ratio > 0.65 else 1.15)
            if dynamic_ms > 0:
                time.sleep(random.uniform(0.0, min(dynamic_ms / 1000.0, 0.25)))

        def submit_probe(target: str) -> None:
            apply_pacing_jitter()
            pending.add(
                executor.submit(
                    probe_target,
                    target,
                    args.timeout,
                    ssl_context,
                    args.user_agent,
                    args.accept_language,
                    args.referer,
                    args.fingerprint,
                    args.finger_db,
                    args.finger_strict,
                    denylist,
                    max_finger_hits,
                    tcp_timeout,
                    tcp_retries,
                    args.tcp_retry_interval,
                    args.tcp_syn,
                    args.udp,
                    args.udp_only,
                    udp_timeout,
                    udp_retries,
                    args.udp_retry_interval,
                    args.service_probe,
                    max(0.1, args.service_probe_budget),
                    args.web_enrich,
                    max(0.1, args.web_enrich_timeout),
                )
            )

        def consume_done(done: Set[concurrent.futures.Future]) -> None:
            nonlocal timeout_ratio, in_flight_limit
            for future in done:
                result = future.result()
                results.append(result)
                timeout_window.append(1 if _is_timeout_text(result.error) else 0)

            if args.adaptive_pacing and len(timeout_window) >= 10:
                timeout_ratio = sum(timeout_window) / len(timeout_window)
                in_flight_limit = _adaptive_inflight_limit(
                    base_in_flight_limit,
                    min_in_flight_limit,
                    max_in_flight_limit,
                    timeout_ratio,
                )

        for target in iter_targets_by_ports(targets, ports):
            submit_probe(target)
            if len(pending) >= in_flight_limit:
                done, pending = concurrent.futures.wait(
                    pending,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                consume_done(done)

        while pending:
            done, pending = concurrent.futures.wait(
                pending,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            consume_done(done)

    results.sort(key=lambda item: item.target)
    if args.only_alive:
        results = [item for item in results if item.alive]
    return results


# 程序入口：解析参数、执行探测、展示结果并可选导出。
def main() -> None:
    just_fix_windows_console()
    parser = build_parser()
    args = parser.parse_args()
    args = apply_scan_profile(args)

    print_banner()

    try:
        results = run_probe(args)
    except ValueError as exc:
        parser.error(str(exc))
        return

    print_results(results)
    print_summary(results)

    if args.output:
        output_path = export_results(results, args.output, args.format)
        print(colorize(f"结果已导出: {output_path}", Style.BOLD + Style.GREEN))


if __name__ == "__main__":
    main()
