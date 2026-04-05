from dataclasses import dataclass


@dataclass
class ProbeResult:
    target: str
    final_url: str = ""
    status: int = 0
    latency_ms: int = 0
    http_server: str = ""
    title: str = ""
    fingerprint: str = ""
    alive: bool = False
    tcp_method: str = "connect"
    tcp_checked: bool = False
    tcp_alive: bool = False
    tcp_latency_ms: int = 0
    udp_checked: bool = False
    udp_status: str = ""
    udp_latency_ms: int = 0
    service_probe: str = ""
    error: str = ""
