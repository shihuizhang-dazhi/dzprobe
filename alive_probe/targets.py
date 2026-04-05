from typing import Iterator, List, Optional, Set
# 读取单目标或文件目标，并去重后返回探测列表。
def load_targets(single_url: Optional[str], file_path: Optional[str]) -> List[str]:
    targets: List[str] = []
    if single_url:
        targets.append(single_url.strip())
    if file_path:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                value = line.strip()
                if value and not value.startswith("#"):
                    targets.append(value)

    deduped = []
    seen = set()
    for item in targets:
        if item and item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


# 解析端口参数：支持逗号、区间和全端口符号 "-"。
def parse_ports(ports_value: Optional[str]) -> List[int]:
    if not ports_value:
        return []

    value = ports_value.strip()
    if value == "-":
        return list(range(1, 65536))

    ports: List[int] = []
    seen = set()
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue

        if "-" in item:
            pieces = item.split("-", 1)
            if len(pieces) != 2 or not pieces[0].isdigit() or not pieces[1].isdigit():
                raise ValueError(f"invalid port range: {item}")
            start = int(pieces[0])
            end = int(pieces[1])
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"port range out of bounds: {item}")
            for p in range(start, end + 1):
                if p not in seen:
                    seen.add(p)
                    ports.append(p)
            continue

        if not item.isdigit():
            raise ValueError(f"invalid port: {item}")
        port = int(item)
        if port < 1 or port > 65535:
            raise ValueError(f"port out of range: {port}")
        if port not in seen:
            seen.add(port)
            ports.append(port)

    return ports


# 将域名目标按端口展开为 host:port 任务；完整 URL 不强制改端口。
def expand_targets_by_ports(targets: List[str], ports: List[int]) -> List[str]:
    if not ports:
        return targets

    expanded: List[str] = []
    seen = set()
    for target in targets:
        if target.startswith(("http://", "https://")):
            items = [target]
        else:
            items = [f"{target}:{port}" for port in ports]

        for item in items:
            if item not in seen:
                seen.add(item)
                expanded.append(item)
    return expanded


# 流式展开目标，避免一次性构建超大任务列表。
def iter_targets_by_ports(targets: List[str], ports: List[int]) -> Iterator[str]:
    if not ports:
        seen: Set[str] = set()
        for target in targets:
            if target and target not in seen:
                seen.add(target)
                yield target
        return

    seen: Set[str] = set()
    for target in targets:
        if target.startswith(("http://", "https://")):
            if target and target not in seen:
                seen.add(target)
                yield target
            continue

        for port in ports:
            item = f"{target}:{port}"
            if item not in seen:
                seen.add(item)
                yield item
