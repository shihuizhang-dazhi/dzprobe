import re
import json
from pathlib import Path
from functools import lru_cache
from typing import Dict

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

DEFAULT_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8"
DEFAULT_REFERER = "https://www.google.com/"

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

DEFAULT_FINGER_DENYLIST = [
    "p3p_enabled",
    "方卡在线(isite)",
]

COMMON_PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    81: "http-alt",
    88: "kerberos",
    123: "ntp",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "smtp-submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    1883: "mqtt",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker",
    2376: "docker-tls",
    3000: "node",
    3388: "rdp",
    3389: "rdp",
    3306: "mysql",
    3899: "ldap-alt",
    4443: "https-alt",
    5000: "flask",
    5001: "https-alt",
    5431: "postgres-alt",
    5432: "postgres",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6378: "redis-alt",
    6379: "redis",
    6443: "k8s-api",
    7001: "weblogic",
    7002: "weblogic-ssl",
    7199: "cassandra-jmx",
    7474: "neo4j-http",
    7687: "neo4j-bolt",
    7777: "http-alt",
    8000: "http-alt",
    8001: "http-alt",
    8008: "http-alt",
    8081: "http-alt",
    8088: "spark-history",
    8080: "http-alt",
    8090: "http-alt",
    8161: "activemq",
    8444: "https-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "minio",
    9042: "cassandra",
    9090: "prometheus",
    9092: "kafka",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    9418: "git",
    11211: "memcached",
    15672: "rabbitmq",
    27018: "mongodb-alt",
    27017: "mongodb",
    50070: "hdfs-namenode",
    5601: "kibana",
}


@lru_cache(maxsize=2)
def load_service_mapping(path: str = "services.json") -> Dict[int, str]:
    file_path = Path(path)
    if not file_path.exists():
        return COMMON_PORT_SERVICES

    try:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception:
        return COMMON_PORT_SERVICES

    if not isinstance(raw, dict):
        return COMMON_PORT_SERVICES

    mapping: Dict[int, str] = dict(COMMON_PORT_SERVICES)
    for key, value in raw.items():
        try:
            port = int(key)
        except Exception:
            continue
        label = str(value).strip()
        if 1 <= port <= 65535 and label:
            mapping[port] = label
    return mapping
