import os
import sys
import csv
import json
import time
import queue
import signal
import socket
import random
import struct
import hashlib
import logging
import threading
import argparse
from collections import deque, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

_original_path_exists = Path.exists

def _safe_path_exists(self, *a, **kw):
    try:
        return _original_path_exists(self, *a, **kw)
    except (PermissionError, OSError):
        return False

Path.exists = _safe_path_exists

import joblib
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from scapy.all import (
    AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR,
    Raw, get_working_ifaces, conf, wrpcap, Ether
)
from sklearn.preprocessing import StandardScaler

Path.exists = _original_path_exists

# =========================================================
# ZENIHT AI NETWORK ANALYZER V15
# Autoencoder avanzado + profiling de host + auto-blacklist
# + puertos sospechosos + alertas de escritorio + ARP spoof
# + MAC vendor + fingerprinting OS + identificacion de dispositivos
# + geographic IP + clasificacion de trafico + salud de red
# + navegacion entre redes + descubrimiento + topologia
# + modelo mejorado con attention + entrenamiento adaptativo
# =========================================================

VERSION = "15.0.0"

BASE_DIR = Path(__file__).parent
MODEL_PATH = BASE_DIR / "zeniht_ai_model.pth"
SCALER_PATH = BASE_DIR / "zeniht_ai_scaler.pkl"
THRESHOLD_PATH = BASE_DIR / "zeniht_ai_threshold.npy"
ALERT_LOG_PATH = BASE_DIR / "zeniht_ai_alerts.log"
EVENTS_CSV_PATH = BASE_DIR / "zeniht_ai_events.csv"
FLOWS_CSV_PATH = BASE_DIR / "zeniht_ai_flows.csv"
DNS_CSV_PATH = BASE_DIR / "zeniht_ai_dns.csv"
BLACKLIST_PATH = BASE_DIR / "zeniht_ai_blacklist.json"
HOST_PROFILES_PATH = BASE_DIR / "zeniht_host_profiles.json"
CONFIG_PATH = BASE_DIR / "zeniht_config.json"
PCAP_DIR = BASE_DIR / "pcap_captures"
REPORT_DIR = BASE_DIR / "reports"

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

SEQ_LEN = 24
FEATURE_DIM = 16

INITIAL_WARMUP = 150
BUFFER_MAX = 15000
NORMAL_BUFFER_MAX = 10000
QUEUE_MAX = 10000

TRAIN_INTERVAL_SEC = 3.0
INFER_INTERVAL_SEC = 0.08
SUMMARY_INTERVAL_SEC = 15.0
DASHBOARD_INTERVAL_SEC = 2.0
FLOW_TIMEOUT_SEC = 300.0

INITIAL_EPOCHS = 35
INCREMENTAL_EPOCHS = 2
LR = 0.0008
GRAD_CLIP = 1.0

ALERT_COOLDOWN_SEC = 0.5
MIN_NORMAL_FOR_UPDATE = 200
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW_SEC = 30.0
DDOS_PACKET_THRESHOLD = 200
DDOS_WINDOW_SEC = 3.0
DNS_TUNNEL_LENGTH = 40
DNS_QUERY_RATE_THRESHOLD = 60
DNS_QUERY_RATE_WINDOW = 20.0
AUTO_BLACKLIST_THRESHOLD = 10
ARP_SPOOF_THRESHOLD = 3
TCP_SYN_FLOOD_THRESHOLD = 50
ICMP_FLOOD_THRESHOLD = 100
BRUTE_FORCE_THRESHOLD = 20

WEBHOOK_URL = os.environ.get("ZENIHT_WEBHOOK_URL", "")
WEBHOOK_COOLDOWN_SEC = 15.0

LAB_MODE = True
LAB_INTERVAL_SEC = 6.0

DESKTOP_ALERTS = True

SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 6667, 7777, 8888, 9999,
    31337, 12345, 54321, 1234, 4321,
    445, 135, 137, 138, 139,
    5900, 5901, 5902,
    8080, 8443, 9090,
    6660, 6661, 6662, 6663, 6664, 6665, 6668, 6669,
    1080, 3128, 8000, 8888,
    23, 2323,
    27015, 27016, 27017, 27018, 27019, 28017,
}

C2_DOMAINS = {
    "pastebin.com", "hastebin.com", "rentry.co",
    "ngrok.io", "serveo.net", "localtunnel.me",
    "requestbin.com", "webhook.site", "pipedream.net",
}

# ─── V13: MAC VENDOR DATABASE ──────────────────────────────
MAC_VENDORS = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:15:5D": "Hyper-V",
    "00:16:3E": "Xen",
    "00:1D:D8": "Dell",
    "00:14:22": "Dell",
    "00:1E:67": "Intel",
    "00:1B:21": "Intel",
    "00:1A:A0": "Dell",
    "00:22:19": "Apple",
    "00:25:00": "Apple",
    "3C:22:FB": "Apple",
    "A4:83:E7": "Apple",
    "F0:18:98": "Apple",
    "00:1A:2B": "Cisco",
    "00:1B:0D": "Cisco",
    "00:26:0B": "Cisco",
    "64:F6:9D": "Cisco",
    "B8:BE:BF": "Cisco",
    "00:1E:49": "Cisco",
    "00:24:D7": "TP-Link",
    "14:CC:20": "TP-Link",
    "50:C7:BF": "TP-Link",
    "60:32:B1": "TP-Link",
    "18:A6:F7": "TP-Link",
    "00:1D:D8": "Dell",
    "00:14:22": "Dell",
    "F8:BC:12": "Dell",
    "D4:AE:52": "Dell",
    "18:66:DA": "Dell",
    "00:24:E8": "Dell",
    "00:08:74": "Dell",
    "00:C0:4F": "Dell",
    "00:06:5B": "Dell",
    "00:12:79": "Dell",
    "00:15:C5": "Dell",
    "00:19:B9": "Dell",
    "00:21:9B": "Dell",
    "00:26:B9": "Dell",
    "34:17:EB": "Dell",
    "B0:83:FE": "Dell",
    "D8:9B:3B": "Dell",
    "EC:F4:BB": "Dell",
    "F8:DB:88": "Dell",
    "18:A9:9B": "Hewlett-Packard",
    "00:17:A4": "Hewlett-Packard",
    "00:1B:78": "Hewlett-Packard",
    "00:1E:0B": "Hewlett-Packard",
    "00:21:5A": "Hewlett-Packard",
    "00:23:7D": "Hewlett-Packard",
    "00:25:B3": "Hewlett-Packard",
    "28:92:4A": "Hewlett-Packard",
    "30:E1:71": "Hewlett-Packard",
    "40:B0:34": "Hewlett-Packard",
    "68:B5:99": "Hewlett-Packard",
    "70:10:6F": "Hewlett-Packard",
    "8C:3B:AD": "Hewlett-Packard",
    "94:57:A5": "Hewlett-Packard",
    "98:E7:F4": "Hewlett-Packard",
    "A0:1D:48": "Hewlett-Packard",
    "B4:39:D6": "Hewlett-Packard",
    "C8:CB:B8": "Hewlett-Packard",
    "D4:C9:EF": "Hewlett-Packard",
    "E8:F7:24": "Hewlett-Packard",
    "F4:39:09": "Hewlett-Packard",
    "FC:15:B4": "Hewlett-Packard",
    "00:1A:2B": "Cisco",
    "00:1B:0D": "Cisco",
    "00:26:0B": "Cisco",
    "64:F6:9D": "Cisco",
    "B8:BE:BF": "Cisco",
    "00:1E:49": "Cisco",
    "00:24:D7": "TP-Link",
    "14:CC:20": "TP-Link",
    "50:C7:BF": "TP-Link",
    "60:32:B1": "TP-Link",
    "18:A6:F7": "TP-Link",
    "00:04:5A": "Linksys",
    "00:1A:70": "Linksys",
    "00:1C:10": "Linksys",
    "00:21:29": "Linksys",
    "00:23:69": "Linksys",
    "00:25:53": "Linksys",
    "20:AA:4B": "Linksys",
    "30:23:03": "Linksys",
    "48:F8:B3": "Linksys",
    "58:EF:68": "Linksys",
    "68:7F:74": "Linksys",
    "84:1B:5E": "Linksys",
    "94:10:3E": "Linksys",
    "A0:04:60": "Linksys",
    "B0:26:80": "Linksys",
    "C0:56:27": "Linksys",
    "C8:3A:35": "Linksys",
    "D4:4B:68": "Linksys",
    "E0:05:C5": "Linksys",
    "EC:1A:59": "Linksys",
    "F0:9F:C2": "Linksys",
    "F4:42:8F": "Linksys",
    "FC:55:DC": "Linksys",
    "00:04:5A": "Linksys",
    "00:1A:70": "Linksys",
    "00:1C:10": "Linksys",
    "00:21:29": "Linksys",
    "00:23:69": "Linksys",
    "00:25:53": "Linksys",
    "20:AA:4B": "Linksys",
    "30:23:03": "Linksys",
    "48:F8:B3": "Linksys",
    "58:EF:68": "Linksys",
    "68:7F:74": "Linksys",
    "84:1B:5E": "Linksys",
    "94:10:3E": "Linksys",
    "A0:04:60": "Linksys",
    "B0:26:80": "Linksys",
    "C0:56:27": "Linksys",
    "C8:3A:35": "Linksys",
    "D4:4B:68": "Linksys",
    "E0:05:C5": "Linksys",
    "EC:1A:59": "Linksys",
    "F0:9F:C2": "Linksys",
    "F4:42:8F": "Linksys",
    "FC:55:DC": "Linksys",
    "00:1A:A0": "Intel",
    "00:1B:21": "Intel",
    "00:1E:67": "Intel",
    "00:22:FB": "Intel",
    "00:24:D6": "Intel",
    "00:26:C6": "Intel",
    "3C:97:0E": "Intel",
    "40:A6:D9": "Intel",
    "44:85:00": "Intel",
    "48:51:B7": "Intel",
    "5C:51:4F": "Intel",
    "68:05:CA": "Intel",
    "6C:88:14": "Intel",
    "78:2B:46": "Intel",
    "80:86:F2": "Intel",
    "84:3A:4B": "Intel",
    "88:70:8C": "Intel",
    "8C:EC:4B": "Intel",
    "94:65:9C": "Intel",
    "98:FA:9B": "Intel",
    "A0:36:9F": "Intel",
    "A4:4C:C8": "Intel",
    "A8:60:B6": "Intel",
    "AC:67:5D": "Intel",
    "B4:96:91": "Intel",
    "B8:08:CF": "Intel",
    "BC:77:37": "Intel",
    "C4:00:AD": "Intel",
    "C8:5B:76": "Intel",
    "CC:3D:82": "Intel",
    "D4:3D:7E": "Intel",
    "D8:FC:93": "Intel",
    "DC:53:60": "Intel",
    "E0:94:04": "Intel",
    "E4:7E:66": "Intel",
    "E8:B1:FC": "Intel",
    "EC:08:6B": "Intel",
    "F0:72:EA": "Intel",
    "F4:8C:50": "Intel",
    "F8:63:3F": "Intel",
    "FC:44:82": "Intel",
}

# ─── V13: OS FINGERPRINTING (TTL-based) ───────────────────
OS_FINGERPRINTS = {
    (64, 64): {"os": "Linux/macOS", "confidence": 0.9},
    (128, 128): {"os": "Windows", "confidence": 0.9},
    (255, 255): {"os": "Solaris/Network Device", "confidence": 0.7},
    (64, 63): {"os": "Linux (1 hop)", "confidence": 0.85},
    (64, 62): {"os": "Linux (2 hops)", "confidence": 0.8},
    (64, 61): {"os": "Linux (3 hops)", "confidence": 0.75},
    (128, 127): {"os": "Windows (1 hop)", "confidence": 0.85},
    (128, 126): {"os": "Windows (2 hops)", "confidence": 0.8},
    (128, 125): {"os": "Windows (3 hops)", "confidence": 0.75},
    (255, 254): {"os": "Solaris/Router (1 hop)", "confidence": 0.7},
    (255, 253): {"os": "Solaris/Router (2 hops)", "confidence": 0.65},
}

# ─── V13: DEVICE TYPE IDENTIFICATION ──────────────────────
DEVICE_TYPES = {
    "web_server": [80, 443, 8080, 8443, 8000, 3000],
    "mail_server": [25, 110, 143, 465, 587, 993, 995],
    "file_server": [20, 21, 445, 139, 548, 2049],
    "dns_server": [53],
    "database_server": [3306, 5432, 1433, 27017, 6379, 9042],
    "remote_access": [22, 23, 3389, 5900, 5901, 5902],
    "gaming": [27015, 27016, 27017, 27018, 27019, 28017, 3478, 3479],
    "streaming": [554, 8554, 1935, 4004, 4005],
    "iot_device": [1883, 5683, 8883, 9001, 9002],
    "printer": [631, 9100, 515, 631],
    "camera": [554, 80, 8080, 37777],
    "router": [23, 80, 443, 161, 162],
    "vpn": [500, 1194, 1723, 4500],
    "proxy": [8080, 3128, 1080, 8888],
    "monitoring": [9090, 9100, 3000, 5601, 9200],
}

# ─── V13: KNOWN PORTS/SERVICES ────────────────────────────
KNOWN_PORTS_SERVICE = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 135: "MSRPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 515: "LPD", 554: "RTSP",
    587: "SMTP-Submission", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-Monitor", 1521: "Oracle",
    1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL", 3000: "Dev-Server",
    3128: "Squid", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5601: "Kibana", 5683: "CoAP", 5900: "VNC", 5901: "VNC-1",
    5902: "VNC-2", 6379: "Redis", 6443: "Kubernetes-API",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8883: "MQTTS",
    8888: "HTTP-Alt", 9042: "Cassandra", 9090: "Prometheus",
    9100: "Printer", 9200: "Elasticsearch", 9418: "Git",
    1080: "SOCKS", 1194: "OpenVPN", 1935: "RTMP",
    27015: "Game-Query", 27016: "Game-Query", 27017: "MongoDB",
    28017: "MongoDB-Web", 3478: "STUN", 3479: "STUN",
    500: "IKE", 4500: "NAT-T",
}

# ─── V13: GEOGRAPHIC IP RANGES (simplified) ───────────────
GEOIP_RANGES = {
    "192.168.0.0/16": {"region": "Private", "country": "Local Network"},
    "10.0.0.0/8": {"region": "Private", "country": "Local Network"},
    "172.16.0.0/12": {"region": "Private", "country": "Local Network"},
    "127.0.0.0/8": {"region": "Loopback", "country": "Localhost"},
    "8.8.8.8": {"region": "North America", "country": "USA", "org": "Google DNS"},
    "8.8.4.4": {"region": "North America", "country": "USA", "org": "Google DNS"},
    "1.1.1.1": {"region": "Oceania", "country": "Australia", "org": "Cloudflare DNS"},
    "1.0.0.1": {"region": "Oceania", "country": "Australia", "org": "Cloudflare DNS"},
    "208.67.222.222": {"region": "North America", "country": "USA", "org": "OpenDNS"},
    "208.67.220.220": {"region": "North America", "country": "USA", "org": "OpenDNS"},
}

# ─── V13: TRAFFIC PROFILES ────────────────────────────────
TRAFFIC_PROFILES = {
    "web_browsing": {"ports": {80, 443, 8080, 8443}, "protocols": {"TCP"}, "typical_size": (64, 1500)},
    "email": {"ports": {25, 110, 143, 465, 587, 993, 995}, "protocols": {"TCP"}, "typical_size": (64, 10000)},
    "file_transfer": {"ports": {20, 21, 445, 139}, "protocols": {"TCP"}, "typical_size": (64, 65535)},
    "dns": {"ports": {53}, "protocols": {"UDP", "TCP"}, "typical_size": (64, 512)},
    "streaming": {"ports": {554, 8554, 1935}, "protocols": {"TCP", "UDP"}, "typical_size": (1000, 1500)},
    "gaming": {"ports": {27015, 27016, 27017, 3478, 3479}, "protocols": {"UDP", "TCP"}, "typical_size": (64, 1200)},
    "remote_access": {"ports": {22, 23, 3389, 5900}, "protocols": {"TCP"}, "typical_size": (64, 1500)},
    "vpn": {"ports": {500, 1194, 1723, 4500}, "protocols": {"UDP", "TCP"}, "typical_size": (64, 1500)},
    "iot": {"ports": {1883, 5683, 8883}, "protocols": {"TCP", "UDP"}, "typical_size": (64, 256)},
    "database": {"ports": {3306, 5432, 1433, 27017, 6379}, "protocols": {"TCP"}, "typical_size": (64, 65535)},
    "monitoring": {"ports": {9090, 9100, 5601, 9200}, "protocols": {"TCP"}, "typical_size": (64, 1500)},
}

# ─── V13: DEVICE INVENTORY ────────────────────────────────
INVENTORY_PATH = BASE_DIR / "zeniht_device_inventory.json"


# ─── V14: NETWORK NAVIGATION ──────────────────────────────
NETWORK_DISCOVERY_PATH = BASE_DIR / "zeniht_network_discovery.json"
TOPOLOGY_PATH = BASE_DIR / "zeniht_topology.json"

SCAN_TIMEOUT = 2.0
MAX_CONCURRENT_SCANS = 10
SCAN_COOLDOWN_SEC = 5.0
TRACE_HOP_LIMIT = 15
DISCOVERY_INTERVAL_SEC = 30.0
ACTIVE_SCAN_INTERVAL_SEC = 60.0

# Known private network ranges
PRIVATE_RANGES = [
    (0, "0.0.0.0", "255.255.255.255", "Unspecified"),
    (10, "10.0.0.0", "10.255.255.255", "Class A Private"),
    (127, "127.0.0.0", "127.255.255.255", "Loopback"),
    (172, "172.16.0.0", "172.31.255.255", "Class B Private"),
    (192, "192.168.0.0", "192.168.255.255", "Class C Private"),
]

# Scan types
SCAN_TYPES = {
    "ping": {"desc": "ICMP Echo Request", "risk": "LOW", "stealth": True},
    "tcp_syn": {"desc": "TCP SYN Scan", "risk": "MEDIUM", "stealth": True},
    "tcp_ack": {"desc": "TCP ACK Scan", "risk": "MEDIUM", "stealth": False},
    "udp": {"desc": "UDP Scan", "risk": "MEDIUM", "stealth": True},
    "trace": {"desc": "Traceroute", "risk": "LOW", "stealth": True},
    "full": {"desc": "Full Connect Scan", "risk": "HIGH", "stealth": False},
}

# Common ports to scan
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 
              1433, 1521, 3306, 3389, 5432, 5900, 5901, 8080, 8443, 8888, 27017]

# ─── TU RED ─────────────────────────────────────────────
MY_IP = "192.168.1.40"
MY_GATEWAY = "192.168.1.1"
MY_SUBNET = "192.168.1.0/24"
MY_SUBNET_MASK = "255.255.255.0"
MY_NETWORK_CLASS = "Class C Private"
MY_INTERFACE = "Wi-Fi"

# ─── GLOBALS ─────────────────────────────────────────────
packet_queue = queue.Queue(maxsize=QUEUE_MAX)
all_features = deque(maxlen=BUFFER_MAX)
normal_features = deque(maxlen=NORMAL_BUFFER_MAX)
recent_timestamps = deque(maxlen=800)
recent_sizes = deque(maxlen=800)
recent_packet_objs = deque(maxlen=200)

scaler = StandardScaler()
model = None
optimizer = None
loss_fn = nn.MSELoss()

trained = False
threshold = None
dynamic_threshold = None
last_packet_time = None
packet_count = 0
last_scored_packet_count = 0
last_alert_time = 0.0
last_webhook_time = 0.0
anomaly_count_total = 0
critical_count_total = 0
blocked_count = 0
start_time = time.time()

lock = threading.Lock()
sniffers = []
last_packet_obj = None
shutdown_event = threading.Event()

host_stats = defaultdict(lambda: {
    "packets": 0, "bytes": 0, "anomalies": 0, "critical": 0,
    "last_err": 0.0, "last_seen": 0.0, "iface": "unknown",
    "ports_accessed": set(), "protocols": set(),
    "first_seen": 0.0, "tcp_flags": defaultdict(int),
    "syn_count": 0, "rst_count": 0, "fin_count": 0,
    "avg_pkt_size": 0.0, "unique_ports": set(),
    "dns_queries": 0, "icmp_count": 0,
    "consecutive_anomalies": 0, "auto_blocked": False,
})

iface_stats = defaultdict(lambda: {
    "packets": 0, "bytes": 0, "anomalies": 0,
    "bps": 0.0, "pps": 0.0,
})
protocol_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
port_stats = defaultdict(lambda: {"packets": 0, "anomalies": 0, "hosts": set()})

active_flows = {}
flow_history = deque(maxlen=5000)
port_scan_tracker = defaultdict(lambda: {"ports": set(), "timestamps": deque(maxlen=200)})
ddos_tracker = defaultdict(lambda: {"timestamps": deque(maxlen=1000), "bytes": deque(maxlen=1000)})
dns_tracker = defaultdict(lambda: {"queries": deque(maxlen=500), "lengths": deque(maxlen=200)})
blacklisted_hosts = set()
host_profiles = {}
arp_table = defaultdict(set)
syn_tracker = defaultdict(lambda: {"timestamps": deque(maxlen=200)})
icmp_tracker = defaultdict(lambda: {"timestamps": deque(maxlen=200)})
brute_force_tracker = defaultdict(lambda: {"attempts": deque(maxlen=200), "target_ports": set()})

# ─── LOGGER ──────────────────────────────────────────────
logger = logging.getLogger("zeniht")
logger.setLevel(logging.DEBUG)
_log_fmt = logging.Formatter("[%(asctime)s] %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
_log_sh = logging.StreamHandler()
_log_sh.setLevel(logging.INFO)
_log_sh.setFormatter(_log_fmt)
logger.addHandler(_log_sh)


DEFAULT_CONFIG = {
    "seq_len": SEQ_LEN, "feature_dim": FEATURE_DIM,
    "initial_warmup": INITIAL_WARMUP, "buffer_max": BUFFER_MAX,
    "normal_buffer_max": NORMAL_BUFFER_MAX,
    "train_interval": TRAIN_INTERVAL_SEC, "infer_interval": INFER_INTERVAL_SEC,
    "summary_interval": SUMMARY_INTERVAL_SEC, "dashboard_interval": DASHBOARD_INTERVAL_SEC,
    "flow_timeout": FLOW_TIMEOUT_SEC,
    "initial_epochs": INITIAL_EPOCHS, "incremental_epochs": INCREMENTAL_EPOCHS,
    "lr": LR, "alert_cooldown": ALERT_COOLDOWN_SEC,
    "port_scan_threshold": PORT_SCAN_THRESHOLD, "port_scan_window": PORT_SCAN_WINDOW_SEC,
    "ddos_packet_threshold": DDOS_PACKET_THRESHOLD, "ddos_window": DDOS_WINDOW_SEC,
    "dns_tunnel_length": DNS_TUNNEL_LENGTH,
    "dns_query_rate_threshold": DNS_QUERY_RATE_THRESHOLD,
    "dns_query_rate_window": DNS_QUERY_RATE_WINDOW,
    "auto_blacklist_threshold": AUTO_BLACKLIST_THRESHOLD,
    "arp_spoof_threshold": ARP_SPOOF_THRESHOLD,
    "tcp_syn_flood_threshold": TCP_SYN_FLOOD_THRESHOLD,
    "icmp_flood_threshold": ICMP_FLOOD_THRESHOLD,
    "brute_force_threshold": BRUTE_FORCE_THRESHOLD,
    "lab_mode": LAB_MODE, "lab_interval": LAB_INTERVAL_SEC,
    "webhook_url": WEBHOOK_URL, "webhook_cooldown": WEBHOOK_COOLDOWN_SEC,
    "sound_alerts": False, "desktop_alerts": DESKTOP_ALERTS,
    "save_pcap": True, "max_pcap_anomalies": 100,
}

config = DEFAULT_CONFIG.copy()


def load_config():
    global config
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            config.update(user_cfg)
        except Exception:
            pass
    else:
        save_config()


def save_config():
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, default=str)


class AttentionBlock(nn.Module):
    """Multi-head self-attention for feature relationships."""
    def __init__(self, dim, num_heads=4):
        super().__init__()
        self.attention = nn.MultiheadAttention(dim, num_heads, batch_first=True, dropout=0.1)
        self.norm = nn.LayerNorm(dim)
        self.ff = nn.Sequential(
            nn.Linear(dim, dim * 2),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(dim * 2, dim),
        )
        self.norm2 = nn.LayerNorm(dim)

    def forward(self, x):
        attn_out, _ = self.attention(x, x, x)
        x = self.norm(x + attn_out)
        x = self.norm2(x + self.ff(x))
        return x


class ZenihtAutoEncoder(nn.Module):
    """Autoencoder mejorado con attention y skip connections."""
    def __init__(self, input_dim):
        super().__init__()
        self.input_dim = input_dim

        self.feature_proj = nn.Linear(input_dim, 256)

        self.attention = AttentionBlock(256, num_heads=4)

        self.encoder = nn.Sequential(
            nn.Linear(256, 512), nn.BatchNorm1d(512), nn.GELU(), nn.Dropout(0.25),
            nn.Linear(512, 384), nn.BatchNorm1d(384), nn.GELU(), nn.Dropout(0.2),
            nn.Linear(384, 256), nn.BatchNorm1d(256), nn.GELU(), nn.Dropout(0.15),
            nn.Linear(256, 128), nn.BatchNorm1d(128), nn.GELU(), nn.Dropout(0.1),
            nn.Linear(128, 64), nn.GELU(),
        )

        self.bottleneck = nn.Sequential(
            nn.Linear(64, 48), nn.GELU(),
            nn.Linear(48, 64), nn.GELU(),
        )

        self.decoder = nn.Sequential(
            nn.Linear(64, 128), nn.BatchNorm1d(128), nn.GELU(), nn.Dropout(0.1),
            nn.Linear(128, 256), nn.BatchNorm1d(256), nn.GELU(), nn.Dropout(0.15),
            nn.Linear(256, 384), nn.BatchNorm1d(384), nn.GELU(), nn.Dropout(0.2),
            nn.Linear(384, 512), nn.BatchNorm1d(512), nn.GELU(), nn.Dropout(0.25),
            nn.Linear(512, 256),
        )

        self.output_proj = nn.Linear(256, input_dim)

    def forward(self, x):
        proj = self.feature_proj(x)

        batch_size = proj.size(0)
        seq_len = 1
        attn_in = proj.unsqueeze(1)
        attn_out = self.attention(attn_in).squeeze(1)
        proj = proj + attn_out

        enc = self.encoder(proj)
        enc = self.bottleneck(enc) + enc
        dec = self.decoder(enc)
        out = self.output_proj(dec)
        return out

    def get_encoding(self, x):
        proj = self.feature_proj(x)
        return self.encoder(proj)


def build_model():
    global model, optimizer
    model = ZenihtAutoEncoder(config["seq_len"] * config["feature_dim"]).to(device)
    optimizer = optim.AdamW(model.parameters(), lr=config["lr"], weight_decay=1e-4)


def init_files():
    PCAP_DIR.mkdir(exist_ok=True)
    REPORT_DIR.mkdir(exist_ok=True)
    for csv_path, header in [
        (EVENTS_CSV_PATH, ["timestamp","src","dst","iface","severity","error","threshold","packet_count","anomaly_count","src_port","dst_port","protocol","payload_len","threat_type"]),
        (FLOWS_CSV_PATH, ["flow_id","src","dst","src_port","dst_port","protocol","packets","bytes","duration","start_time","end_time","iface"]),
        (DNS_CSV_PATH, ["timestamp","src","query","query_length","subdomain_count","response_type","iface","suspicious"]),
    ]:
        if not csv_path.exists():
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(header)

    if BLACKLIST_PATH.exists():
        try:
            with open(BLACKLIST_PATH, "r") as f:
                blacklisted_hosts.update(json.load(f).get("hosts", []))
        except Exception:
            pass

    if HOST_PROFILES_PATH.exists():
        try:
            with open(HOST_PROFILES_PATH, "r") as f:
                host_profiles.update(json.load(f))
        except Exception:
            pass


def save_blacklist():
    with open(BLACKLIST_PATH, "w") as f:
        json.dump({"hosts": list(blacklisted_hosts)}, f, indent=2)


def save_host_profiles():
    try:
        clean = {}
        for ip, p in host_profiles.items():
            clean[ip] = {k: v for k, v in p.items() if not isinstance(v, (set, deque))}
        with open(HOST_PROFILES_PATH, "w") as f:
            json.dump(clean, f, indent=2)
    except Exception:
        pass


def append_event_csv(src, dst, iface, severity, err, thr, pkt_cnt, anom_cnt,
                     sport=0, dport=0, proto="", plen=0, threat=""):
    try:
        with open(EVENTS_CSV_PATH, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                time.strftime("%Y-%m-%d %H:%M:%S"),
                src, dst, iface, severity, f"{err:.8f}",
                f"{thr:.8f}" if thr is not None else "",
                pkt_cnt, anom_cnt, sport, dport, proto, plen, threat
            ])
    except Exception:
        pass


def append_flow_csv(flow_id, src, dst, sport, dport, proto, pkts, byts, dur, start, end, iface):
    try:
        with open(FLOWS_CSV_PATH, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([flow_id, src, dst, sport, dport, proto, pkts, byts, f"{dur:.3f}", start, end, iface])
    except Exception:
        pass


def append_dns_csv(src, query, qlen, sub_count, resp_type, iface, suspicious):
    try:
        with open(DNS_CSV_PATH, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([time.strftime("%Y-%m-%d %H:%M:%S"), src, query, qlen, sub_count, resp_type, iface, "YES" if suspicious else "NO"])
    except Exception:
        pass


def make_windows(arr, seq_len):
    if len(arr) < seq_len:
        return np.empty((0, seq_len, arr.shape[1]), dtype=np.float32)
    return np.asarray([arr[i:i + seq_len] for i in range(len(arr) - seq_len + 1)], dtype=np.float32)


def flatten_windows(windows):
    return windows.reshape(windows.shape[0], -1)


def get_src_dst(pkt):
    if pkt.haslayer(IP): return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6): return pkt[IPv6].src, pkt[IPv6].dst
    if pkt.haslayer(ARP): return pkt[ARP].psrc, pkt[ARP].pdst
    return "N/A", "N/A"


def packet_proto_id(pkt):
    if pkt.haslayer(TCP): return 1
    if pkt.haslayer(UDP): return 2
    if pkt.haslayer(ICMP): return 3
    if pkt.haslayer(ARP): return 4
    if pkt.haslayer(IPv6): return 5
    if pkt.haslayer(IP): return 6
    return 0


def proto_name(pid):
    return {0:"OTHER",1:"TCP",2:"UDP",3:"ICMP",4:"ARP",5:"IPv6",6:"IP"}.get(pid,"UNK")


def safe_port(pkt, attr):
    try: return int(getattr(pkt, attr))
    except: return 0


def get_iface(pkt):
    return getattr(pkt, "sniffed_on", "unknown")


def is_private_ip(ip):
    try:
        parts = ip.split(".")
        if len(parts) != 4: return False
        f, s = int(parts[0]), int(parts[1])
        return f == 10 or (f == 172 and 16 <= s <= 31) or (f == 192 and s == 168) or f == 127
    except: return False


def flow_key(src, dst, sport, dport, proto):
    ips = sorted([src, dst])
    ports = sorted([sport, dport])
    return f"{ips[0]}:{ports[0]}-{ips[1]}:{ports[1]}:{proto}"


def format_bytes(b):
    for unit in ["B","KB","MB","GB"]:
        if b < 1024: return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}TB"


def format_rate(bps):
    return format_bytes(bps) + "/s"



# =========================================================
# V13: DEVICE FINGERPRINTING & NETWORK ANALYSIS


# =========================================================
# V14: NETWORK-TO-NETWORK NAVIGATION
# =========================================================
def calculate_subnet_mask(cidr_bits):
    """Calculate subnet mask from CIDR bits."""
    mask = 0xffffffff << (32 - cidr_bits) & 0xffffffff
    return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"


def ip_in_subnet(ip, network, cidr_bits):
    """Check if IP is in subnet."""
    try:
        ip_int = sum(int(o) << (24 - 8*i) for i, o in enumerate(ip.split(".")))
        net_int = sum(int(o) << (24 - 8*i) for i, o in enumerate(network.split(".")))
        mask = 0xffffffff << (32 - cidr_bits) & 0xffffffff
        return (ip_int & mask) == (net_int & mask)
    except:
        return False


def get_network_class(ip):
    """Get network class and whether it's private."""
    try:
        first = int(ip.split(".")[0])
        if first == 0: return "Unspecified", True
        if first == 127: return "Loopback", True
        if first == 10: return "Class A Private", True
        if first == 172: 
            second = int(ip.split(".")[1])
            if 16 <= second <= 31: return "Class B Private", True
        if first == 192:
            second = int(ip.split(".")[1])
            if second == 168: return "Class C Private", True
        if 1 <= first <= 126: return "Class A Public", False
        if 128 <= first <= 191: return "Class B Public", False
        if 192 <= first <= 223: return "Class C Public", False
        if 224 <= first <= 239: return "Multicast", False
        if 240 <= first <= 255: return "Reserved", False
        return "Unknown", False
    except:
        return "Unknown", False


def discover_networks():
    """Discover networks from observed traffic."""
    networks = {}
    
    with lock:
        for ip in list(host_stats.keys()) + list(arp_table.keys()):
            if not ip or ip == "N/A":
                continue
            
            parts = ip.split(".")
            if len(parts) != 4:
                continue
            
            # Determine network based on IP class
            first = int(parts[0])
            if first == 192 and int(parts[1]) == 168:
                # Class C - /24
                network = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
                cidr = 24
            elif first == 10:
                # Class A - /8
                network = f"{parts[0]}.0.0.0"
                cidr = 8
            elif first == 172 and 16 <= int(parts[1]) <= 31:
                # Class B - /16
                network = f"{parts[0]}.{parts[1]}.0.0"
                cidr = 16
            else:
                # Assume /24
                network = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
                cidr = 24
            
            if network not in networks:
                net_class, is_private = get_network_class(ip)
                networks[network] = {
                    "cidr": cidr,
                    "mask": calculate_subnet_mask(cidr),
                    "hosts": set(),
                    "class": net_class,
                    "private": is_private,
                    "first_seen": time.time(),
                    "last_seen": time.time(),
                    "host_count": 0,
                }
            
            networks[network]["hosts"].add(ip)
            networks[network]["host_count"] = len(networks[network]["hosts"])
            networks[network]["last_seen"] = time.time()
    
    return networks


def scan_network_target(target_ip, scan_type="ping", ports=None):
    """Scan a specific target IP with specified scan type."""
    import subprocess
    
    results = {
        "target": target_ip,
        "scan_type": scan_type,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "alive": False,
        "open_ports": [],
        "hop_count": 0,
        "response_time": 0,
        "details": {},
    }
    
    try:
        if scan_type == "ping":
            # ICMP ping
            param = "-n" if os.name == "nt" else "-c"
            timeout_param = "-w" if os.name == "nt" else "-W"
            cmd = ["ping", param, "1", timeout_param, "2", target_ip]
            start = time.time()
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            results["response_time"] = time.time() - start
            results["alive"] = output.returncode == 0
            results["details"]["output"] = output.stdout[:500]
            
        elif scan_type == "tcp_syn":
            # TCP SYN scan on common ports
            if ports is None:
                ports = SCAN_PORTS[:10]  # Top 10 ports
            
            open_ports = []
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(SCAN_TIMEOUT)
                    start = time.time()
                    result = sock.connect_ex((target_ip, port))
                    if result == 0:
                        open_ports.append({
                            "port": port,
                            "service": get_service_name(port),
                            "response_time": time.time() - start,
                        })
                    sock.close()
                except:
                    pass
            
            results["open_ports"] = open_ports
            results["alive"] = len(open_ports) > 0
            results["details"]["scanned_ports"] = len(ports)
            
        elif scan_type == "trace":
            # Traceroute
            param = "-d" if os.name == "nt" else "-I"
            max_hops = "-h" if os.name == "nt" else "-m"
            cmd = ["tracert" if os.name == "nt" else "traceroute", 
                   max_hops, str(TRACE_HOP_LIMIT), target_ip]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            results["details"]["output"] = output.stdout[:2000]
            
            # Parse hop count
            lines = output.stdout.split("\n")
            hop_count = 0
            for line in lines:
                if line.strip() and line.strip()[0].isdigit():
                    hop_count += 1
            results["hop_count"] = hop_count
            results["alive"] = hop_count > 0
            
        elif scan_type == "full":
            # Full connect scan
            open_ports = []
            for port in range(1, 1025):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((target_ip, port))
                    if result == 0:
                        open_ports.append({
                            "port": port,
                            "service": get_service_name(port),
                        })
                    sock.close()
                except:
                    pass
            
            results["open_ports"] = open_ports
            results["alive"] = len(open_ports) > 0
            results["details"]["scanned_ports"] = 1024
            
    except Exception as e:
        results["details"]["error"] = str(e)
    
    return results


def scan_subnet(network, cidr, scan_type="ping", max_hosts=254):
    """Scan an entire subnet."""
    import concurrent.futures
    
    results = {
        "network": f"{network}/{cidr}",
        "scan_type": scan_type,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hosts_up": [],
        "total_scanned": 0,
    }
    
    # Generate host list
    parts = network.split(".")
    base = f"{parts[0]}.{parts[1]}.{parts[2]}"
    
    targets = []
    for i in range(1, min(max_hosts + 1, 255)):
        targets.append(f"{base}.{i}")
    
    # Scan with threading
    scan_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_SCANS) as executor:
        future_to_ip = {executor.submit(scan_network_target, ip, scan_type): ip for ip in targets}
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                result = future.result()
                scan_results.append(result)
                if result["alive"]:
                    results["hosts_up"].append(result)
            except:
                pass
    
    results["total_scanned"] = len(targets)
    results["hosts_up_count"] = len(results["hosts_up"])
    
    return results


def trace_route(target_ip, max_hops=TRACE_HOP_LIMIT):
    """Perform traceroute to target."""
    import subprocess
    
    results = {
        "target": target_ip,
        "hops": [],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    try:
        param = "-d" if os.name == "nt" else "-I"
        max_hops_param = "-h" if os.name == "nt" else "-m"
        cmd = ["tracert" if os.name == "nt" else "traceroute",
               max_hops_param, str(max_hops), target_ip]
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        lines = output.stdout.split("\n")
        for line in lines:
            line = line.strip()
            if line and line[0].isdigit():
                parts = line.split()
                if len(parts) >= 2:
                    hop = {
                        "hop_num": int(parts[0]),
                        "ip": parts[1] if len(parts) > 1 else "*",
                        "response_time": parts[2] if len(parts) > 2 else "*",
                    }
                    results["hops"].append(hop)
        
        results["hop_count"] = len(results["hops"])
        results["reachable"] = len(results["hops"]) > 0
        
    except Exception as e:
        results["error"] = str(e)
    
    return results


def analyze_network_topology():
    """Analyze network topology from observed traffic."""
    topology = {
        "local_networks": [],
        "remote_networks": [],
        "cross_network_flows": [],
        "gateways": [],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    networks = discover_networks()
    
    # Classify networks
    for network, info in networks.items():
        net_info = {
            "network": network,
            "cidr": info["cidr"],
            "hosts": list(info["hosts"]),
            "host_count": info["host_count"],
            "class": info["class"],
            "private": info["private"],
        }
        
        if info["private"]:
            topology["local_networks"].append(net_info)
        else:
            topology["remote_networks"].append(net_info)
    
    # Analyze cross-network flows
    with lock:
        for fk, flow in active_flows.items():
            src = flow["src"]
            dst = flow["dst"]
            
            src_net = None
            dst_net = None
            
            for network, info in networks.items():
                if ip_in_subnet(src, network, info["cidr"]):
                    src_net = network
                if ip_in_subnet(dst, network, info["cidr"]):
                    dst_net = network
            
            if src_net and dst_net and src_net != dst_net:
                topology["cross_network_flows"].append({
                    "src_network": src_net,
                    "dst_network": dst_net,
                    "flow_key": fk,
                    "packets": flow["packets"],
                    "bytes": flow["bytes"],
                })
    
    # Identify potential gateways (hosts with most cross-network traffic)
    gateway_candidates = defaultdict(int)
    for flow_info in topology["cross_network_flows"]:
        src = flow_info["flow_key"].split("-")[0].split(":")[0]
        dst = flow_info["flow_key"].split("-")[1].split(":")[0]
        gateway_candidates[src] += flow_info["packets"]
        gateway_candidates[dst] += flow_info["packets"]
    
    if gateway_candidates:
        top_gateways = sorted(gateway_candidates.items(), key=lambda x: x[1], reverse=True)[:5]
        topology["gateways"] = [{"ip": ip, "packets": count} for ip, count in top_gateways]
    
    # Save topology
    try:
        with open(TOPOLOGY_PATH, "w") as f:
            json.dump(topology, f, indent=2, default=str)
    except:
        pass
    
    return topology


def discover_and_scan_all():
    """Discover networks and scan them."""
    networks = discover_networks()
    
    results = {
        "networks_found": len(networks),
        "scan_results": [],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    for network, info in networks.items():
        # Only scan private networks for safety
        if info["private"]:
            scan_result = scan_subnet(network, info["cidr"], scan_type="ping", max_hosts=50)
            results["scan_results"].append(scan_result)
    
    # Save discovery results
    try:
        with open(NETWORK_DISCOVERY_PATH, "w") as f:
            json.dump(results, f, indent=2, default=str)
    except:
        pass
    
    return results


def get_network_map():
    """Get a visual network map."""
    networks = discover_networks()
    topology = analyze_network_topology()
    
    network_map = {
        "nodes": [],
        "edges": [],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    # Add network nodes
    for network, info in networks.items():
        node = {
            "id": network,
            "type": "network",
            "label": f"{network}/{info['cidr']}",
            "hosts": info["host_count"],
            "private": info["private"],
        }
        network_map["nodes"].append(node)
    
    # Add host nodes and edges
    for network, info in networks.items():
        for host in info["hosts"][:10]:  # Limit to 10 hosts per network
            host_node = {
                "id": host,
                "type": "host",
                "label": host,
                "network": network,
            }
            network_map["nodes"].append(host_node)
            
            # Add edge from host to network
            edge = {
                "source": host,
                "target": network,
                "type": "connected_to",
            }
            network_map["edges"].append(edge)
    
    # Add cross-network edges from topology
    for flow in topology.get("cross_network_flows", [])[:20]:
        edge = {
            "source": flow["src_network"],
            "target": flow["dst_network"],
            "type": "cross_network",
            "packets": flow["packets"],
        }
        network_map["edges"].append(edge)
    
    return network_map


# Global network scan state
network_scan_lock = threading.Lock()
last_network_scan_time = 0.0
discovered_networks_cache = {}


def network_scan_loop():
    """Background thread for network scanning."""
    global last_network_scan_time
    
    while not shutdown_event.is_set():
        time.sleep(config.get("network_scan_interval", ACTIVE_SCAN_INTERVAL_SEC))
        
        try:
            now = time.time()
            if now - last_network_scan_time < config.get("network_scan_cooldown", SCAN_COOLDOWN_SEC):
                continue
            
            last_network_scan_time = now
            
            with network_scan_lock:
                discovered = discover_networks()
                discovered_networks_cache.update(discovered)
            
        except Exception as e:
            logger.debug(f"Network scan error: {e}")

# =========================================================
def lookup_mac_vendor(mac):
    """Look up vendor from MAC address prefix."""
    if not mac:
        return "Unknown"
    mac_clean = mac.upper().replace("-", ":")
    prefix = mac_clean[:8]
    return MAC_VENDORS.get(prefix, "Unknown")


def fingerprint_os(ttl):
    """Fingerprint OS based on TTL value."""
    if ttl <= 0:
        return {"os": "Unknown", "confidence": 0.0}

    for (ttl_min, ttl_max), info in OS_FINGERPRINTS.items():
        if ttl_min <= ttl <= ttl_max:
            return info

    if ttl <= 32:
        return {"os": "Windows/Network Device", "confidence": 0.5}
    elif ttl <= 64:
        return {"os": "Linux/macOS", "confidence": 0.6}
    elif ttl <= 128:
        return {"os": "Windows", "confidence": 0.6}
    elif ttl <= 255:
        return {"os": "Solaris/Network Device", "confidence": 0.5}
    return {"os": "Unknown", "confidence": 0.0}


def identify_device_type(open_ports):
    """Identify device type based on open ports."""
    if not open_ports:
        return "Unknown"

    scores = {}
    for device_type, ports in DEVICE_TYPES.items():
        score = len(set(open_ports) & set(ports))
        if score > 0:
            scores[device_type] = score

    if not scores:
        return "Unknown"

    best_match = max(scores, key=scores.get)
    if scores[best_match] >= 2:
        return best_match.replace("_", " ").title()
    elif scores[best_match] == 1:
        return f"Possible {best_match.replace('_', ' ').title()}"
    return "Unknown"


def get_service_name(port):
    """Get service name from port number."""
    return KNOWN_PORTS_SERVICE.get(port, f"Unknown({port})")


def get_geo_info(ip):
    """Get geographic information for an IP address."""
    if not ip:
        return {"region": "Unknown", "country": "Unknown"}

    if is_private_ip(ip):
        return {"region": "Private", "country": "Local Network", "org": "Local"}

    if ip in GEOIP_RANGES:
        return GEOIP_RANGES[ip]

    for cidr, info in GEOIP_RANGES.items():
        if "/" in cidr:
            continue
        if ip == cidr:
            return info

    parts = ip.split(".")
    if len(parts) == 4:
        first = int(parts[0])
        if first == 8 or first == 1 or first == 208:
            return {"region": "North America", "country": "USA", "org": "Tech Company"}
        elif first >= 192:
            return {"region": "Europe", "country": "Various"}
        elif first >= 100:
            return {"region": "Asia", "country": "Various"}

    return {"region": "Unknown", "country": "Unknown", "org": "Unknown"}


def classify_traffic(sport, dport, proto, size=0):
    """Classify traffic based on ports and protocol."""
    for profile_name, profile in TRAFFIC_PROFILES.items():
        if dport in profile["ports"] or sport in profile["ports"]:
            if proto in profile["protocols"]:
                return profile_name
    return "other"


def calculate_network_health():
    """Calculate overall network health score (0-100, higher is better)."""
    with lock:
        if not host_stats:
            return 100.0

        total_hosts = len(host_stats)
        active_hosts = sum(1 for h in host_stats.values()
                          if time.time() - h["last_seen"] < 300)

        healthy_hosts = sum(1 for h in host_stats.values()
                          if h["anomalies"] == 0 and time.time() - h["last_seen"] < 300)

        total_anomalies = sum(h["anomalies"] for h in host_stats.values())
        total_critical = sum(h["critical"] for h in host_stats.values())
        total_packets = sum(h["packets"] for h in host_stats.values())

        if total_packets == 0:
            return 100.0

        anomaly_ratio = total_anomalies / max(1, total_packets)
        critical_ratio = total_critical / max(1, total_packets)
        healthy_ratio = healthy_hosts / max(1, active_hosts)

        score = 100.0
        score -= anomaly_ratio * 500
        score -= critical_ratio * 1000
        score -= (1 - healthy_ratio) * 30

        if len(blacklisted_hosts) > 0:
            score -= min(len(blacklisted_hosts) * 5, 20)

        return max(0.0, min(100.0, score))


def get_device_inventory():
    """Get or build device inventory from observed hosts."""
    inventory = {}

    if INVENTORY_PATH.exists():
        try:
            with open(INVENTORY_PATH, "r") as f:
                inventory = json.load(f)
        except Exception:
            inventory = {}

    with lock:
        for ip, stats in host_stats.items():
            if ip not in inventory:
                inventory[ip] = {
                    "first_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats["first_seen"])),
                    "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats["last_seen"])),
                    "os": "Unknown",
                    "vendor": "Unknown",
                    "device_type": "Unknown",
                    "geo": get_geo_info(ip),
                }

            inv = inventory[ip]
            inv["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats["last_seen"]))
            inv["packets"] = stats["packets"]
            inv["bytes"] = stats["bytes"]
            inv["anomalies"] = stats["anomalies"]
            inv["critical"] = stats["critical"]

            open_ports = list(stats.get("unique_ports", set()))
            inv["device_type"] = identify_device_type(open_ports)
            inv["open_ports"] = open_ports
            inv["services"] = [get_service_name(p) for p in open_ports[:10]]

            if stats.get("protocols"):
                inv["protocols"] = list(stats["protocols"])

    try:
        with open(INVENTORY_PATH, "w") as f:
            json.dump(inventory, f, indent=2, default=str)
    except Exception:
        pass

    return inventory


def scan_host_details(ip):
    """Get detailed scan results for a host."""
    with lock:
        if ip not in host_stats:
            return None

        stats = host_stats[ip]
        profile = host_profiles.get(ip, {})

        open_ports = list(stats.get("unique_ports", set()))
        device_type = identify_device_type(open_ports)
        os_info = fingerprint_os(0)
        geo_info = get_geo_info(ip)

        protocols_used = list(stats.get("protocols", set()))

        traffic_types = set()
        for port in open_ports:
            for profile_name, prof in TRAFFIC_PROFILES.items():
                if port in prof["ports"]:
                    traffic_types.add(profile_name)

        threat = get_host_threat_score(ip)

        result = {
            "ip": ip,
            "packets": stats["packets"],
            "bytes": stats["bytes"],
            "anomalies": stats["anomalies"],
            "critical": stats["critical"],
            "threat_score": threat,
            "first_seen": stats["first_seen"],
            "last_seen": stats["last_seen"],
            "interface": stats["iface"],
            "device_type": device_type,
            "os_fingerprint": os_info,
            "vendor": "Unknown",
            "geo": geo_info,
            "open_ports": open_ports,
            "services": [get_service_name(p) for p in open_ports[:10]],
            "protocols": protocols_used,
            "traffic_types": list(traffic_types),
            "syn_count": stats.get("syn_count", 0),
            "rst_count": stats.get("rst_count", 0),
            "fin_count": stats.get("fin_count", 0),
            "icmp_count": stats.get("icmp_count", 0),
            "dns_queries": stats.get("dns_queries", 0),
            "blacklisted": ip in blacklisted_hosts,
            "auto_blocked": stats.get("auto_blocked", False),
        }

        return result


def desktop_notify(title, message):
    if not config.get("desktop_alerts", True):
        return
    try:
        ps_script = f'Add-Type -AssemblyName System.Windows.Forms; $n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Warning; $n.Visible = $true; $n.ShowBalloonTip(5000, "{title}", "{message}", [System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep 3; $n.Dispose()'
        threading.Thread(target=lambda: os.system(f'powershell -Command "{ps_script}"'), daemon=True).start()
    except Exception:
        pass


def save_alert_to_log(line):
    try:
        with open(ALERT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except: pass


# =========================================================
# FEATURE EXTRACTION (16 features)
# =========================================================
def extract_features(pkt):
    global last_packet_time

    now = float(getattr(pkt, "time", time.time()))
    size = len(pkt)
    proto = packet_proto_id(pkt)

    sport = safe_port(pkt, "sport") if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) else 0
    dport = safe_port(pkt, "dport") if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) else 0

    ttl = 0
    if pkt.haslayer(IP): ttl = int(pkt[IP].ttl)
    elif pkt.haslayer(IPv6): ttl = int(pkt[IPv6].hlim)

    flags = int(pkt[TCP].flags) if pkt.haslayer(TCP) else 0

    payload_len = 0
    if pkt.haslayer(IP): payload_len = len(bytes(pkt[IP].payload))
    elif pkt.haslayer(IPv6): payload_len = len(bytes(pkt[IPv6].payload))

    is_fragment = 0
    if pkt.haslayer(IP):
        is_fragment = 1 if (pkt[IP].flags.MF or pkt[IP].frag != 0) else 0

    ip_version = 0
    if pkt.haslayer(IP): ip_version = 4
    elif pkt.haslayer(IPv6): ip_version = 6
    elif pkt.haslayer(ARP): ip_version = 0

    icmp_type = int(pkt[ICMP].type) if pkt.haslayer(ICMP) else 0
    icmp_code = int(pkt[ICMP].code) if pkt.haslayer(ICMP) else 0

    recent_timestamps.append(now)
    recent_sizes.append(size)

    pkt_rate_1s = sum(1 for t in recent_timestamps if now - t <= 1.0)
    bytes_rate_1s = sum(s for t, s in zip(recent_timestamps, recent_sizes) if now - t <= 1.0)

    delta_t = 0.0 if last_packet_time is None else max(0.0, now - last_packet_time)
    last_packet_time = now

    window_entropy = 0.0
    if len(recent_sizes) > 10:
        sizes_arr = np.array(list(recent_sizes)[-50:], dtype=np.float64)
        sizes_arr = sizes_arr / (sizes_arr.sum() + 1e-10)
        window_entropy = float(-np.sum(sizes_arr * np.log2(sizes_arr + 1e-10)))

    return np.array([
        float(size), float(proto), float(sport), float(dport),
        float(ttl), float(flags), float(payload_len), float(is_fragment),
        float(ip_version), float(pkt_rate_1s), float(bytes_rate_1s),
        float(delta_t), float(icmp_type), float(icmp_code),
        float(window_entropy), float(min(size, 1500) / 1500.0),
    ], dtype=np.float32)


# =========================================================
# HOST PROFILING
# =========================================================
def update_host_profile(src, pkt, dport, proto):
    now = time.time()
    size = len(pkt)

    if src not in host_profiles:
        host_profiles[src] = {
            "avg_size": size, "count": 1,
            "common_ports": {}, "common_protos": {},
            "first_seen": now, "last_seen": now,
            "max_pkt_rate": 0, "unique_dsts": set(),
        }
        return

    p = host_profiles[src]
    p["count"] += 1
    p["avg_size"] = (p["avg_size"] * (p["count"] - 1) + size) / p["count"]
    p["last_seen"] = now

    if dport > 0:
        p["common_ports"][str(dport)] = p["common_ports"].get(str(dport), 0) + 1
    p["common_protos"][proto] = p["common_protos"].get(proto, 0) + 1


def get_host_threat_score(src):
    if src not in host_profiles:
        return 0.0

    p = host_profiles[src]
    score = 0.0

    if src in host_stats:
        hs = host_stats[src]
        total = max(1, hs["packets"])
        anom_ratio = hs["anomalies"] / total
        if anom_ratio > 0.1: score += anom_ratio * 50
        if hs["anomalies"] > 5: score += min(hs["anomalies"] * 5, 50)

        suspicious_count = sum(1 for port in hs.get("ports_accessed", set()) if port in SUSPICIOUS_PORTS)
        score += suspicious_count * 10

    return min(score, 100.0)


# =========================================================
# THREAT DETECTIONS
# =========================================================
def detect_port_scan(src, dst, dport, now):
    if is_private_ip(src):
        return False

    tracker = port_scan_tracker[src]
    tracker["ports"].add(dport)
    tracker["timestamps"].append(now)

    recent = [t for t in tracker["timestamps"] if now - t <= config["port_scan_window"]]
    if len(recent) > 1:
        rate = len(tracker["ports"]) / max(0.1, recent[-1] - recent[0])
    else:
        rate = 0

    if len(tracker["ports"]) >= config["port_scan_threshold"]:
        return True
    if len(recent) >= 8 and rate > 3:
        return True
    return False


def detect_ddos(src, size, now):
    tracker = ddos_tracker[src]
    tracker["timestamps"].append(now)
    tracker["bytes"].append(size)

    recent = [t for t in tracker["timestamps"] if now - t <= config["ddos_window"]]
    recent_b = [b for t, b in zip(tracker["timestamps"], tracker["bytes"]) if now - t <= config["ddos_window"]]

    if len(recent) >= config["ddos_packet_threshold"]:
        return True
    if sum(recent_b) > 5 * 1024 * 1024:
        return True
    return False


def detect_syn_flood(src, now):
    tracker = syn_tracker[src]
    tracker["timestamps"].append(now)
    recent = [t for t in tracker["timestamps"] if now - t <= 5.0]
    return len(recent) >= config["tcp_syn_flood_threshold"]


def detect_icmp_flood(src, now):
    tracker = icmp_tracker[src]
    tracker["timestamps"].append(now)
    recent = [t for t in tracker["timestamps"] if now - t <= 3.0]
    return len(recent) >= config["icmp_flood_threshold"]


def detect_brute_force(src, dport, now):
    tracker = brute_force_tracker[src]
    tracker["attempts"].append(now)
    tracker["target_ports"].add(dport)
    recent = [t for t in tracker["attempts"] if now - t <= 30.0]
    return len(recent) >= config["brute_force_threshold"]


def detect_arp_spoof(src_mac, src_ip, dst_ip):
    arp_table[src_ip].add(src_mac)
    if len(arp_table[src_ip]) > config["arp_spoof_threshold"]:
        return True
    return False


def is_suspicious_domain(query):
    query_lower = query.lower()
    for domain in C2_DOMAINS:
        if domain in query_lower:
            return True
    if query_lower.count(".") > 5:
        return True
    if len(query) > 60:
        return True
    return False


# =========================================================
# DNS ANALYSIS
# =========================================================
def analyze_dns(pkt, src, iface):
    if not pkt.haslayer(DNS):
        return

    dns = pkt[DNS]
    now = time.time()

    if dns.qr == 0 and pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        query_len = len(query)
        subdomain_count = query.count(".")

        tracker = dns_tracker[src]
        tracker["queries"].append(now)
        tracker["lengths"].append(query_len)

        suspicious = is_suspicious_domain(query)

        recent_q = [t for t in tracker["queries"] if now - t <= config["dns_query_rate_window"]]
        if len(recent_q) > config["dns_query_rate_threshold"]:
            suspicious = True

        if subdomain_count > 4:
            suspicious = True

        append_dns_csv(src, query, query_len, subdomain_count, "QUERY", iface, suspicious)

        if suspicious:
            with lock:
                host_stats[src]["consecutive_anomalies"] += 1

    elif dns.qr == 1:
        resp_type = "A" if dns.rrcount > 0 else "NONE"
        if dns.rcode == 3: resp_type = "NXDOMAIN"
        elif dns.rcode == 2: resp_type = "SERVFAIL"

        query_name = ""
        if pkt.haslayer(DNSQR):
            query_name = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        append_dns_csv(src, query_name, len(query_name), 0, resp_type, iface, False)


# =========================================================
# FLOW TRACKING
# =========================================================
def update_flow(pkt, src, dst, sport, dport, proto_id, iface):
    now = time.time()
    fk = flow_key(src, dst, sport, dport, proto_id)
    size = len(pkt)

    with lock:
        if fk in active_flows:
            flow = active_flows[fk]
            flow["packets"] += 1
            flow["bytes"] += size
            flow["end_time"] = now
            flow["last_update"] = now
            if pkt.haslayer(TCP):
                flow["tcp_flags"][int(pkt[TCP].flags)] += 1
        else:
            active_flows[fk] = {
                "src": src, "dst": dst, "sport": sport, "dport": dport,
                "proto": proto_id, "iface": iface,
                "packets": 1, "bytes": size,
                "start_time": now, "end_time": now, "last_update": now,
                "tcp_flags": defaultdict(int),
            }


def expire_flows():
    now = time.time()
    expired = []
    with lock:
        for fk, flow in list(active_flows.items()):
            if now - flow["last_update"] > config["flow_timeout"]:
                expired.append((fk, flow))
                del active_flows[fk]

    for fk, flow in expired:
        dur = flow["end_time"] - flow["start_time"]
        fid = hashlib.md5(fk.encode()).hexdigest()[:12]
        append_flow_csv(fid, flow["src"], flow["dst"], flow["sport"], flow["dport"],
                        proto_name(flow["proto"]), flow["packets"], flow["bytes"], dur,
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(flow["start_time"])),
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(flow["end_time"])),
                        flow["iface"])


# =========================================================
# WEBHOOK + PCAP
# =========================================================
def send_webhook(severity, src, dst, iface, err, extra=""):
    global last_webhook_time
    url = config.get("webhook_url", "")
    if not url: return

    now = time.time()
    if now - last_webhook_time < config["webhook_cooldown"]: return
    last_webhook_time = now

    try:
        import urllib.request
        payload = json.dumps({"content": (
            f"**ZENIHT {severity}**\n"
            f"Source: `{src}`\nDest: `{dst}`\nIface: `{iface}`\n"
            f"Error: `{err:.6f}`\nThreshold: `{threshold:.6f}`\n"
            f"{extra}\nTime: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        threading.Thread(target=lambda: urllib.request.urlopen(req, timeout=5), daemon=True).start()
    except: pass


def save_anomaly_pcap(pkt, src, dst, severity):
    try:
        fname = PCAP_DIR / f"anomaly_{severity}_{int(time.time())}_{src.replace('.','_')}.pcap"
        wrpcap(str(fname), [pkt])
    except: pass


# =========================================================
# SAVE / LOAD
# =========================================================
def save_all():
    torch.save({"state_dict": model.state_dict(), "threshold": threshold,
                "seq_len": config["seq_len"], "feature_dim": config["feature_dim"]}, str(MODEL_PATH))
    joblib.dump(scaler, str(SCALER_PATH))
    if threshold is not None:
        np.save(str(THRESHOLD_PATH), np.array([threshold], dtype=np.float32))
    save_host_profiles()
    logger.info("Modelo, escalador, umbral y perfiles guardados.")


def load_all():
    global trained, threshold, scaler

    if MODEL_PATH.exists():
        try:
            ckpt = torch.load(str(MODEL_PATH), map_location=device)
            try:
                model.load_state_dict(ckpt["state_dict"], strict=False)
                threshold = ckpt.get("threshold", None)
                trained = True
                logger.info(f"Modelo cargado desde {MODEL_PATH}")
            except Exception as e_inner:
                logger.warning(f"Modelo incompatible ({e_inner}), reentrenando...")
                for p in (MODEL_PATH, SCALER_PATH, THRESHOLD_PATH):
                    try: p.unlink(missing_ok=True)
                    except: pass
        except Exception as e:
            logger.warning(f"Error cargando modelo ({e}), reentrenando...")
            for p in (MODEL_PATH, SCALER_PATH, THRESHOLD_PATH):
                try: p.unlink(missing_ok=True)
                except: pass

    if SCALER_PATH.exists():
        try:
            scaler = joblib.load(str(SCALER_PATH))
        except: pass

    if THRESHOLD_PATH.exists():
        try:
            threshold = float(np.load(str(THRESHOLD_PATH))[0])
            logger.info(f"Threshold loaded: {threshold:.8f}")
        except: pass


# =========================================================
# TRAINING
# =========================================================
def calibrate_threshold_from_tensor(X_t, sample_limit=2000):
    global threshold, dynamic_threshold

    if X_t is None or len(X_t) == 0: return None

    model.eval()
    errors = []
    with torch.no_grad():
        n = min(len(X_t), sample_limit)
        for i in range(0, n, 32):
            batch = X_t[i:min(i + 32, n)]
            recon = model(batch)
            errs = torch.mean((recon - batch) ** 2, dim=1)
            errors.extend(errs.cpu().tolist())

    if not errors: return None

    arr = np.asarray(errors, dtype=np.float32)

    threshold = float(np.quantile(arr, 0.92))
    dynamic_threshold = float(np.quantile(arr, 0.85))

    mean_err = float(np.mean(arr))
    std_err = float(np.std(arr))
    adaptive = mean_err + 2.0 * std_err

    if threshold > adaptive:
        threshold = adaptive

    # Asegurar umbral minimo razonable
    min_threshold = 0.001
    if threshold < min_threshold:
        threshold = min_threshold
    if dynamic_threshold < min_threshold * 0.8:
        dynamic_threshold = min_threshold * 0.8

    logger.info(f"Threshold calibrated: {threshold:.8f} | Dynamic: {dynamic_threshold:.8f} | Mean err: {mean_err:.8f} | Std: {std_err:.8f}")
    return threshold


def train_on_windows(X_windows, epochs):
    X_flat = flatten_windows(X_windows)
    X_t = torch.tensor(X_flat, dtype=torch.float32, device=device)
    if len(X_t) < 8: return None

    model.train()
    best_state = None
    best_loss = float("inf")

    for _ in range(epochs):
        optimizer.zero_grad(set_to_none=True)
        recon = model(X_t)
        loss = loss_fn(recon, X_t)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
        optimizer.step()
        current = float(loss.item())
        if current < best_loss:
            best_loss = current
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
    return X_t


def initial_training():
    global trained, normal_features

    if len(all_features) < config["initial_warmup"]:
        return False

    logger.info("Entrenando modelo base...")

    X = np.asarray(all_features, dtype=np.float32)
    scaler.fit(X)
    X_scaled = scaler.transform(X)

    windows = make_windows(X_scaled, config["seq_len"])
    if len(windows) < 16:
        logger.warning("Not enough windows.")
        return False

    split = int(len(windows) * 0.9)
    if split < 8: split = max(1, len(windows) - 1)

    train_windows = windows[:split]
    val_windows = windows[split:] if split < len(windows) else windows[-max(1, len(windows) // 10):]

    train_t = torch.tensor(flatten_windows(train_windows), dtype=torch.float32, device=device)
    val_t = torch.tensor(flatten_windows(val_windows), dtype=torch.float32, device=device)

    best_val = float("inf")
    best_state = None
    patience = 7

    model.train()
    for epoch in range(config["initial_epochs"]):
        optimizer.zero_grad(set_to_none=True)
        recon = model(train_t)
        loss = loss_fn(recon, train_t)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
        optimizer.step()

        model.eval()
        with torch.no_grad():
            val_loss = loss_fn(model(val_t), val_t).item()

        logger.info(f"Epoca {epoch+1:02d} | train={loss.item():.6f} val={val_loss:.6f}")

        if val_loss < best_val:
            best_val = val_loss
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            patience = 7
        else:
            patience -= 1
            if patience <= 0: break
        model.train()

    if best_state: model.load_state_dict(best_state)

    if calibrate_threshold_from_tensor(train_t, sample_limit=2000) is None:
        logger.error("Could not calibrate threshold.")
        return False

    trained = True
    seed = list(all_features)[-config["normal_buffer_max"]:]
    normal_features.clear()
    for item in seed: normal_features.append(item)

    save_all()
    logger.info(f"IA ONLINE | Umbral: {threshold:.8f}")
    return True


def incremental_training_loop():
    global threshold
    while not shutdown_event.is_set():
        time.sleep(config["train_interval"])

        if not trained:
            with lock:
                if len(all_features) >= config["initial_warmup"]:
                    initial_training()
            continue

        with lock:
            if len(normal_features) < MIN_NORMAL_FOR_UPDATE: continue
            X = np.asarray(normal_features, dtype=np.float32)
            normal_features.clear()

        try:
            scaler.partial_fit(X)
            X_scaled = scaler.transform(X)
            windows = make_windows(X_scaled, config["seq_len"])
            if len(windows) < 8: continue

            recent = windows[-256:] if len(windows) > 256 else windows
            train_tensor = train_on_windows(recent, config["incremental_epochs"])
            if train_tensor is None: continue

            new_thr = calibrate_threshold_from_tensor(train_tensor, sample_limit=min(400, len(train_tensor)))
            if new_thr is not None:
                if threshold is not None:
                    new_thr = float(0.85 * threshold + 0.15 * new_thr)
                with lock:
                    threshold = new_thr

            save_all()
        except: pass


# =========================================================
# INFERENCE / SCORING
# =========================================================
def log_alert(src, dst, iface, err, threat="", extra=""):
    global last_alert_time, anomaly_count_total, critical_count_total

    now = time.time()
    severity_label = "CRITICAL" if "CRITICAL" in str(extra) else "ALERT"
    if now - last_alert_time < config["alert_cooldown"]: return
    last_alert_time = now
    anomaly_count_total += 1

    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {severity_label} | {src} -> {dst} | iface={iface} | err={err:.8f} | threat={threat} {extra}"
    save_alert_to_log(line)

    desktop_notify(f"ZENIHT {severity_label}", f"{src} -> {dst}\n{threat}")

    send_webhook(severity_label, src, dst, iface, err, extra)


def score_sequence(seq_raw, src, dst, iface, current_feature=None,
                   source_tag="NET", update_normal=True, pkt=None,
                   sport=0, dport=0, proto=""):
    global threshold, dynamic_threshold

    if threshold is None: return None

    seq_scaled = scaler.transform(seq_raw)
    flat = seq_scaled.reshape(1, -1)
    x = torch.tensor(flat, dtype=torch.float32, device=device)

    model.eval()
    with torch.no_grad():
        recon = model(x)
        err = torch.mean((recon - x) ** 2).item()

    thr_to_use = dynamic_threshold if dynamic_threshold else threshold

    severity = "OK"
    if err > thr_to_use * 2.5: severity = "CRITICAL"
    elif err > thr_to_use * 1.8: severity = "ATTACK"
    elif err > thr_to_use * 1.2: severity = "SUSPICIOUS"
    elif err > thr_to_use * 0.9: severity = "UNKNOWN"

    is_anomaly = err > thr_to_use
    threat_type = ""

    if is_anomaly:
        now = time.time()

        if pkt and pkt.haslayer(TCP) and int(pkt[TCP].flags) == 2:
            if detect_syn_flood(src, now):
                severity = "CRITICAL"
                threat_type = "SYN_FLOOD"

        if pkt and pkt.haslayer(ICMP):
            if detect_icmp_flood(src, now):
                severity = "CRITICAL"
                threat_type = "ICMP_FLOOD"

        if detect_port_scan(src, dst, dport, now):
            severity = "ATTACK"
            threat_type = "PORT_SCAN"

        if detect_ddos(src, len(pkt) if pkt else 0, now):
            severity = "CRITICAL"
            threat_type = "DDOS"

        if dport in SUSPICIOUS_PORTS:
            threat_type = f"SUSPICIOUS_PORT:{dport}"
            if severity == "OK": severity = "SUSPICIOUS"

        if sport in SUSPICIOUS_PORTS:
            threat_type = f"SUSPICIOUS_SRC_PORT:{sport}"
            if severity == "OK": severity = "SUSPICIOUS"

        if detect_brute_force(src, dport, now):
            severity = "ATTACK"
            threat_type = "BRUTE_FORCE"

    with lock:
        st = host_stats[src]
        st["last_err"] = err
        st["last_seen"] = time.time()
        st["iface"] = iface
        st["packets"] += 1
        st["bytes"] += len(pkt) if pkt else 0
        if st["first_seen"] == 0: st["first_seen"] = time.time()

        if is_anomaly:
            st["anomalies"] += 1
            st["consecutive_anomalies"] += 1
            if severity == "CRITICAL": st["critical"] += 1
        else:
            st["consecutive_anomalies"] = 0

        if sport > 0: st["unique_ports"].add(sport)
        if dport > 0: st["unique_ports"].add(dport)
        st["ports_accessed"].add(dport) if dport > 0 else None
        st["protocols"].add(proto)

        if pkt and pkt.haslayer(TCP):
            flags = int(pkt[TCP].flags)
            if flags & 0x02: st["syn_count"] += 1
            if flags & 0x04: st["rst_count"] += 1
            if flags & 0x01: st["fin_count"] += 1

        if pkt and pkt.haslayer(ICMP): st["icmp_count"] += 1

        iface_stats[iface]["packets"] += 1
        iface_stats[iface]["bytes"] += len(pkt) if pkt else 0
        if is_anomaly: iface_stats[iface]["anomalies"] += 1

        protocol_stats[proto]["packets"] += 1
        protocol_stats[proto]["bytes"] += len(pkt) if pkt else 0

        if dport > 0:
            port_stats[dport]["packets"] += 1
            port_stats[dport]["hosts"].add(src)
            if is_anomaly: port_stats[dport]["anomalies"] += 1

        if (not is_anomaly) and update_normal and current_feature is not None:
            normal_features.append(current_feature)

        pkt_count_snap = packet_count
        anom_count_snap = st["anomalies"]

        if st["consecutive_anomalies"] >= config["auto_blacklist_threshold"] and src not in blacklisted_hosts and not is_private_ip(src):
            blacklisted_hosts.add(src)
            st["auto_blocked"] = True
            severity = "CRITICAL"
            threat_type = "AUTO_BLACKLISTED"
            logger.warning(f"AUTO-BLACKLISTED: {src} ({st['consecutive_anomalies']} consecutive anomalies)")

    if is_anomaly:
        log_alert(src, dst, iface, err, threat_type, f"[{severity}]")
        if pkt is not None: save_anomaly_pcap(pkt, src, dst, severity)

    append_event_csv(src, dst, iface, severity, err, threshold, pkt_count_snap,
                     anom_count_snap, sport, dport, proto, len(pkt) if pkt else 0, threat_type)

    colors = {
        "OK": "\033[92m", "UNKNOWN": "\033[93m", "SUSPICIOUS": "\033[93m",
        "ATTACK": "\033[91m", "CRITICAL": "\033[95m",
    }
    color = colors.get(severity, "\033[0m")
    threat_str = f" [{threat_type}]" if threat_type else ""
    print(f"{color}[ZENIHT] {source_tag} {src}:{sport} -> {dst}:{dport} | "
          f"{proto} | {severity} | err={err:.6f}{threat_str}\033[0m")

    return err


def inference_loop():
    global last_scored_packet_count

    while not shutdown_event.is_set():
        time.sleep(config["infer_interval"])

        if not trained or threshold is None: continue

        with lock:
            current_count = packet_count
            if current_count == last_scored_packet_count: continue
            if len(all_features) < config["seq_len"] or last_packet_obj is None: continue

            seq = np.asarray(list(all_features)[-config["seq_len"]:], dtype=np.float32)
            current_feature = np.asarray(all_features)[-1].copy()
            pkt = last_packet_obj
            last_scored_packet_count = current_count

        try:
            src, dst = get_src_dst(pkt)
            iface = get_iface(pkt)
            sport = safe_port(pkt, "sport") if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) else 0
            dport = safe_port(pkt, "dport") if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) else 0
            proto = proto_name(packet_proto_id(pkt))

            score_sequence(seq_raw=seq, src=src, dst=dst, iface=iface,
                          current_feature=current_feature, source_tag="NET",
                          update_normal=True, pkt=pkt,
                          sport=sport, dport=dport, proto=proto)
        except: pass


# =========================================================
# LAB MODE
# =========================================================
def make_synthetic_anomaly(seq_raw):
    x = seq_raw.copy()
    attack = random.choice(["flood","scan","exfil","c2","syn_flood","icmp_flood","port_knock","data_injection"])

    if attack == "flood":
        for i in range(min(8, len(x))):
            idx = random.randrange(len(x))
            x[idx][0] *= random.uniform(5.0, 25.0)
            x[idx][9] *= random.uniform(3.0, 15.0)
            x[idx][10] *= random.uniform(3.0, 15.0)
    elif attack == "scan":
        for i in range(min(15, len(x))):
            idx = random.randrange(len(x))
            x[idx][3] = random.uniform(1, 65535)
            x[idx][5] = 2.0
            x[idx][11] = random.uniform(0.0, 0.001)
    elif attack == "exfil":
        for i in range(min(5, len(x))):
            idx = random.randrange(len(x))
            x[idx][0] *= random.uniform(10.0, 40.0)
            x[idx][7] = 1.0
            x[idx][11] = random.uniform(0.0, 0.0005)
    elif attack == "c2":
        for i in range(min(6, len(x))):
            idx = random.randrange(len(x))
            x[idx][4] = random.uniform(1, 50)
            x[idx][5] = random.uniform(0, 255)
            x[idx][11] = random.uniform(0.0, 0.002)
            x[idx][3] = random.choice([443, 8443, 4444, 5555, 80])
    elif attack == "syn_flood":
        for i in range(min(20, len(x))):
            idx = random.randrange(len(x))
            x[idx][5] = 2.0
            x[idx][9] *= random.uniform(5.0, 30.0)
            x[idx][3] = random.uniform(1, 65535)
    elif attack == "icmp_flood":
        for i in range(min(10, len(x))):
            idx = random.randrange(len(x))
            x[idx][1] = 3.0
            x[idx][12] = random.uniform(0, 8)
            x[idx][9] *= random.uniform(5.0, 20.0)
    elif attack == "port_knock":
        for i in range(min(12, len(x))):
            idx = random.randrange(len(x))
            x[idx][3] = random.choice([1, 7, 9, 13, 37, 42, 69, 80, 443, 8080])
            x[idx][5] = 2.0
    else:
        for i in range(min(4, len(x))):
            idx = random.randrange(len(x))
            x[idx][0] *= random.uniform(3.0, 15.0)
            x[idx][3] = random.uniform(10000, 65535)
            x[idx][9] *= random.uniform(2.0, 12.0)
            x[idx][10] *= random.uniform(2.0, 12.0)

    return x.astype(np.float32)


def lab_mode_loop():
    while not shutdown_event.is_set():
        time.sleep(config["lab_interval"])

        if not config["lab_mode"] or not trained or threshold is None: continue

        with lock:
            if len(normal_features) < config["seq_len"] + 8: continue
            base = np.asarray(list(normal_features)[-config["seq_len"]:], dtype=np.float32)

        syn = make_synthetic_anomaly(base)

        try:
            score_sequence(seq_raw=syn, src="LAB", dst="LAB", iface="LAB",
                          current_feature=None, source_tag="LAB",
                          update_normal=False)
        except: pass


def flow_cleanup_loop():
    while not shutdown_event.is_set():
        time.sleep(30)
        expire_flows()


def bandwidth_loop():
    prev_iface_bytes = {}
    while not shutdown_event.is_set():
        time.sleep(3)
        now = time.time()
        with lock:
            for iface, data in iface_stats.items():
                prev = prev_iface_bytes.get(iface, (0, now))
                byte_diff = data["bytes"] - prev[0]
                time_diff = now - prev[1]
                if time_diff > 0:
                    data["bps"] = byte_diff / time_diff
                    data["pps"] = data["packets"] / max(1, time_diff)
                prev_iface_bytes[iface] = (data["bytes"], now)


def save_profiles_loop():
    while not shutdown_event.is_set():
        time.sleep(120)
        save_host_profiles()


# =========================================================
# DASHBOARD
# =========================================================
def get_threat_level():
    if critical_count_total > 0: return "CRITICAL", "\033[95m"
    if anomaly_count_total > 50: return "HIGH", "\033[91m"
    if anomaly_count_total > 10: return "MEDIUM", "\033[93m"
    if anomaly_count_total > 0: return "LOW", "\033[96m"
    return "SAFE", "\033[92m"


def dashboard_loop():
    while not shutdown_event.is_set():
        time.sleep(config["dashboard_interval"])

        if not trained: continue

        os.system("cls" if os.name == "nt" else "clear")

        threat_name, threat_color = get_threat_level()
        uptime = time.time() - start_time
        uptime_str = f"{int(uptime//3600)}h {int((uptime%3600)//60)}m"

        print(f"\033[96m{'='*78}\033[0m")
        print(f"\033[96m  ZENIHT AI ANALIZADOR DE RED v{VERSION}\033[0m")
        print(f"{threat_color}  NIVEL DE AMENAZA: {threat_name}\033[0m")
        health = calculate_network_health()
        health_color = "\033[92m" if health >= 80 else "\033[93m" if health >= 60 else "\033[91m"
        print(f"\033[96m  Device: {device} | Threshold: {threshold:.6f if threshold else 'N/A'} | Uptime: {uptime_str} | Health: {health_color}{health:.0f}/100\033[0m")
        print(f"\033[96m{'='*78}\033[0m")

        with lock:
            active_hosts = sum(1 for h in host_stats.values() if time.time() - h["last_seen"] < 60)

            print(f"\n\033[93m  PAQUETES: {packet_count:,} | ANOMALIAS: {anomaly_count_total:,} | "
                  f"CRITICOS: {critical_count_total:,} | BLOQUEADOS: {blocked_count:,}\033[0m")
            print(f"\033[93m  HOSTS ACTIVOS: {active_hosts} | FLUJOS: {len(active_flows):,}\033[0m")
            print(f"\033[93m  MI RED: {MY_IP}/{MY_SUBNET}\033[0m")

            print(f"\n\033[92m  --- INTERFACES ---\033[0m")
            for iface, data in sorted(iface_stats.items(), key=lambda x: x[1]["packets"], reverse=True)[:5]:
                anom_pct = (data['anomalies'] / max(1, data['packets'])) * 100
                print(f"  {iface:20s} | pkts={data['packets']:>8,} | anom={data['anomalies']:>4,}({anom_pct:.1f}%) | "
                      f"rate={format_rate(data.get('bps', 0)):>10s}")

            print(f"\n\033[92m  --- PROTOCOLOS ---\033[0m")
            for proto, data in sorted(protocol_stats.items(), key=lambda x: x[1]["packets"], reverse=True)[:6]:
                print(f"  {proto:10s} | pkts={data['packets']:>8,} | bytes={format_bytes(data['bytes']):>10s}")

            print(f"\n\033[92m  --- TOP HOSTS (por anomalias) ---\033[0m")
            top_hosts = sorted(host_stats.items(), key=lambda kv: (kv[1]["anomalies"], kv[1]["critical"]), reverse=True)[:8]
            for ip, data in top_hosts:
                flag = ""
                if data.get("auto_blocked"): flag = " \033[91m[BLOCKED]\033[0m"
                elif data["critical"] > 0: flag = " \033[95m[!]\033[0m"
                elif data["anomalies"] > 0: flag = " \033[93m[*]\033[0m"
                threat = get_host_threat_score(ip)
                print(f"  {ip:16s} | pkts={data['packets']:>6,} | anom={data['anomalies']:>3,} | "
                      f"crit={data['critical']:>2} | threat={threat:>5.1f}{flag}")

            print(f"\n\033[92m  --- PUERTOS SOSPECHOSOS ---\033[0m")
            flagged_ports = [(p, d) for p, d in port_stats.items() if p in SUSPICIOUS_PORTS]
            for port, data in sorted(flagged_ports, key=lambda x: x[1]["anomalies"], reverse=True)[:6]:
                print(f"  \033[91mport {port:>5d}\033[0m | pkts={data['packets']:>6,} | anom={data['anomalies']:>3,} | hosts={len(data['hosts'])}")

            print(f"\n\033[92m  --- BLOQUEADOS ---\033[0m")
            bl_active = [(ip, host_stats[ip]) for ip in blacklisted_hosts if ip in host_stats]
            if bl_active:
                for ip, data in bl_active[:5]:
                    print(f"  \033[91m{ip}\033[0m | pkts={data['packets']} | anom={data['anomalies']}")
            else:
                print(f"  (none)")

            print(f"\n\033[92m  --- INVENTARIO DE DISPOSITIVOS ---\033[0m")
            inventory = get_device_inventory()
            active_devices = [(ip, inv) for ip, inv in inventory.items()
                            if ip in host_stats and time.time() - host_stats[ip]["last_seen"] < 120]
            for ip, inv in active_devices[:6]:
                dtype = inv.get("device_type", "Unknown")
                geo = inv.get("geo", {}).get("country", "?")
                print(f"  {ip:16s} | {dtype:20s} | {geo:12s} | pkts={inv.get('packets', 0):>6,}")

            print(f"\n\033[92m  --- REDES DESCUBIERTAS ---\033[0m")
            networks = discover_networks()
            for net, info in list(networks.items())[:5]:
                net_type = "Private" if info["private"] else "Public"
                print(f"  {net}/{info['cidr']:>2d} | {info['host_count']:>3} hosts | {net_type:7s} | {info['class']}")

        print(f"\n\033[96m{'='*78}\033[0m")
        print(f"  Comandos: estado | informe | flujos | top | inventario | salud | descubrir | trazar <ip> | topologia | blacklist <ip> | escanear <ip> | ayuda | salir")
        print(f"\033[96m{'='*78}\033[0m")


# =========================================================
# SUMMARY
# =========================================================
def summary_loop():
    while not shutdown_event.is_set():
        time.sleep(config["summary_interval"])

        with lock:
            if not host_stats: continue

            threat_name, _ = get_threat_level()
            print(f"\n=== RESUMEN ZENIHT | Amenaza: {threat_name} ===")

            top_hosts = sorted(host_stats.items(), key=lambda kv: kv[1]["anomalies"], reverse=True)[:5]
            for ip, data in top_hosts:
                threat = get_host_threat_score(ip)
                print(f"- {ip} | pkts={data['packets']} | anom={data['anomalies']} | crit={data['critical']} | threat={threat:.1f}")

            print(f"=== Flujos activos: {len(active_flows)} | Total anomalias: {anomaly_count_total} | Criticos: {critical_count_total} ===\n")


# =========================================================
# CLI
# =========================================================
def interactive_cli():
    global DESKTOP_ALERTS

    help_text = """
  status           - Show status
  report           - Generate report
  flows            - Show active flows
  top              - Top hosts by anomalies
  scan <ip>        - Show details for an IP
  inventory        - Show device inventory
  health           - Show network health score
  blacklist <ip>   - Blacklist an IP
  unblacklist <ip> - Remove from blacklist
  threshold        - Show threshold info
  threat           - Show threat level
  sound on/off     - Toggle sound alerts
  desktop on/off   - Toggle desktop alerts
  discover         - Discover networks
  scan-net <cidr>  - Scan a subnet
  trace <ip>       - Traceroute to IP
  topology         - Show network topology
  network-map      - Show network map
  save             - Save model
  help             - Show this help
  exit/quit        - Shutdown
"""
    while not shutdown_event.is_set():
        try:
            cmd = input("\n\033[96mzeniht>\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            shutdown_event.set()
            break

        if not cmd: continue
        parts = cmd.split()
        action = parts[0].lower()

        if action in ("help", "ayuda"):
            print(help_text)

        elif action in ("estado", "status"):
            threat_name, _ = get_threat_level()
            print(f"Paquetes: {packet_count:,} | Anomalias: {anomaly_count_total:,} | Criticos: {critical_count_total:,}")
            print(f"Umbral: {threshold:.8f}" if threshold else "Umbral: N/A")
            print(f"Umbral dinamico: {dynamic_threshold:.8f}" if dynamic_threshold else "Umbral dinamico: N/A")
            print(f"Entrenado: {trained} | Flujos: {len(active_flows)} | Amenaza: {threat_name}")
            print(f"Bloqueados: {len(blacklisted_hosts)} | Tiempo activo: {int((time.time()-start_time)//60)}m")
            print(f"Mi IP: {MY_IP} | Gateway: {MY_GATEWAY}")

        elif action in ("amenaza", "threat"):
            name, _ = get_threat_level()
            print(f"Nivel de amenaza actual: {name}")
            print(f"Anomalias: {anomaly_count_total} | Criticos: {critical_count_total}")

        elif action in ("informe", "report"):
            path = generate_report()
            print(f"Informe guardado: {path}")

        elif action == "blacklist" and len(parts) > 1:
            blacklisted_hosts.add(parts[1])
            save_blacklist()
            print(f"Bloqueado: {parts[1]}")

        elif action in ("quitar", "unblacklist") and len(parts) > 1:
            blacklisted_hosts.discard(parts[1])
            save_blacklist()
            print(f"Removido: {parts[1]}")

        elif action in ("escanear", "scan") and len(parts) > 1:
            ip = parts[1]
            details = scan_host_details(ip)
            if details:
                threat = details["threat_score"]
                os_info = details["os_fingerprint"]
                geo = details["geo"]
                print(f"\n{'='*60}")
                print(f"  HOST SCAN: {ip}")
                print(f"{'='*60}")
                print(f"  Packets: {details['packets']:,} | Bytes: {format_bytes(details['bytes'])}")
                print(f"  Anomalies: {details['anomalies']} | Critical: {details['critical']}")
                print(f"  Threat Score: {threat:.1f}/100")
                print(f"  Interface: {details['interface']}")
                print(f"  First seen: {time.strftime('%H:%M:%S', time.localtime(details['first_seen']))}")
                print(f"  Last seen: {time.strftime('%H:%M:%S', time.localtime(details['last_seen']))}")
                print(f"\n  --- Device Fingerprint ---")
                print(f"  Device Type: {details['device_type']}")
                print(f"  OS: {os_info.get('os', 'Unknown')} (confidence: {os_info.get('confidence', 0):.0%})")
                print(f"  Vendor: {details['vendor']}")
                print(f"  Geography: {geo.get('country', 'Unknown')} ({geo.get('region', 'Unknown')})")
                print(f"  Protocols: {', '.join(details['protocols'])}")
                print(f"  Traffic Types: {', '.join(details['traffic_types']) if details['traffic_types'] else 'Unknown'}")
                print(f"\n  --- Ports & Services ({len(details['open_ports'])}) ---")
                for port, svc in zip(details['open_ports'][:10], details['services'][:10]):
                    flag = " [SUSPICIOUS]" if port in SUSPICIOUS_PORTS else ""
                    print(f"    {port:>5d} - {svc}{flag}")
                if len(details['open_ports']) > 10:
                    print(f"    ... and {len(details['open_ports']) - 10} more")
                print(f"\n  --- Traffic Analysis ---")
                print(f"  SYN: {details['syn_count']} | RST: {details['rst_count']} | FIN: {details['fin_count']}")
                print(f"  ICMP: {details['icmp_count']} | DNS: {details['dns_queries']}")
                print(f"  Blacklisted: {details['blacklisted']} | Auto-blocked: {details['auto_blocked']}")
                print(f"{'='*60}")
            else:
                print(f"No data for {ip}")

        elif action == "inventory":
            inventory = get_device_inventory()
            print(f"\n{'='*60}")
            print(f"  DEVICE INVENTORY ({len(inventory)} devices)")
            print(f"{'='*60}")
            for ip, inv in sorted(inventory.items(), key=lambda x: x[1].get("anomalies", 0), reverse=True)[:15]:
                dtype = inv.get("device_type", "Unknown")
                geo = inv.get("geo", {}).get("country", "?")
                anom = inv.get("anomalies", 0)
                crit = inv.get("critical", 0)
                flag = " [!]" if crit > 0 else " [*]" if anom > 0 else ""
                print(f"  {ip:16s} | {dtype:20s} | {geo:12s} | anom={anom:>3}{flag}")
            print(f"{'='*60}")

        elif action == "health":
            health = calculate_network_health()
            health_color = "\033[92m" if health >= 80 else "\033[93m" if health >= 60 else "\033[91m"
            print(f"\n{'='*60}")
            print(f"  NETWORK HEALTH SCORE")
            print(f"{'='*60}")
            print(f"  Score: {health_color}{health:.1f}/100\033[0m")
            if health >= 80:
                print(f"  Status: \033[92mEXCELLENT\033[0m")
            elif health >= 60:
                print(f"  Status: \033[93mFAIR\033[0m")
            elif health >= 40:
                print(f"  Status: \033[93mPOOR\033[0m")
            else:
                print(f"  Status: \033[91mCRITICAL\033[0m")
            with lock:
                active = sum(1 for h in host_stats.values() if time.time() - h["last_seen"] < 60)
                total_anom = sum(h["anomalies"] for h in host_stats.values())
                total_crit = sum(h["critical"] for h in host_stats.values())
            print(f"  Active Hosts: {active}")
            print(f"  Total Anomalies: {total_anom}")
            print(f"  Total Critical: {total_crit}")
            print(f"  Blacklisted: {len(blacklisted_hosts)}")
            print(f"{'='*60}")

        elif action == "flows":
            with lock:
                for fk, flow in list(active_flows.items())[:10]:
                    print(f"  {flow['src']}:{flow['sport']} -> {flow['dst']}:{flow['dport']} "
                          f"| {proto_name(flow['proto'])} | pkts={flow['packets']} | bytes={format_bytes(flow['bytes'])}")

        elif action == "top":
            with lock:
                top = sorted(host_stats.items(), key=lambda kv: kv[1]["anomalies"], reverse=True)[:10]
                for ip, data in top:
                    threat = get_host_threat_score(ip)
                    print(f"  {ip} | pkts={data['packets']} | anom={data['anomalies']} | crit={data['critical']} | threat={threat:.1f}")

        elif action == "threshold":
            print(f"Threshold: {threshold:.8f}" if threshold else "Threshold: N/A")
            print(f"Dynamic: {dynamic_threshold:.8f}" if dynamic_threshold else "Dynamic: N/A")

        elif action == "desktop":
            if len(parts) > 1:
                global DESKTOP_ALERTS
                DESKTOP_ALERTS = parts[1].lower() in ("on", "true", "1")
                config["desktop_alerts"] = DESKTOP_ALERTS
                print(f"Desktop alerts: {'ON' if DESKTOP_ALERTS else 'OFF'}")

        elif action == "discover":
            print("\nDiscovering networks...")
            results = discover_and_scan_all()
            print(f"\n{'='*60}")
            print(f"  NETWORK DISCOVERY RESULTS")
            print(f"{'='*60}")
            print(f"  Networks found: {results['networks_found']}")
            for scan in results['scan_results']:
                print(f"\n  Network: {scan['network']}")
                print(f"  Hosts up: {scan['hosts_up_count']}/{scan['total_scanned']}")
                for host in scan['hosts_up'][:5]:
                    print(f"    - {host['target']} ({host['scan_type']})")
            print(f"{'='*60}")

        elif action == "scan-net" and len(parts) > 1:
            target = parts[1]
            scan_type = parts[2] if len(parts) > 2 else "ping"
            print(f"\nScanning {target} with {scan_type}...")
            
            if "/" in target:
                # Subnet scan
                network, cidr = target.split("/")
                result = scan_subnet(network, int(cidr), scan_type)
                print(f"\n{'='*60}")
                print(f"  SUBNET SCAN: {target}")
                print(f"{'='*60}")
                print(f"  Hosts up: {result['hosts_up_count']}/{result['total_scanned']}")
                for host in result['hosts_up'][:10]:
                    ports = ", ".join([str(p["port"]) for p in host.get("open_ports", [])[:5]])
                    print(f"    - {host['target']} | ports: {ports or 'none'}")
            else:
                # Single host scan
                result = scan_network_target(target, scan_type)
                print(f"\n{'='*60}")
                print(f"  HOST SCAN: {target}")
                print(f"{'='*60}")
                print(f"  Alive: {result['alive']}")
                if result['open_ports']:
                    print(f"  Open ports:")
                    for port in result['open_ports']:
                        print(f"    - {port['port']}: {port['service']}")
                if result['hop_count']:
                    print(f"  Hop count: {result['hop_count']}")
                print(f"  Response time: {result['response_time']:.3f}s")
            print(f"{'='*60}")

        elif action == "trace" and len(parts) > 1:
            target = parts[1]
            print(f"\nTracing route to {target}...")
            result = trace_route(target)
            print(f"\n{'='*60}")
            print(f"  TRACEROUTE: {target}")
            print(f"{'='*60}")
            for hop in result['hops']:
                print(f"  {hop['hop_num']:>2}. {hop['ip']:>15} {hop['response_time']}")
            print(f"  Reachable: {result['reachable']}")
            print(f"{'='*60}")

        elif action == "topology":
            print("\nAnalyzing network topology...")
            topology = analyze_network_topology()
            print(f"\n{'='*60}")
            print(f"  NETWORK TOPOLOGY")
            print(f"{'='*60}")
            print(f"  Local networks: {len(topology['local_networks'])}")
            for net in topology['local_networks']:
                print(f"    - {net['network']}/{net['cidr']} ({net['host_count']} hosts)")
            print(f"  Remote networks: {len(topology['remote_networks'])}")
            for net in topology['remote_networks']:
                print(f"    - {net['network']}/{net['cidr']} ({net['host_count']} hosts)")
            print(f"  Cross-network flows: {len(topology['cross_network_flows'])}")
            if topology['gateways']:
                print(f"  Potential gateways:")
                for gw in topology['gateways']:
                    print(f"    - {gw['ip']} ({gw['packets']} packets)")
            print(f"{'='*60}")

        elif action == "network-map":
            print("\nGenerating network map...")
            network_map = get_network_map()
            print(f"\n{'='*60}")
            print(f"  NETWORK MAP")
            print(f"{'='*60}")
            print(f"  Nodes: {len(network_map['nodes'])}")
            print(f"  Edges: {len(network_map['edges'])}")
            print(f"\n  Networks:")
            for node in network_map['nodes']:
                if node['type'] == 'network':
                    private = "Private" if node.get('private') else "Public"
                    print(f"    - {node['label']} ({node['hosts']} hosts) [{private}]")
            print(f"\n  Connections:")
            for edge in network_map['edges'][:10]:
                if edge['type'] == 'cross_network':
                    print(f"    - {edge['source']} <-> {edge['target']} ({edge.get('packets', 0)} packets)")
            print(f"{'='*60}")

        elif action == "save":
            save_all()
            print("Saved.")

        elif action in ("exit", "quit"):
            shutdown_event.set()
            break

        else:
            print(f"Unknown: {action}. Type 'help'.")


# =========================================================
# REPORT
# =========================================================
def generate_report():
    now_str = time.strftime("%Y%m%d_%H%M%S")
    report_path = REPORT_DIR / f"report_{now_str}.txt"

    lines = [
        f"ZENIHT AI NETWORK ANALYZER v{VERSION} - REPORT",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Device: {device}",
        f"Threshold: {threshold:.8f}" if threshold else "Threshold: N/A",
        f"Dynamic Threshold: {dynamic_threshold:.8f}" if dynamic_threshold else "",
        f"Total packets: {packet_count:,}",
        f"Total anomalies: {anomaly_count_total:,}",
        f"Critical alerts: {critical_count_total:,}",
        f"Blacklisted hosts: {len(blacklisted_hosts)}",
        "",
        "=== TOP HOSTS (by anomalies) ===",
    ]
    for ip, data in sorted(host_stats.items(), key=lambda kv: kv[1]["anomalies"], reverse=True)[:25]:
        threat = get_host_threat_score(ip)
        lines.append(f"  {ip} | pkts={data['packets']} | anom={data['anomalies']} | crit={data['critical']} | threat={threat:.1f} | iface={data['iface']}")

    lines.append("\n=== SUSPICIOUS PORTS ===")
    for port, data in sorted(port_stats.items(), key=lambda kv: kv[1]["anomalies"], reverse=True)[:15]:
        flag = " [SUSPICIOUS]" if port in SUSPICIOUS_PORTS else ""
        lines.append(f"  port {port} | pkts={data['packets']} | anom={data['anomalies']} | hosts={len(data['hosts'])}{flag}")

    lines.append("\n=== INTERFACES ===")
    for iface, data in sorted(iface_stats.items(), key=lambda kv: kv[1]["packets"], reverse=True):
        lines.append(f"  {iface} | pkts={data['packets']} | anom={data['anomalies']} | rate={format_rate(data.get('bps', 0))}")

    lines.append("\n=== PROTOCOLS ===")
    for proto, data in sorted(protocol_stats.items(), key=lambda kv: kv[1]["packets"], reverse=True):
        lines.append(f"  {proto} | pkts={data['packets']} | bytes={format_bytes(data['bytes'])}")

    lines.append("\n=== BLACKLIST ===")
    for ip in sorted(blacklisted_hosts):
        lines.append(f"  {ip}")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    logger.info(f"Report saved: {report_path}")
    return report_path


# =========================================================
# PACKET PIPELINE
# =========================================================
def on_packet(pkt):
    try:
        packet_queue.put_nowait(pkt)
    except queue.Full: pass


def packet_consumer():
    global packet_count, last_packet_obj, blocked_count

    while not shutdown_event.is_set():
        try:
            pkt = packet_queue.get(timeout=1)
        except queue.Empty: continue

        if pkt is None: break

        try:
            if not (pkt.haslayer(IP) or pkt.haslayer(IPv6) or pkt.haslayer(ARP)):
                continue

            f = extract_features(pkt)
            src, dst = get_src_dst(pkt)
            iface = get_iface(pkt)
            now = time.time()

            sport = safe_port(pkt, "sport") if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) else 0
            dport = safe_port(pkt, "dport") if (pkt.haslayer(TCP) or pkt.haslayer(UDP)) else 0
            proto_id = packet_proto_id(pkt)
            proto = proto_name(proto_id)

            update_flow(pkt, src, dst, sport, dport, proto_id, iface)
            update_host_profile(src, pkt, dport, proto)

            if pkt.haslayer(DNS):
                analyze_dns(pkt, src, iface)

            if pkt.haslayer(ARP):
                if pkt.haslayer(ARP):
                    arp = pkt[ARP]
                    if arp.op == 2:
                        if detect_arp_spoof(arp.hwsrc, arp.psrc, arp.pdst):
                            with lock:
                                host_stats[src]["anomalies"] += 1
                                host_stats[src]["critical"] += 1
                            line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} | ARP_SPOOF | {arp.psrc} ({arp.hwsrc}) spoofing {arp.pdst}"
                            save_alert_to_log(line)
                            logger.warning(f"ARP SPOOF: {arp.psrc} ({arp.hwsrc}) -> {arp.pdst}")

            with lock:
                if src in blacklisted_hosts:
                    blocked_count += 1
                    continue

                last_packet_obj = pkt
                all_features.append(f)
                packet_count += 1
                recent_packet_objs.append(pkt)

                host_stats[src]["packets"] += 1
                host_stats[src]["bytes"] += len(pkt)
                host_stats[src]["last_seen"] = now
                host_stats[src]["iface"] = iface

                iface_stats[iface]["packets"] += 1
                iface_stats[iface]["bytes"] += len(pkt)

        except: pass
        finally:
            packet_queue.task_done()


# =========================================================
# SNIFFER START
# =========================================================
def start_multi_interface_sniffers():
    global sniffers
    sniffers = []

    working_ifaces = list(get_working_ifaces())
    if not working_ifaces:
        logger.error("No active interfaces found.")
        return False

    logger.info("Available interfaces:")
    for i in working_ifaces:
        logger.info(f"  - {i.name} ({i.description})")

    for iface in working_ifaces:
        try:
            sniffer = AsyncSniffer(iface=iface.name, prn=on_packet, store=False, filter="ip or ip6 or arp")
            sniffer.start()
            sniffers.append(sniffer)
            logger.info(f"Capturing on: {iface.name}")
        except Exception as e:
            logger.warning(f"Failed on {iface.name}: {e}")

    return len(sniffers) > 0


# =========================================================
# WEB SERVER (modo local)
# =========================================================
def get_web_status():
    """Obtener estado para la API web."""
    networks = discover_networks()
    inventory = get_device_inventory()
    
    hosts_data = []
    with lock:
        for ip, stats in host_stats.items():
            inv = inventory.get(ip, {})
            hosts_data.append({
                "ip": ip,
                "packets": stats.get("packets", 0),
                "anomalies": stats.get("anomalies", 0),
                "critical": stats.get("critical", 0),
                "threatScore": get_host_threat_score(ip),
                "deviceType": inv.get("device_type", "Desconocido"),
                "country": inv.get("geo", {}).get("country", "Local"),
                "lastSeen": stats.get("last_seen", 0),
            })

    flows_data = []
    for fk, flow in list(active_flows.items())[:20]:
        flows_data.append({
            "src": flow["src"],
            "dst": flow["dst"],
            "sport": flow["sport"],
            "dport": flow["dport"],
            "proto": proto_name(flow["proto"]),
            "packets": flow["packets"],
        })

    networks_data = []
    for net, info in networks.items():
        networks_data.append({
            "network": net,
            "cidr": info["cidr"],
            "hostCount": info["host_count"],
            "private": info["private"],
            "class": info["class"],
        })

    ports_data = []
    for port, stats in sorted(port_stats.items(), key=lambda x: x[1]["packets"], reverse=True)[:15]:
        ports_data.append({
            "port": port,
            "service": get_service_name(port),
            "packets": stats["packets"],
            "anomalies": stats["anomalies"],
            "suspicious": port in SUSPICIOUS_PORTS,
        })

    health = calculate_network_health()
    threat_name, _ = get_threat_level()
    
    active_hosts = sum(1 for h in host_stats.values() if time.time() - h.get("last_seen", 0) < 300)

    return {
        "stats": {
            "packets": packet_count,
            "anomalies": anomaly_count_total,
            "critical": critical_count_total,
            "activeHosts": active_hosts,
            "blocked": len(blacklisted_hosts),
            "health": round(health),
            "threshold": round(threshold, 8) if threshold else None,
            "dynamicThreshold": round(dynamic_threshold, 8) if dynamic_threshold else None,
        },
        "threat": {
            "name": threat_name,
            "description": f"Anomalias: {anomaly_count_total} | Criticos: {critical_count_total}",
        },
        "hosts": sorted(hosts_data, key=lambda x: x["anomalies"], reverse=True)[:30],
        "flows": flows_data,
        "networks": networks_data,
        "ports": ports_data,
        "events": [],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def start_web_server(port):
    """Iniciar servidor web HTTP."""
    import http.server
    import json
    import os
    
    WEB_DIR = BASE_DIR / "web"
    
    class ZENIHTHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(WEB_DIR), **kwargs)
        
        def do_GET(self):
            if self.path == '/api/status':
                data = get_web_status()
                response = json.dumps(data).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Length', len(response))
                self.end_headers()
                self.wfile.write(response)
            elif self.path == '/api/health':
                data = {"status": "ok", "version": VERSION, "uptime": time.time() - start_time}
                response = json.dumps(data).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Length', len(response))
                self.end_headers()
                self.wfile.write(response)
            else:
                super().do_GET()
        
        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
        
        def log_message(self, format, *args):
            pass
    
    try:
        server = http.server.HTTPServer(('0.0.0.0', port), ZENIHTHandler)
        logger.info(f"Servidor web iniciado en http://0.0.0.0:{port}")
        logger.info(f"Abre http://localhost:{port} en tu navegador")
        server.serve_forever()
    except Exception as e:
        logger.error(f"Error iniciando servidor web: {e}")


def signal_handler(sig, frame):
    logger.info("Shutting down...")
    shutdown_event.set()
    for s in sniffers:
        try: s.stop()
        except: pass
    try: packet_queue.put_nowait(None)
    except: pass
    if trained: save_all()
    save_host_profiles()
    generate_report()
    logger.info("Goodbye.")
    sys.exit(0)


# =========================================================
# MAIN
# =========================================================
def main():
    parser = argparse.ArgumentParser(description=f"ZENIHT AI Network Analyzer v{VERSION}")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable dashboard")
    parser.add_argument("--no-lab", action="store_true", help="Disable lab mode")
    parser.add_argument("--no-sound", action="store_true", help="Disable sound alerts")
    parser.add_argument("--no-desktop", action="store_true", help="Disable desktop alerts")
    parser.add_argument("--webhook", type=str, default="", help="Webhook URL")
    parser.add_argument("--report-only", action="store_true", help="Generate report and exit")
    parser.add_argument("--config", type=str, default="", help="Config file path")
    parser.add_argument("--web", action="store_true", help="Habilitar servidor web")
    parser.add_argument("--web-port", type=int, default=8080, help="Puerto del servidor web")
    args = parser.parse_args()

    print(f"\033[96m{'='*60}\033[0m")
    print(f"\033[96m  ZENIHT AI ANALIZADOR DE RED v{VERSION}\033[0m")
    print(f"\033[96m  AI + Host Profiling + Auto-Blacklist + Threat Detection\033[0m")
    print(f"\033[96m  Device: {device}\033[0m")
    print(f"\033[96m{'='*60}\033[0m\n")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.config:
        global CONFIG_PATH
        CONFIG_PATH = Path(args.config)

    load_config()

    if args.no_lab: config["lab_mode"] = False
    if args.no_sound: config["sound_alerts"] = False
    if args.no_desktop: config["desktop_alerts"] = False
    if args.webhook: config["webhook_url"] = args.webhook

    build_model()
    init_files()
    load_all()

    if args.report_only:
        generate_report()
        return

    threading.Thread(target=packet_consumer, daemon=True).start()
    threading.Thread(target=incremental_training_loop, daemon=True).start()
    threading.Thread(target=inference_loop, daemon=True).start()
    threading.Thread(target=flow_cleanup_loop, daemon=True).start()
    threading.Thread(target=bandwidth_loop, daemon=True).start()
    threading.Thread(target=save_profiles_loop, daemon=True).start()
    threading.Thread(target=network_scan_loop, daemon=True).start()

    if not args.no_dashboard:
        threading.Thread(target=dashboard_loop, daemon=True).start()
    else:
        threading.Thread(target=summary_loop, daemon=True).start()

    if config["lab_mode"]:
        threading.Thread(target=lab_mode_loop, daemon=True).start()

    ok = start_multi_interface_sniffers()
    if not ok:
        logger.error("No se pudo iniciar la captura.")
        logger.info("Instala Npcap y ejecuta como Administrador.")
        return

    logger.info("Analizando todos los protocolos...")
    logger.info("Entrenamiento incremental habilitado.")
    logger.info(f"Red local: {MY_IP} -> {MY_GATEWAY}")
    if config["lab_mode"]: logger.info("Modo laboratorio habilitado.")
    if config.get("webhook_url"): logger.info("Webhook habilitado.")

    if args.web:
        threading.Thread(target=start_web_server, args=(args.web_port,), daemon=True).start()
    
    threading.Thread(target=interactive_cli, daemon=True).start()

    try:
        while not shutdown_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt: pass
    finally:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
