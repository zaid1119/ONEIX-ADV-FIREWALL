from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP
import datetime

# --- CONFIGURATION (The Rule Engine) ---
# You can update these lists without touching the core logic
BLACKLIST_IPS = ["8.8.8.8", "1.1.1.1"]
BLOCKED_PORTS = [22, 23, 445, 3389]  # SSH, Telnet, SMB, RDP
LOG_FILE = "firewall_activity.log"

def log_event(message):
    """Saves security events to a text file with a timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def process_packet(packet):
    """The 'Brain' of the firewall sitting in the INPUT chain."""
    # Convert raw payload to a Scapy IP Packet (Layer 3)
    scapy_packet = IP(packet.get_payload())
    src_ip = scapy_packet.src
    dst_ip = scapy_packet.dst

    # 1. LAYER 3 CHECK: IP Filtering
    if src_ip in BLACKLIST_IPS:
        msg = f"BLOCK L3: Dropped packet from Blacklisted IP: {src_ip}"
        print(f"[!] {msg}")
        log_event(msg)
        return packet.drop()

    # 2. LAYER 4 CHECK: Port & Protocol Filtering
    if scapy_packet.haslayer(TCP):
        dport = scapy_packet[TCP].dport
        if dport in BLOCKED_PORTS:
            msg = f"BLOCK L4: TCP Connection to Blocked Port {dport} from {src_ip}"
            print(f"[!] {msg}")
            log_event(msg)
            return packet.drop()
        elif dport == 80 or dport == 443:
            print(f"[*] ALLOW: Web traffic passing to {dst_ip}")

    # 3. ICMP CHECK (Ping)
    if scapy_packet.haslayer(ICMP):
        print(f"[*] ICMP: Ping detected from {src_ip}")

    # DEFAULT ACTION: If it doesn't match a block rule, let it through
    packet.accept()

# --- INITIALIZATION ---
nfqueue = NetfilterQueue()
nfqueue.bind(1, process_packet)

try:
    print("=========================================")
    print("   ONEIX ADVANCED LAYER 3/4 FIREWALL    ")
    print("=========================================")
    print(f"[*] Monitoring Queue 1...")
    print(f"[*] Logs saving to: {LOG_FILE}")
    nfqueue.run()
except KeyboardInterrupt:
    print("\n[!] Stopping Firewall...")
    nfqueue.unbind()
