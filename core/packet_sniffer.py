"""Real-time packet capture and analysis (Scapy) with BPF filter support."""
import threading
from datetime import datetime

from . import utils

try:
    from scapy.all import sniff
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

TCP_FLAG_NAMES = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK",
                  "U": "URG", "E": "ECE", "C": "CWR"}
ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
              8: "Echo Request", 11: "Time Exceeded", 30: "Traceroute"}


class ProfessionalPacketSniffer:
    """Layered protocol dissection with live stats and BPF filters."""

    def __init__(self, output_callback=None):
        self.output_callback = output_callback
        self.available = SCAPY_OK and self._check_permissions()
        self.is_sniffing = False
        self.captured = []
        self.protocol_stats = {}
        self._thread = None
        self._stop = threading.Event()

    @staticmethod
    def _check_permissions():
        """Linux requires root for raw sockets; degrade gracefully."""
        try:
            import getpass
            return getpass.getuser() == "root"
        except Exception:
            return False

    def log(self, message, level="info"):
        if self.output_callback:
            self.output_callback(message, level)

    def start_sniffing(self, count=50, timeout=30, filter_exp=None, interface=None, async_mode=True):
        if not SCAPY_OK:
            self.log("Scapy is not installed - packet sniffer disabled.", "error")
            return []
        if not self._check_permissions():
            self.log("Packet capture needs admin/root privileges. On Windows run as Administrator, "
                     "on Linux use sudo.", "warning")
        self.log(f"Starting capture (count={count}, timeout={timeout}s, "
                 f"filter={filter_exp or 'None'}, interface={interface or 'default'})", "info")
        self._stop.clear()
        self.captured = []
        self.protocol_stats = {}
        packets = []

        def process(pkt):
            info = self._analyze(pkt)
            packets.append(info)
            self.captured.append(info)
            proto = info.get("protocol", "Other")
            self.protocol_stats[proto] = self.protocol_stats.get(proto, 0) + 1
            self.output_callback(self._format(info, len(packets)), "info")

        def run():
            kwargs = {"prn": process, "count": count, "store": False, "timeout": timeout}
            if filter_exp and filter_exp.strip():
                kwargs["filter"] = filter_exp.strip()
            if interface:
                kwargs["iface"] = interface
            try:
                sniff(**kwargs)
            except Exception as exc:
                self.log(f"Capture error: {exc}", "error")
            finally:
                self.is_sniffing = False
                self.log("\nCapture finished.", "info")
                self._summary()

        self.is_sniffing = True
        if async_mode:
            self._thread = threading.Thread(target=run, daemon=True)
            self._thread.start()
            return packets
        run()
        return packets

    def stop_sniffing(self):
        self.is_sniffing = False
        self._stop.set()
        self.log("Capture stopped by user.", "warning")

    def _analyze(self, pkt):
        info = {"timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "summary": pkt.summary()[:120], "raw_length": len(pkt), "layers": []}
        layer, depth = pkt, 0
        while layer is not None and depth < 5:
            entry = {"name": layer.name}
            for attr in ("src", "dst", "sport", "dport"):
                if hasattr(layer, attr):
                    entry[attr] = getattr(layer, attr)
            info["layers"].append(entry)
            layer = layer.payload if hasattr(layer, "payload") else None
            depth += 1
        if pkt.haslayer(IP):
            ip = pkt["IP"]
            info["src_ip"], info["dst_ip"], info["ttl"] = ip.src, ip.dst, ip.ttl
        if pkt.haslayer(Ether):
            eth = pkt["Ether"]
            info["src_mac"], info["dst_mac"] = eth.src, eth.dst
        if pkt.haslayer(TCP):
            t = pkt["TCP"]
            info.update(protocol="TCP", src_port=t.sport, dst_port=t.dport,
                        flags=", ".join(TCP_FLAG_NAMES.get(c, c) for c in str(t.flags)) or "None",
                        seq=t.seq, ack=t.ack)
        elif pkt.haslayer(UDP):
            u = pkt["UDP"]
            info.update(protocol="UDP", src_port=u.sport, dst_port=u.dport, length=u.len)
        elif pkt.haslayer(ICMP):
            i = pkt["ICMP"]
            info.update(protocol="ICMP", icmp_type=i.type, code=i.code,
                        type_desc=ICMP_TYPES.get(i.type, f"Unknown ({i.type})"))
        elif pkt.haslayer(ARP):
            a = pkt["ARP"]
            info.update(protocol="ARP", op=a.op, src_ip=a.psrc, dst_ip=a.pdst, src_mac=a.hwsrc, dst_mac=a.hwdst)
        else:
            info["protocol"] = f"Other"
        return info

    def _format(self, info, num):
        sep = "─" * 78
        out = f"\n{sep}\nPACKET #{num:03d} | Time: {info['timestamp']} | Length: {info['raw_length']} B\n{sep}\n"
        if "src_ip" in info and "dst_ip" in info:
            sp = f":{info['src_port']}" if info.get("src_port") else ""
            dp = f":{info['dst_port']}" if info.get("dst_port") else ""
            out += f"NETWORK: {info['src_ip']}{sp} -> {info['dst_ip']}{dp}\n"
        if "src_mac" in info and "dst_mac" in info:
            out += f"MAC: {info['src_mac'][:17]} -> {info['dst_mac'][:17]}\n"
        proto = info.get("protocol", "Other")
        out += f"PROTOCOL: {proto}\n"
        if proto == "TCP":
            out += f"FLAGS: {info.get('flags')} | SEQ: {info.get('seq')} | ACK: {info.get('ack')}\n"
        elif proto == "ICMP":
            out += f"TYPE: {info.get('icmp_type')} ({info.get('type_desc')}) | CODE: {info.get('code')}\n"
        elif proto == "ARP":
            out += f"OP: {'Request' if info.get('op') == 1 else 'Reply' if info.get('op') == 2 else info.get('op')}\n"
        if info["layers"]:
            out += f"LAYERS ({len(info['layers'])}): " + " > ".join(l["name"].upper() for l in info["layers"]) + "\n"
        out += f"SUMMARY: {info['summary']}"
        return out

    def _summary(self):
        if not self.captured:
            self.log("No packets captured.", "error")
            return
        total = len(self.captured)
        size = sum(p["raw_length"] for p in self.captured)
        self.log("\n" + "=" * 60, "info")
        self.log("CAPTURE SUMMARY", "info")
        self.log("=" * 60, "info")
        self.log(f"Total packets: {total} | Total data: {utils.fmt_size(size)}", "success")
        self.log("\nPROTOCOL DISTRIBUTION:", "info")
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: -x[1]):
            pct = count / total * 100
            bar = "█" * int(pct / 5)
            self.log(f"  {proto:8} {count:5,} {pct:6.1f}% {bar}", "info")
        srcs = {p.get("src_ip") for p in self.captured if p.get("src_ip")}
        dsts = {p.get("dst_ip") for p in self.captured if p.get("dst_ip")}
        for label, ips in (("UNIQUE SOURCE IPs", srcs), ("UNIQUE DESTINATION IPs", dsts)):
            self.log(f"\n{label}: {len(ips)}", "info")
            if len(ips) <= 12:
                for ip in sorted(ips):
                    self.log(f"  • {ip}", "info")
