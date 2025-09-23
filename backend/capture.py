from scapy.all import sniff, TCP, UDP, IP 
import threading 
import time 
from typing import Callable 
from .features import FlowExtractor 
from .utils import write_csv_row
import os

class CaptureThread: 
    def __init__(self, iface: str | None, bpf_filter: str | None, callback: Callable[[dict, str, str], None]): 
        self.iface = iface 
        self.bpf_filter = bpf_filter 
        self.callback = callback 
        self.fx = FlowExtractor() 
        self._stop = threading.Event() 
        self._thr: threading.Thread | None = None 
        self._stop_flag = False
        
    def _handle_packet(self, pkt):
        try:
            ts = pkt.time
            size = len(pkt)

            # Extract basic fields
            src, dst, sport, dport, proto, flags, l7_proto = None, None, None, None, None, None, "UNKNOWN"

            if pkt.haslayer("IP"):
                ip = pkt["IP"]
                src, dst = ip.src, ip.dst
                proto = ip.proto

            if pkt.haslayer("TCP"):
                tcp = pkt["TCP"]
                sport, dport = tcp.sport, tcp.dport
                proto = "TCP"
                flags = str(tcp.flags)

                # Simple L7 guesses for TCP
                if sport == 80 or dport == 80:
                    l7_proto = "HTTP"
                elif sport == 443 or dport == 443:
                    l7_proto = "HTTPS"
                elif sport == 22 or dport == 22:
                    l7_proto = "SSH"
                elif sport == 21 or dport == 21:
                    l7_proto = "FTP"

            elif pkt.haslayer("UDP"):
                udp = pkt["UDP"]
                sport, dport = udp.sport, udp.dport
                proto = "UDP"

                # Simple L7 guesses for UDP
                if sport == 53 or dport == 53:
                    l7_proto = "DNS"
                elif sport == 123 or dport == 123:
                    l7_proto = "NTP"
                elif sport == 67 or dport == 68:
                    l7_proto = "DHCP"

            # Skip if missing required fields
            if not all([src, dst, sport, dport, proto]):
                return

            # Direction: incoming vs outgoing
            import socket
            local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
            if dst in local_ips:
                direction = "in"
            else:
                direction = "out"

            # Update flow features
            feats = self.fx.update(
                src, sport, dst, dport, proto, size, direction, flags, ts, l7_proto
            )

            if feats and self.callback:
                self.callback(feats)
                print("Captured features:", feats) # for debugging

        except Exception as e:
            print(f"Error handling packet: {e}")
 
    def start(self): 
        self._stop.clear() 
        self._thr = threading.Thread(target=self._run, daemon=True) 
        self._thr.start() 
        
    def _run(self): 
        sniff(prn=self._handle_packet, store=False, iface=self.iface, filter=self.bpf_filter, stop_filter=lambda x: self._stop.is_set()) 
        
    def stop(self): 
        self._stop.set()


# --- monkeypatch: prefer AsyncSniffer for responsive stop() if available ---
try:
    from scapy.all import AsyncSniffer
except Exception:
    AsyncSniffer = None

def _ids_start(self):
    # If AsyncSniffer exists, prefer it; otherwise fall back to existing start implementation.
    if AsyncSniffer is not None:
        if getattr(self, "_sniffer", None) and getattr(self._sniffer, "running", False):
            return
        try:
            self._sniffer = AsyncSniffer(prn=self._handle_packet, store=False, iface=self.iface, filter=self.bpf_filter)
            self._sniffer.start()
            return
        except Exception:
            # fallback to old threaded start below
            pass
    # original fallback: start thread that runs self._run()
    if getattr(self, "_thr", None) and getattr(self._thr, "is_alive", lambda: False)():
        return
    self._stop.clear()
    self._thr = threading.Thread(target=self._run, daemon=True)
    self._thr.start()

def _ids_stop(self):
    try:
        if getattr(self, "_sniffer", None):
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
    finally:
        self._stop.set()

# attach monkeypatch to the class
CaptureThread.start = _ids_start
CaptureThread.stop = _ids_stop
