from scapy.all import sniff, TCP, UDP, IP 
import threading 
import time 
from typing import Callable 
from .features import FlowExtractor 

class CaptureThread: 
    def __init__(self, iface: str | None, bpf_filter: str | None, callback: Callable[[dict, str, str], None]): 
        self.iface = iface 
        self.bpf_filter = bpf_filter 
        self.callback = callback 
        self.fx = FlowExtractor() 
        self._stop = threading.Event() 
        self._thr: threading.Thread | None = None 
        
    def _handle_packet(self, pkt): 
        ts = time.time() 
        if IP not in pkt: 
            return 
        ip = pkt[IP] 
        src = ip.src 
        dst = ip.dst 
        size = len(pkt) 
        if TCP in pkt: 
            sport = int(pkt[TCP].sport) 
            dport = int(pkt[TCP].dport) 
            flags = pkt[TCP].flags.flagrepr() if hasattr(pkt[TCP].flags, 'flagrepr') else str(pkt[TCP].flags) 
            feats = self.fx.update(src, sport, dst, dport, 'TCP', size, flags, ts) 
        elif UDP in pkt: 
            sport = int(pkt[UDP].sport) 
            dport = int(pkt[UDP].dport) 
            feats = self.fx.update(src, sport, dst, dport, 'UDP', size, None, ts) 
        else: 
            # skip non TCP/UDP 
            return 
        if feats: 
            self.callback(feats, src, dst) 
            self.fx.reap_idle() 
            
    def start(self): 
        self._stop.clear() 
        self._thr = threading.Thread(target=self._run, daemon=True) 
        self._thr.start() 
        
    def _run(self): 
        sniff(prn=self._handle_packet, store=False, iface=self.iface, filter=self.bpf_filter, stop_filter=lambda x: self._stop.is_set()) 
        
    def stop(self): 
        self._stop.set()