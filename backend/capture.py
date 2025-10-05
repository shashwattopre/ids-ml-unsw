# Fixed capture.py - COMPLETE WORKING VERSION

from scapy.all import sniff, AsyncSniffer, TCP, UDP, IP
import threading
import time
import logging
from typing import Callable
from .features import FlowExtractor
import os
import psutil

logger = logging.getLogger(__name__)

class CaptureThread:
    def __init__(self, iface: str = None, bpffilter: str = None, callback: Callable[[dict], str] = None):
        self.iface = iface
        self.bpffilter = bpffilter
        self.callback = callback
        
        # Initialize flow extractor
        self.fx = FlowExtractor()
        self.stop_flag = False
        self.stop = threading.Event()
        self.thr = threading.Thread()
        self.sniffer = None
        self.local_ips = set()
        
        # Get local IP addresses for traffic direction detection
        self.update_local_ips()
    
    def update_local_ips(self):
        """Get local IP addresses for traffic direction detection"""
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == 2:  # IPv4
                        self.local_ips.add(addr.address)
        except Exception as e:
            logger.warning(f"Could not get local IPs: {e}")
        self.local_ips.add("127.0.0.1")  # Always add localhost
    
    def extract_packet_info(self, pkt) -> tuple:
        """Enhanced packet information extraction"""
        try:
            if IP in pkt:
                ip_layer = pkt[IP]
                src, dst = ip_layer.src, ip_layer.dst
                proto = ip_layer.proto
                size = len(pkt)
                ttl = ip_layer.ttl
                
                sport = dport = 0
                flags = None
                tcp_window = None
                
                if TCP in pkt:
                    tcp_layer = pkt[TCP]
                    sport, dport = tcp_layer.sport, tcp_layer.dport
                    flags = str(tcp_layer.flags)
                    tcp_window = tcp_layer.window
                    proto_name = "TCP"
                elif UDP in pkt:
                    udp_layer = pkt[UDP]
                    sport, dport = udp_layer.sport, udp_layer.dport
                    proto_name = "UDP"
                else:
                    proto_name = f"IP-{proto}"
                
                return (src, sport, dst, dport, proto_name, size, flags, ttl, tcp_window)
        except Exception as e:
            logger.debug(f"Packet parsing error: {e}")
        return None
    
    def handle_packet(self, pkt):
        """Enhanced packet handling with additional features"""
        try:
            packet_info = self.extract_packet_info(pkt)
            if not packet_info:
                return
                
            src, sport, dst, dport, proto, size, flags, ttl, tcp_window = packet_info
            
            # Determine direction
            direction = "unknown"
            if src in self.local_ips:
                direction = "outgoing"
            elif dst in self.local_ips:
                direction = "incoming"
            
            ts = time.time()
            
            # Update flow extractor with enhanced features
            feats = self.fx.update(
                src=src, sport=sport, dst=dst, dport=dport, proto=proto,
                size=size, direction=direction, flags=flags, ts=ts,
                ttl=ttl, tcp_window=tcp_window
            )
            
            if feats and self.callback:
                self.callback(feats)
                logger.debug(f"Captured enhanced features: {len(feats)} fields")
                
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
    
    def start(self):
        """Start enhanced packet capture"""
        self.stop.clear()
        
        # Try AsyncSniffer first (non-blocking)
        try:
            self.sniffer = AsyncSniffer(
                prn=self.handle_packet,
                store=False,
                iface=self.iface,
                filter=self.bpffilter
            )
            self.sniffer.start()
            logger.info(f"Started enhanced async packet capture on {self.iface}")
            return
        except Exception as e:
            logger.warning(f"AsyncSniffer failed: {e}, falling back to threaded capture")
        
        # Fallback to threaded capture
        self.thr = threading.Thread(target=self.run, daemon=True)
        self.thr.start()
        logger.info(f"Started enhanced threaded packet capture on {self.iface}")
    
    def run(self):
        """Threaded packet capture loop"""
        try:
            sniff(
                prn=self.handle_packet,
                store=False,
                iface=self.iface,
                filter=self.bpffilter,
                stop_filter=lambda x: self.stop.is_set()
            )
        except Exception as e:
            logger.error(f"Capture thread error: {e}")
    
    def stop_capture(self):
        """Stop packet capture"""
        try:
            if self.sniffer:
                try:
                    self.sniffer.stop()
                except Exception:
                    pass
                self.sniffer = None
            
            self.stop.set()
            if self.thr and self.thr.is_alive():
                self.thr.join(timeout=2)
            
            logger.info("Enhanced packet capture stopped")
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")
    
    def is_running(self) -> bool:
        """Check if capture is running"""
        if self.sniffer:
            return getattr(self.sniffer, 'running', False)
        return self.thr and self.thr.is_alive() if self.thr else False

def list_interfaces():
    """List available network interfaces"""
    try:
        return list(psutil.net_if_addrs().keys())
    except Exception as e:
        logger.error(f"Failed to list interfaces: {e}")
        return ["eth0", "wlan0", "lo"]  # Common defaults