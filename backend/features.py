import datetime
import time
import numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

@dataclass
class FlowState:
    """Enhanced flow state tracking with additional metrics"""
    first_ts: float
    last_ts: float
    in_pkts: int = 0
    out_pkts: int = 0
    in_bytes: int = 0
    out_bytes: int = 0
    tcp_flags_folded: str = "OTHER"
    proto: str = "OTHER"
    l7_proto: str = "UNKNOWN"

    # Enhanced metrics for better detection
    packet_sizes: list = field(default_factory=list)
    inter_arrival_times: list = field(default_factory=list)
    ttl_values: list = field(default_factory=list)
    tcp_window_sizes: list = field(default_factory=list)

    # Throughput tracking
    throughput_samples: list = field(default_factory=list)
    last_throughput_calc: float = 0

class FlowExtractor:
    """Enhanced flow extractor with two-stage compatible feature extraction"""

    def __init__(self, window_sec: float = 2.0, idle_timeout: float = 5.0):
        self.window_sec = window_sec
        self.idle_timeout = idle_timeout
        self.flows: Dict[Tuple[str,int,str,int,str], FlowState] = {}

        # Enhanced tracking for new features
        self.packet_size_buckets = {
            'up_to_128': 0,
            '128_to_256': 0,
            '256_to_512': 0,
            '512_to_1024': 0,
            '1024_to_1514': 0
        }

    def fold_tcp_flags(self, flags: str) -> str:
        """Enhanced TCP flag folding with more granular detection"""
        if not flags:
            return "OTHER"

        f = set(list(flags.upper()))

        # More specific flag combinations for better detection
        if 'S' in f and 'A' not in f:
            return "SYN"
        elif 'S' in f and 'A' in f:
            return "SYN_ACK"  
        elif 'F' in f:
            return "FIN"
        elif 'R' in f:
            return "RST"
        elif 'P' in f:
            return "PSH"
        elif 'A' in f and len(f) == 1:
            return "ACK"
        elif 'U' in f:
            return "URG"
        elif len(f) > 1:
            return "COMBINED"

        return "OTHER"

    def detect_l7_protocol(self, sport: int, dport: int, size: int) -> str:
        """Enhanced Layer 7 protocol detection"""
        # Common protocol port mappings
        protocol_ports = {
            80: "HTTP", 443: "HTTPS", 53: "DNS", 25: "SMTP",
            110: "POP3", 143: "IMAP", 21: "FTP", 22: "SSH",
            23: "TELNET", 161: "SNMP", 389: "LDAP", 636: "LDAPS",
            993: "IMAPS", 995: "POP3S", 587: "SMTP_TLS",
            3389: "RDP", 5432: "POSTGRESQL", 3306: "MYSQL",
            1433: "MSSQL", 6379: "REDIS", 27017: "MONGODB"
        }

        # Check both source and destination ports
        if sport in protocol_ports:
            return protocol_ports[sport]
        elif dport in protocol_ports:
            return protocol_ports[dport]

        # Heuristic-based detection
        if size < 100 and (sport == 53 or dport == 53):
            return "DNS"
        elif size > 1000 and (sport in [80, 443] or dport in [80, 443]):
            return "HTTP_LARGE"
        elif sport > 1024 and dport > 1024:
            return "P2P_LIKE"

        return "UNKNOWN"

    def categorize_packet_size(self, size: int) -> str:
        """Categorize packet sizes for enhanced feature extraction"""
        if size <= 128:
            return 'up_to_128'
        elif size <= 256:
            return '128_to_256'
        elif size <= 512:
            return '256_to_512'
        elif size <= 1024:
            return '512_to_1024'
        else:
            return '1024_to_1514'

    def calculate_throughput(self, flow_state: FlowState, current_ts: float) -> Dict[str, float]:
        """Calculate bidirectional throughput metrics"""
        duration = current_ts - flow_state.first_ts
        if duration <= 0:
            return {'src_to_dst_avg_throughput': 0.0, 'dst_to_src_avg_throughput': 0.0}

        # Simple bidirectional throughput (bytes/second)
        src_to_dst_throughput = flow_state.out_bytes / duration if duration > 0 else 0
        dst_to_src_throughput = flow_state.in_bytes / duration if duration > 0 else 0

        return {
            'src_to_dst_avg_throughput': src_to_dst_throughput,
            'dst_to_src_avg_throughput': dst_to_src_throughput
        }

    def update(self, src: str, sport: int, dst: str, dport: int, proto: str, 
               size: int, direction: str, flags: str = None, ts: float = None,
               l7_proto: str = "UNKNOWN", ttl: int = None, 
               tcp_window: int = None) -> Optional[Dict[str, float]]:
        """Enhanced update with additional feature extraction"""

        if ts is None:
            ts = time.time()

        key = (src, sport, dst, dport, proto)
        st = self.flows.get(key)

        if not st:
            st = FlowState(
                first_ts=ts, 
                last_ts=ts, 
                proto=proto.upper(),
                l7_proto=self.detect_l7_protocol(sport, dport, size)
            )
            self.flows[key] = st

        # Update basic metrics
        st.last_ts = ts

        if direction == "in":
            st.in_pkts += 1
            st.in_bytes += size
        else:
            st.out_pkts += 1
            st.out_bytes += size

        # Enhanced metrics collection
        st.packet_sizes.append(size)
        if len(st.inter_arrival_times) > 0:
            iat = ts - st.last_ts
            st.inter_arrival_times.append(iat)

        if ttl:
            st.ttl_values.append(ttl)

        if tcp_window:
            st.tcp_window_sizes.append(tcp_window)

        if flags:
            st.tcp_flags_folded = self.fold_tcp_flags(flags)

        # Check if flow is complete or timed out
        duration = st.last_ts - st.first_ts
        if duration >= self.window_sec or (ts - st.last_ts) > self.idle_timeout:
            return self._extract_features(key, st, ts)

        return None

    def _extract_features(self, key: Tuple, st: FlowState, ts: float) -> Dict[str, float]:
        """Extract comprehensive feature set for two-stage detection"""
        src, sport, dst, dport, proto = key
        duration = max(st.last_ts - st.first_ts, 0.001)  # Avoid division by zero

        # Original features (maintain compatibility)
        features = {
            'SRC_IP': src,
            'DST_IP': dst,
            'PROTOCOL': st.proto,
            'L4_SRC_PORT': sport,
            'L4_DST_PORT': dport,
            'IN_BYTES': st.in_bytes,
            'IN_PKTS': st.in_pkts,
            'OUT_BYTES': st.out_bytes,
            'OUT_PKTS': st.out_pkts,
            'FLOW_DURATION_MILLISECONDS': duration * 1000,
            'TCP_FLAGS': st.tcp_flags_folded,
            'TIMESTAMP': ts
        }

        # Enhanced features for better accuracy
        features.update({
            'L7_PROTO': st.l7_proto,
            'SRC_TO_DST_AVG_THROUGHPUT': st.out_bytes / duration if duration > 0 else 0,
            'DST_TO_SRC_AVG_THROUGHPUT': st.in_bytes / duration if duration > 0 else 0,
        })

        # Packet size distribution features
        size_categories = {'up_to_128': 0, '128_to_256': 0, '256_to_512': 0, 
                          '512_to_1024': 0, '1024_to_1514': 0}
        for size in st.packet_sizes:
            category = self.categorize_packet_size(size)
            size_categories[category] += 1

        features['NUM_PKTS_UP_TO_128_BYTES'] = size_categories['up_to_128']

        # TTL analysis
        if st.ttl_values:
            features.update({
                'MIN_TTL': min(st.ttl_values),
                'MAX_TTL': max(st.ttl_values),
            })
        else:
            features.update({'MIN_TTL': 0, 'MAX_TTL': 0})

        # Inter-arrival time analysis
        if st.inter_arrival_times:
            features.update({
                'SRC_TO_DST_IAT_AVG': np.mean(st.inter_arrival_times),
                'DST_TO_SRC_IAT_AVG': np.mean(st.inter_arrival_times),  # Simplified
            })
        else:
            features.update({'SRC_TO_DST_IAT_AVG': 0, 'DST_TO_SRC_IAT_AVG': 0})

        # Clean up completed flow
        del self.flows[key]

        return features

    def reap_idle(self):
        """Clean up idle flows"""
        now = time.time()
        idle = [k for k, v in self.flows.items() if (now - v.last_ts) > self.idle_timeout]
        for k in idle:
            del self.flows[k]
