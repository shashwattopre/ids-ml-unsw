import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Tuple

@dataclass
class FlowState:
    first_ts: float
    last_ts: float
    in_pkts: int = 0
    out_pkts: int = 0
    in_bytes: int = 0
    out_bytes: int = 0
    tcp_flags_folded: str = 'OTHER'
    proto: str = 'OTHER'
    l7_proto: str = 'UNKNOWN'

class FlowExtractor:
    def __init__(self, window_sec: float = 2.0, idle_timeout: float = 5.0):
        self.window_sec = window_sec
        self.idle_timeout = idle_timeout
        self.flows: Dict[Tuple[str,int,str,int,str], FlowState] = {}

    def _fold_tcp_flags(self, flags: str) -> str:
        f = set(list(flags.upper()))
        if {'S'} <= f and 'A' not in f:
            return 'SYN'
        if 'F' in f:
            return 'FIN'
        if 'R' in f:
            return 'RST'
        if 'P' in f:
            return 'PSH'
        if 'A' in f:
            return 'ACK'
        return 'OTHER'

    def update(self, src: str, sport: int, dst: str, dport: int,
               proto: str, size: int, direction: str,
               flags: str | None, ts: float, l7_proto: str = 'UNKNOWN') -> Dict[str, float] | None:

        key = (src, sport, dst, dport, proto)
        st = self.flows.get(key)
        if not st:
            st = FlowState(first_ts=ts, last_ts=ts, proto=proto.upper(), l7_proto=l7_proto)
            self.flows[key] = st

        st.last_ts = ts
        if direction == 'in':
            st.in_pkts += 1
            st.in_bytes += size
        else:
            st.out_pkts += 1
            st.out_bytes += size

        if flags:
            st.tcp_flags_folded = self._fold_tcp_flags(flags)

        dur = max((st.last_ts - st.first_ts) * 1000.0, 1e-3)  # ms
        if dur >= self.window_sec * 1000:
            feats = {
                'PROTOCOL': st.proto,
                'L7_PROTO': st.l7_proto,
                'L4_SRC_PORT': int(sport),
                'L4_DST_PORT': int(dport),
                'IN_BYTES': int(st.in_bytes),
                'IN_PKTS': int(st.in_pkts),
                'OUT_BYTES': int(st.out_bytes),
                'OUT_PKTS': int(st.out_pkts),
                'TCP_FLAGS': st.tcp_flags_folded,
                'FLOW_DURATION_MILLISECONDS': float(dur),
            }
            # reset counters
            st.first_ts = ts
            st.in_pkts = st.out_pkts = 0
            st.in_bytes = st.out_bytes = 0
            return feats
        return None

    def reap_idle(self):
        now = time.time()
        idle = [k for k,v in self.flows.items() if (now - v.last_ts) > self.idle_timeout]
        for k in idle:
            del self.flows[k]
