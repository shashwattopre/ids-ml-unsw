# backend/capture.py
from scapy.all import sniff, TCP, UDP, IP, get_if_list, get_if_hwaddr
import threading
import time
from typing import Callable, Optional
from .features import FlowExtractor
import traceback

# Global capture thread reference
_capture_thread: Optional["CaptureThread"] = None


class CaptureThread:
    def __init__(self, iface: str | None, bpf_filter: str | None,
                 callback: Callable[[dict, str, str], None]):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.callback = callback
        self.fx = FlowExtractor()
        self._stop = threading.Event()
        self._thr: threading.Thread | None = None

    def _handle_packet(self, pkt):
        try:
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
                flags = (
                    pkt[TCP].flags.flagrepr()
                    if hasattr(pkt[TCP].flags, "flagrepr")
                    else str(pkt[TCP].flags)
                )
                feats = self.fx.update(src, sport, dst, dport, "TCP", size, flags, ts)
            elif UDP in pkt:
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
                feats = self.fx.update(src, sport, dst, dport, "UDP", size, None, ts)
            else:
                return
            if feats:
                try:
                    self.callback(feats, src, dst)
                except Exception:
                    # ensure callback exceptions don't stop capture loop
                    print("Callback error:", traceback.format_exc())
                self.fx.reap_idle()
        except Exception:
            # defensive: print and continue
            print("Packet handling error:", traceback.format_exc())

    def start(self):
        self._stop.clear()
        self._thr = threading.Thread(target=self._run, daemon=True)
        self._thr.start()

    def _run(self):
        try:
            sniff(
                prn=self._handle_packet,
                store=False,
                iface=self.iface,
                filter=self.bpf_filter,
                stop_filter=lambda x: self._stop.is_set(),
            )
        except OSError as e:
            # Likely Windows adapter open error or permission issues
            print(f"[capture] OSError when opening iface '{self.iface}': {e}")
            raise
        except Exception:
            print("[capture] Unexpected error in sniff thread:\n", traceback.format_exc())
            raise

    def stop(self):
        self._stop.set()


# ---- Public API functions for backend/app.py ----

def list_interfaces():
    """Return a list of available interfaces (scapy ids). We'll also attempt to map to friendly names."""
    scapy_ifaces = []
    try:
        scapy_ifaces = get_if_list()
    except Exception:
        # fallback empty
        scapy_ifaces = []

    # Build a map of MAC address -> psutil friendly name (via net_if_addrs)
    # Doing this locally avoids importing psutil here; we'll try best-effort using scapy.get_if_hwaddr
    friendly_map = {}
    try:
        # For each scapy iface try to get its hwaddr and use that as mapping key
        for iface in scapy_ifaces:
            try:
                mac = get_if_hwaddr(iface)
                if mac and mac != "00:00:00:00:00:00":
                    friendly_map[iface] = {"id": iface, "name": iface, "mac": mac}
                else:
                    friendly_map[iface] = {"id": iface, "name": iface, "mac": None}
            except Exception:
                friendly_map[iface] = {"id": iface, "name": iface, "mac": None}
    except Exception:
        # fallback: just list scapy names
        return [{"id": iface, "name": iface} for iface in scapy_ifaces]

    # Attempt to augment names using platform-level interfaces via psutil if available
    try:
        import psutil
        ps_addrs = psutil.net_if_addrs()
        # create mac -> psutil name mapping
        mac_to_name = {}
        for name, addrs in ps_addrs.items():
            for a in addrs:
                if getattr(a, "family", None) is not None:
                    # MAC addresses typically appear as 'AF_LINK' or psutil.AF_LINK
                    if hasattr(a, "address") and a.address and (len(a.address) == 17 or ":" in a.address):
                        mac_to_name[a.address.lower()] = name

        out = []
        for iface, meta in friendly_map.items():
            mac = meta.get("mac")
            display = meta["id"]
            if mac:
                n = mac_to_name.get(mac.lower())
                if n:
                    display = f"{n} ({iface})"
            out.append({"id": meta["id"], "name": display})
        return out
    except Exception:
        # If psutil not available, return scapy mapping
        return [{"id": meta["id"], "name": meta["name"]} for meta in friendly_map.values()]


def start_capture(iface: str, bpf_filter: str | None = None):
    """Start a global capture thread. iface should be the scapy iface id (returned from list_interfaces)."""
    global _capture_thread
    if _capture_thread is not None:
        raise RuntimeError("Capture already running")

    # Example callback: write to backend/data/logs.csv or integrate with storage.py
    def handle_flow(features, src, dst):
        # Example: print for now (you should call storage.write_log or classifiers etc.)
        print(f"[CAPTURE] {src} -> {dst} : {features}")

    # Try to start capture, but provide helpful errors
    try:
        _capture_thread = CaptureThread(iface, bpf_filter, handle_flow)
        _capture_thread.start()
        return True
    except OSError as e:
        # Common on Windows: adapter open error (wrong name or permissions)
        _capture_thread = None
        raise RuntimeError(f"Failed to open interface '{iface}': {e}. "
                           "On Windows ensure Npcap is installed and you're using the scapy interface id. "
                           "Try running backend with admin privileges.") from e
    except Exception as e:
        _capture_thread = None
        raise


def stop_capture():
    """Stop the global capture thread."""
    global _capture_thread
    if _capture_thread is None:
        raise RuntimeError("No capture running")
    try:
        _capture_thread.stop()
        _capture_thread = None
        return True
    except Exception as e:
        raise
