# frontend/streamlit_app.py
import streamlit as st
import requests
import pandas as pd
import time
import io
import json
import altair as alt
from datetime import datetime, timezone
import os

BACKEND_URL = "http://localhost:8000"

st.set_page_config(page_title="IDS Dashboard", layout="wide", initial_sidebar_state="auto")

# ---------- Helper functions to call backend ----------
def get_interfaces():
    try:
        r = requests.get(f"{BACKEND_URL}/interfaces", timeout=3)
        r.raise_for_status()
        return r.json().get("interfaces", [])
    except Exception:
        return []

def start_capture(interface: str):
    try:
        r = requests.post(f"{BACKEND_URL}/capture/start", json={"interface": interface}, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def stop_capture():
    try:
        r = requests.post(f"{BACKEND_URL}/capture/stop", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def fetch_logs(limit=100):
    try:
        r = requests.get(f"{BACKEND_URL}/logs/recent", params={"limit": limit}, timeout=5)
        r.raise_for_status()
        return r.json().get("logs", [])
    except Exception:
        return []

def fetch_alerts(limit=100):
    try:
        r = requests.get(f"{BACKEND_URL}/alerts/recent", params={"limit": limit}, timeout=5)
        r.raise_for_status()
        return r.json().get("alerts", [])
    except Exception:
        return []

def get_status():
    try:
        r = requests.get(f"{BACKEND_URL}/status", timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {"ok": False, "error": "Backend unreachable"}

# ---------- Sidebar: controls & settings ----------
st.sidebar.header("IDS Controls")
interfaces = get_interfaces()
selected_iface = st.sidebar.selectbox("Network Interface", options=["(none)"] + interfaces)

col1, col2 = st.sidebar.columns(2)
if col1.button("Start"):
    if selected_iface and selected_iface != "(none)":
        res = start_capture(selected_iface)
        if res.get("error"):
            st.sidebar.error(f"Start failed: {res['error']}")
        else:
            st.sidebar.success("Capture started")
    else:
        st.sidebar.error("Select an interface first")

if col2.button("Stop"):
    res = stop_capture()
    if res.get("error"):
        st.sidebar.error(f"Stop failed: {res['error']}")
    else:
        st.sidebar.success("Capture stopped")

st.sidebar.markdown("---")
st.sidebar.header("Export / Settings")
export_format = st.sidebar.selectbox("Export alerts as", ["CSV", "JSON"])
export_btn = st.sidebar.button("Export current alerts")

alert_threshold = st.sidebar.slider("Alert threshold (sensitivity)", 0, 100, 50)
logging_pref = st.sidebar.selectbox("Logging", ["File + DB", "DB only", "File only"])

st.sidebar.markdown("**n8n / Mongo**")
st.sidebar.write("n8n & Mongo should be running (backend will forward logs).")

# ---------- Main layout ----------
st.title("IDS Dashboard (Streamlit)")
tabs = st.tabs(["Live Traffic", "Security Alerts", "Traffic Stats", "System Analysis", "Settings"])

# ---------- Live Traffic Tab ----------
with tabs[0]:
    st.subheader("Live Traffic (most recent flows)")
    limit = st.number_input("Rows to show", min_value=10, max_value=5000, value=500, step=10)
    col1, col2 = st.columns([1, 1])

    with col1:
        auto_refresh = st.checkbox("Auto Refresh (1s)", value=True)

    with col2:
        if st.button("Clear Logs"):
            import requests
            try:
                resp = requests.post("http://localhost:8000/logs/clear")
                if resp.status_code == 200:
                    st.success("Logs cleared!")
                else:
                    st.error("Failed to clear logs.")
            except Exception as e:
                st.error(f"Error: {e}")
                
    placeholder = st.empty()

    # poll and display
    def render_logs_frame():
        logs = fetch_logs(limit=int(limit))
        if not logs:
            placeholder.info("No logs available (backend may not be running or no traffic).")
            return

        df = pd.DataFrame(logs)

        # normalize timestamp if present
        if "FLOW_START_MILLISECONDS" in df.columns:
            df["time"] = pd.to_datetime(df["FLOW_START_MILLISECONDS"], unit="ms", errors="coerce")
        elif "timestamp" in df.columns:
            df["time"] = pd.to_datetime(df["timestamp"], errors="coerce")
        else:
            df["time"] = pd.NaT

        # select useful columns
        cols = [c for c in ["TIME", "SRC_IP", "DST_IP", "PROTOCOL", "L7_PROTO",
                            "L4_SRC_PORT", "L4_DST_PORT", "IN_BYTES", "OUT_BYTES", "TCP_FLAGS", "DIRECTION"]
                if c in df.columns]

        # show table
        with placeholder.container():
            st.dataframe(df[cols].head(limit), width="stretch")

    render_logs_frame()
    if auto_refresh:
        time.sleep(1)
        render_logs_frame()
    else:
        if st.button("Refresh Dashboard"):
            st.rerun()

# ---------- Security Alerts Tab ----------
with tabs[1]:
    st.subheader("Security Alerts")
    a_limit = st.number_input("Alerts to show", min_value=5, max_value=1000, value=200)
    alerts_placeholder = st.empty()

    def render_alerts():
        alerts = fetch_alerts(limit=int(a_limit))
        if not alerts:
            alerts_placeholder.info("No alerts yet.")
            return
        adf = pd.DataFrame(alerts)
        #print(alerts)   #for debugging only


        # show key columns if exist
        cols = [c for c in ["TIME", "SRC_IP", "DST_IP", "PROTOCOL", 'FLOW_DURATION_MILLISECONDS', 'MALICIOUS_PROB'] if c in adf.columns]
        alerts_placeholder.dataframe(adf[cols].sort_values(by="TIME", ascending=False).head(500), width="stretch")

    render_alerts()

    if export_btn:
        alerts = fetch_alerts(limit=10000)
        if export_format == "CSV":
            csv_bytes = pd.DataFrame(alerts).to_csv(index=False).encode("utf-8")
            st.download_button("Download alerts.csv", csv_bytes, file_name="alerts.csv", mime="text/csv")
        else:
            json_bytes = json.dumps(alerts, indent=2).encode("utf-8")
            st.download_button("Download alerts.json", json_bytes, file_name="alerts.json", mime="application/json")

# ---------- Traffic Stats Tab ----------
with tabs[2]:
    st.subheader("Traffic Statistics")
    stats = get_status().get("stats", {})
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total flows (since start)", stats.get("total_flows", "—"))
    col2.metric("Total alerts", stats.get("total_alerts", "—"))
    col3.metric("Avg throughput (bps)", stats.get("avg_bps", "—"))
    col4.metric("Uptime (s)", stats.get("uptime", "—"))

    # small bar chart: alerts by severity
    alerts = fetch_alerts(limit=1000)
    adf = pd.DataFrame(alerts)
    if alerts:
        if "severity" in adf.columns:
            sev = adf["severity"].value_counts().reset_index()
            sev.columns = ["severity", "count"]
            bar = alt.Chart(sev).mark_bar().encode(x="severity", y="count")
            st.altair_chart(bar, use_container_width=True)

    # Protocol distribution
    if "PROTOCOL" in adf.columns:
        proto_counts = adf["PROTOCOL"].value_counts().reset_index()
        proto_counts.columns = ["PROTOCOL", "count"]
    else:
        proto_counts = pd.DataFrame(columns=["PROTOCOL", "count"])

    if not proto_counts.empty:
        proto_chart = alt.Chart(proto_counts).mark_arc().encode(
            theta="count",
            color="PROTOCOL",
            tooltip=["PROTOCOL", "count"]
        )
        st.altair_chart(proto_chart, use_container_width=True)
    else:
        st.info("No protocol distribution data yet.")

    # L7 Proto distribution
    if "L7_PROTO" in adf.columns:
        l7_counts = adf["L7_PROTO"].value_counts().reset_index()
        l7_counts.columns = ["L7 Proto", "count"]

        l7_chart = alt.Chart(l7_counts).mark_arc().encode(
            theta="count",
            color="L7 Proto",
            tooltip=["L7 Proto", "count"]
        )
        st.altair_chart(l7_chart, use_container_width=True)

    # Normal vs Alerts pie chart
    alerts = pd.read_csv("./backend/data/alerts.csv") if os.path.exists("./backend/data/alerts.csv") else pd.DataFrame()

    alert_count = len(alerts)
    normal_count = len(adf) - alert_count
    dist_df = pd.DataFrame({
        "Category": ["Normal Traffic", "Alerts"],
        "Count": [normal_count, alert_count]
    })

    alert_chart = alt.Chart(dist_df).mark_arc().encode(
        theta="Count",
        color="Category",
        tooltip=["Category", "Count"]
    )
    st.altair_chart(alert_chart, use_container_width=True)

# ---------- System Analysis Tab ----------
with tabs[3]:
    st.subheader("System Analysis")
    status = get_status()
    if not status.get("ok", False):
        st.error(f"Backend status: not OK — {status.get('error')}")
    else:
        st.success("Backend reachable")
        st.markdown("**Model**")
        st.write(f"Model path: {status.get('model_path')}")
        st.write(f"Model loaded: {status.get('model_loaded')}")
        st.markdown("**n8n / Mongo**")
        st.write(f"n8n reachable: {status.get('n8n_ok')}")
        st.write(f"Mongo reachable: {status.get('mongo_ok')}")

st.sidebar.markdown("---")
st.sidebar.write(f"Backend: {BACKEND_URL}")
st.sidebar.write(f"Last update: {datetime.now(timezone.utc).isoformat()} UTC")


with tabs[4]:  # Settings
    st.header("Settings")
    st.subheader("Ignored IP Management")

    try:
        resp = requests.get(f"{BACKEND_URL}/ignore/list")
        ignored_ips = resp.json().get("ignored", [])
    except Exception as e:
        ignored_ips = []
        st.error(f"Failed to fetch ignore list: {e}")

    st.write("Currently ignored IPs:", ignored_ips if ignored_ips else "None")

    # Add IP
    with st.form("add_ignore_form"):
        add_ip = st.text_input("IP to ignore")
        if st.form_submit_button("Add to ignore list"):
            if add_ip:
                try:
                    r = requests.post(f"{BACKEND_URL}/ignore/add", json={"ip": add_ip})
                    st.success(f"Added {add_ip} to ignore list")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed: {e}")

    # Remove IP
    with st.form("remove_ignore_form"):
        remove_ip = st.selectbox("IP to remove", ignored_ips if ignored_ips else ["None"])
        if st.form_submit_button("Remove from ignore list"):
            if remove_ip and remove_ip != "None":
                try:
                    r = requests.post(f"{BACKEND_URL}/ignore/remove", json={"ip": remove_ip})
                    st.success(f"Removed {remove_ip} from ignore list")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed: {e}")
