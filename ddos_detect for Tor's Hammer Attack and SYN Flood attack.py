# ddos_dashboard.py

import streamlit as st
import pandas as pd
import os
import time
import threading
from scapy.all import sniff, TCP, IP
from collections import defaultdict
from datetime import datetime

# ---------------- Dashboard Setup ----------------
st.set_page_config(page_title="DDoS Detection & Auto-Mitigation", layout="wide")

st.title("🛡️ Real-Time DDoS Detection with Auto-Blocking & Auto-Unblocking")

col1, col2 = st.columns(2)
line_chart = col1.line_chart()
bar_chart = col2.bar_chart()

alert_box = st.empty()
summary = st.empty()
blocked_display = st.empty()

# ---------------- Data Storage ----------------
syn_counts = defaultdict(int)
time_series = []
blocked_ips = {}  # {ip: unblock_time}
log_file = "blocked_ips.log"

# ---------------- Auto-Unblock Function ----------------
def unblock_ip(ip, delay=600):  # default 10 minutes
    time.sleep(delay)
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
    if ip in blocked_ips:
        del blocked_ips[ip]
    with open(log_file, "a") as f:
        f.write(f"{datetime.now()} - Unblocked {ip} after {delay} seconds\n")

# ---------------- Packet Handler ----------------
def packet_callback(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":  # SYN packet
        src_ip = pkt[IP].src
        syn_counts[src_ip] += 1
        ts = datetime.now().strftime("%H:%M:%S")
        time_series.append({"time": ts, "ip": src_ip})

# ---------------- Sniffer ----------------
st.info("👂 Listening for SYN packets on eth0... (Run as sudo)")
sniffer = sniff(
    filter="tcp[tcpflags] & tcp-syn != 0",
    iface="eth0",
    prn=packet_callback,
    store=0,
    timeout=30
)

# ---------------- Data Processing ----------------
df = pd.DataFrame(time_series)

if not df.empty:
    # Time series chart
    ts_summary = df.groupby("time").size()
    line_chart.line_chart(ts_summary)

    # Top 5 attacking IPs
    top_ips = pd.Series(syn_counts).sort_values(ascending=False).head(5)
    bar_chart.bar_chart(top_ips)

    # ---------------- Alerts & Blocking ----------------
    alerts = []
    for ip, count in syn_counts.items():
        if count > 500 and ip not in blocked_ips:  # threshold
            # Block the attacking IP
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
            unblock_time = datetime.now() + pd.Timedelta(seconds=600)
            blocked_ips[ip] = unblock_time

            # Log the block
            with open(log_file, "a") as f:
                f.write(f"{datetime.now()} - Blocked {ip} after {count} SYN packets\n")

            # Start unblock timer
            threading.Thread(target=unblock_ip, args=(ip, 600), daemon=True).start()

            alerts.append(f"🚫 Blocked {ip} (auto-unblock in 10 min)")

    # Show alerts
    if alerts:
        alert_box.error("\n".join(alerts))
    else:
        alert_box.success("✅ No suspicious activity detected")

    # ---------------- Summary ----------------
    summary.write(
        f"*Total Packets Captured:* {len(df)} | "
        f"*Unique IPs:* {df['ip'].nunique()} | "
        f"*Currently Blocked IPs:* {len(blocked_ips)}"
    )

    # ---------------- Live Blocked IP List ----------------
    if blocked_ips:
        blocked_list = [f"{ip} (unblocks at {time.strftime('%H:%M:%S', time.localtime(unblock_time.timestamp()))})"
                        for ip, unblock_time in blocked_ips.items()]
        blocked_display.write("### 🚫 Currently Blocked IPs:\n" + "\n".join(blocked_list))

else:
    st.warning("⚠️ No packets captured. Try running an attack or check interface.")
