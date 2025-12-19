# =========================
# Environment configuration
# =========================
import os
import time
import platform
import pandas as pd
import streamlit as st

# Fix CORS issues on Streamlit Cloud
if os.environ.get("STREAMLIT_SERVER_HEADLESS") == "true":
    os.environ["STREAMLIT_SERVER_ENABLE_CORS"] = "false"

# =========================
# Imports (AFTER st)
# =========================
from capture_manager import start_capture, stop_capture
from pipeline import get_new_pcaps, analyze_pcap

# =========================
# Page configuration
# =========================
st.set_page_config(
    page_title="TorUnveil 3.0",
    layout="wide"
)

st.title("🕵️ TorUnveil 3.0 – Live Tor Traffic Analyzer")

# =========================
# Platform detection
# =========================
IS_CLOUD = platform.system() == "Linux" and os.environ.get("STREAMLIT_SERVER_HEADLESS") == "true"

# =========================
# Session State Initialization
# =========================
if "capture_proc" not in st.session_state:
    st.session_state.capture_proc = None

if "running" not in st.session_state:
    st.session_state.running = False

if "processed_pcaps" not in st.session_state:
    st.session_state.processed_pcaps = set()

if "results" not in st.session_state:
    st.session_state.results = []

# =========================
# Capture Controls
# =========================
st.subheader("🎥 Packet Capture")

cap_col1, cap_col2 = st.columns(2)

with cap_col1:
    if st.button("▶ Start Capture", disabled=IS_CLOUD):
        st.session_state.capture_proc = start_capture()
        st.success("Capture started")

with cap_col2:
    if st.button("⛔ Stop Capture", disabled=IS_CLOUD):
        if st.session_state.capture_proc:
            stop_capture(st.session_state.capture_proc)
            st.session_state.capture_proc = None
            st.success("Capture stopped")

if IS_CLOUD:
    st.info("🔒 Packet capture is disabled on Streamlit Cloud.")

st.divider()

# =========================
# Live Analysis Controls
# =========================
st.subheader("⚙️ Live Analysis")

ana_col1, ana_col2 = st.columns(2)

with ana_col1:
    if st.button("▶ Start Live Analysis"):
        st.session_state.running = True

with ana_col2:
    if st.button("⏹ Stop"):
        st.session_state.running = False

st.divider()

# =========================
# Live Pipeline
# =========================
if st.session_state.running:
    new_pcaps = get_new_pcaps(st.session_state.processed_pcaps)

    for pcap in new_pcaps:
        result = analyze_pcap(pcap)
        st.session_state.processed_pcaps.add(pcap)

        if result:
            st.session_state.results.append(result)

            if result.get("suspected_tor", 0) > 0:
                st.warning(f"🚨 Tor traffic detected in {result['pcap']}")

    time.sleep(1)
    st.experimental_rerun()

# =========================
# Results Display
# =========================
if st.session_state.results:
    st.subheader("📊 Live Analysis Results")

    df = pd.DataFrame(st.session_state.results)
    st.dataframe(df, use_container_width=True)

    total_tor = df["suspected_tor"].sum()
    st.metric("Total Suspected Tor Flows", total_tor)

    st.divider()

    # =========================
    # Visualizations
    # =========================
    if "avg_confidence" in df.columns:
        st.subheader("📈 Tor Confidence Over Time")
        st.line_chart(df["avg_confidence"])

    if "suspected_tor" in df.columns:
        st.subheader("📊 Suspected Tor Flows per PCAP")
        st.bar_chart(df["suspected_tor"])

else:
    st.info("Waiting for PCAP files in `capture/` directory…")
