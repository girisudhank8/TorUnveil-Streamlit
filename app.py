import os

if os.environ.get("STREAMLIT_SERVER_HEADLESS") == "true":
    os.environ["STREAMLIT_SERVER_ENABLE_CORS"] = "false"


import streamlit as st
import time
from pipeline import get_new_pcaps, analyze_pcap

st.set_page_config(
    page_title="TorUnveil 3.0",
    layout="wide"
)

st.title("🕵️ TorUnveil 3.0 – Live Tor Traffic Analyzer")

# ---------------- SESSION STATE ----------------
if "running" not in st.session_state:
    st.session_state.running = False

if "processed_pcaps" not in st.session_state:
    st.session_state.processed_pcaps = set()

if "results" not in st.session_state:
    st.session_state.results = []

# ---------------- CONTROLS ----------------
col1, col2 = st.columns(2)

with col1:
    if st.button("▶ Start Live Analysis"):
        st.session_state.running = True

with col2:
    if st.button("⏹ Stop"):
        st.session_state.running = False

st.divider()

# ---------------- LIVE PIPELINE ----------------
if st.session_state.running:
    new_pcaps = get_new_pcaps(st.session_state.processed_pcaps)

    for pcap in new_pcaps:
        result = analyze_pcap(pcap)
        st.session_state.processed_pcaps.add(pcap)

        if result:
            st.session_state.results.append(result)

            if result["suspected_tor"] > 0:
                st.warning(f"🚨 Tor traffic detected in {result['pcap']}")

    time.sleep(1)
    st.experimental_rerun()

# ---------------- DISPLAY ----------------
if st.session_state.results:
    st.subheader("📊 Live Analysis Results")

    st.dataframe(
        st.session_state.results,
        use_container_width=True
    )

    total_tor = sum(r["suspected_tor"] for r in st.session_state.results)
    st.metric("Total Suspected Tor Flows", total_tor)
else:
    st.info("Waiting for PCAP files in `capture/` directory…")
