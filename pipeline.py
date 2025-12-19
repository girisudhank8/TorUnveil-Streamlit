import os
from modules.pcap_parser import PCAPAnalyzer

PCAP_DIR = "capture"

def get_new_pcaps(processed_pcaps):
    pcaps = []

    if not os.path.exists(PCAP_DIR):
        return pcaps

    for filename in sorted(os.listdir(PCAP_DIR)):
        if not filename.endswith(".pcap"):
            continue
        if filename in processed_pcaps:
            continue

        full_path = os.path.join(PCAP_DIR, filename)

        if os.path.getsize(full_path) == 0:
            continue

        pcaps.append(full_path)

    return pcaps


def analyze_pcap(pcap_path):
    analyzer = PCAPAnalyzer()
    df = analyzer.analyze_pcap(pcap_path)

    if df.empty:
        return None

    stats = analyzer.get_flow_statistics(df)

    return {
        "pcap": os.path.basename(pcap_path),
        "total_flows": stats.get("total_flows", 0),
        "suspected_tor": stats.get("suspected_tor_flows", 0),
        "total_packets": stats.get("total_packets", 0),
        "total_bytes": stats.get("total_bytes", 0),
        "avg_confidence": round(stats.get("avg_tor_confidence", 0), 2),
        "src_ips": stats.get("unique_src_ips", 0),
        "dst_ips": stats.get("unique_dst_ips", 0),
    }
