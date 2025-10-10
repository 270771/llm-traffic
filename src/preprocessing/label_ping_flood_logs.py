# Scans Zeek conn.log files for ICMP ping flood attacks using sliding-window detection and
# anomaly IP lists from heuristic-20 CSVs, labels each log with detection results,
# and saves them to a JSON report

import os
import json
import pandas as pd
from collections import defaultdict
from datetime import datetime

# Parse Zeek conn.log file
def parse_zeek_conn_log(file_path):
    entries = []
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            fields = line.strip().split('\t')
            if len(fields) < 22:
                continue
            entry = {
                "ts": float(fields[0]),
                "src_ip": fields[2],
                "src_port": fields[3],
                "dst_ip": fields[4],
                "dst_port": fields[5],
                "proto": fields[6],
            }
            entries.append(entry)
    return entries

# Convert UNIX timestamp to human-readable datetime string
def to_readable(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

# Detect ping flood attacks (many-to-one or one-to-many) in a list of conn.log entries
def detect_ping_flood(entries, threshold=10, time_window=20):
    # Filter only ICMP echo request/reply pairs
    icmp_echoes = [
        e for e in entries if e['proto'] == 'icmp' and (
            (e['src_port'] == '8' and e['dst_port'] == '0') or
            (e['src_port'] == '0' and e['dst_port'] == '8')
        )
    ]
    # Sort by timestamp for time window analysis
    icmp_echoes.sort(key=lambda x: x['ts'])

    floods = {"many_to_one": [], "one_to_many": []}
    
    # Detect many-to-one pattern (DDoS)
    dst_groups = defaultdict(list)
    for e in icmp_echoes:
        dst_groups[e['dst_ip']].append(e)
    
    for dst_ip, packets in dst_groups.items():
        start_idx = 0
        for end_idx in range(len(packets)):
            while packets[end_idx]['ts'] - packets[start_idx]['ts'] > time_window:
                start_idx += 1
            window = packets[start_idx:end_idx + 1]
            src_ips = set(p['src_ip'] for p in window)
            if len(window) >= threshold and len(src_ips) >= 3:
                floods["many_to_one"].append({
                    "type": "many_to_one",
                    "dst_ip": dst_ip,
                    "unique_src_ips": list(src_ips),
                    "src_ip_count": len(src_ips),
                    "packet_count": len(window),
                    "start_time": to_readable(window[0]['ts']),
                    "end_time": to_readable(window[-1]['ts'])
                })
                break
    
    # Detect one-to-many pattern (scan)
    src_groups = defaultdict(list)
    for e in icmp_echoes:
        src_groups[e['src_ip']].append(e)
    
    for src_ip, packets in src_groups.items():
        start_idx = 0
        for end_idx in range(len(packets)):
            while packets[end_idx]['ts'] - packets[start_idx]['ts'] > time_window:
                start_idx += 1
            window = packets[start_idx:end_idx + 1]
            dst_ips = set(p['dst_ip'] for p in window)
            if len(window) >= threshold and len(dst_ips) >= 3:
                floods["one_to_many"].append({
                    "type": "one_to_many",
                    "src_ip": src_ip,
                    "unique_dst_ips": list(dst_ips),
                    "dst_ip_count": len(dst_ips),
                    "packet_count": len(window),
                    "start_time": to_readable(window[0]['ts']),
                    "end_time": to_readable(window[-1]['ts'])
                })
                break

    return floods

# Load all source/destination IPs from anomaly CSV files where heuristic = 20
def load_anomaly_heuristic20_ips(csv_paths):
    all_ips = set()
    for csv_path in csv_paths:
        try:
            df = pd.read_csv(csv_path)
            if 'heuristic' in df.columns:
                h20 = df[df['heuristic'] == 20]
                if 'srcIP' in df.columns and 'dstIP' in df.columns:
                    all_ips.update(h20['srcIP'].dropna().astype(str).tolist())
                    all_ips.update(h20['dstIP'].dropna().astype(str).tolist())
                elif 'ip' in df.columns:
                    all_ips.update(h20['ip'].dropna().astype(str).tolist())
        except Exception as e:
            print(f"Error loading {csv_path}: {e}")
    return all_ips

def label_logs_in_directory(input_folder, anomaly_csvs, output_file="ping_flood_labels.json", threshold=10, time_window=20):
    results = {}
    yes_count = 0
    no_count = 0
    
    # Load all relevant IPs from anomaly CSVs
    anomaly_ips = load_anomaly_heuristic20_ips(anomaly_csvs)
    print(f"Loaded {len(anomaly_ips)} anomaly IPs from heuristic 20")

    for fname in os.listdir(input_folder):
        if not fname.endswith(".log"):
            continue
        fpath = os.path.join(input_folder, fname)
        try:
            entries = parse_zeek_conn_log(fpath)
            floods = detect_ping_flood(entries, threshold=threshold, time_window=time_window)
            
            # Check if any echo requests involve IPs found in heuristic 20 anomalies
            matching_rows = [
                e for e in entries
                if ((e['src_port'] == '8' and e['dst_port'] == '0') or (e['src_port'] == '0' and e['dst_port'] == '8'))
                and (e['src_ip'] in anomaly_ips or e['dst_ip'] in anomaly_ips)
            ]

            # Detection logic
            detected = False
            reason = []

            if len(matching_rows) >= 5:
                detected = True
                reason.append(f"≥5 rows have both ICMP echo and heuristic 20 IP ({len(matching_rows)} match)")

            if floods["many_to_one"]:
                detected = True
                reason.append(f"many-to-one ICMP ping flood detected ({len(floods['many_to_one'])} events)")

            if floods["one_to_many"]:
                detected = True
                reason.append(f"one-to-many ICMP ping flood detected ({len(floods['one_to_many'])} events)")

            results[fname] = {
                "ping_flood_detected": detected,
                "num_floods": len(floods["many_to_one"]) + len(floods["one_to_many"]),
                "flood_details": floods,
                "matching_anomaly_rows": len(matching_rows),
                "detection_reason": reason
            }
            
            # Print result to console
            if detected:
                yes_count += 1
                print(f"✅ {fname} - Ping Flood: YES ({', '.join(reason)})")
            else:
                no_count += 1
                print(f"⬜ {fname} - Ping Flood: NO")

        except Exception as e:
            print(f"❌ Error processing {fname}: {e}")
            results[fname] = {"error": str(e)}
    
    # Save results to JSON file
    output_path = os.path.join(input_folder, output_file)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Total YES (ping floods): {yes_count}")
    print(f"Total NO (no attack): {no_count}")
    print(f"Saved labels to: {output_path}")

# Run the script
if __name__ == "__main__":
    log_folder = "./split_logs"
    anomaly_csvs = [
        "./20220110_anomalous_suspicious - 20220110_anomalous_suspicious1.csv"
    ]

    print("="*60)
    print("🔍 Automated Ping Flood Labeling")
    print("="*60)
    print(f"Input folder: {log_folder}")
    print(f"Anomaly CSVs: {len(anomaly_csvs)} file(s)\n")

    label_logs_in_directory(log_folder, anomaly_csvs)
