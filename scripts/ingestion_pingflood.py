# Import defaultdict to easily group timestamps by IP and datetime for formatting
from collections import defaultdict
from datetime import datetime

# Import ChromaDB client and embedding function
from chromadb import PersistentClient
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

# === Function: parse_zeek_conn_log ===
def parse_zeek_conn_log(file_path):
    """
    Parses a Zeek conn.log file and extracts selected fields into a list of dictionaries.

    Args:
        file_path (str): Path to the Zeek conn.log file.

    Returns:
        entries (list): List of dictionaries, each representing one connection record
                        with timestamp, source IP, destination IP, destination port, and protocol.
    """
    entries = []
    with open(file_path, "r") as f:
        for line in f:
            # Skip comment lines (starting with "#") or empty lines
            if line.startswith("#") or not line.strip():
                continue

            # Split fields by tab character
            fields = line.strip().split('\t')

            # Check if line has at least 22 fields (standard for Zeek conn.log)  if a line is truncated or malformed, it might have fewer columns. We skip those lines to avoid errors when parsing.
            if len(fields) < 22:
                continue  # Skip malformed or incomplete lines

            # Create dictionary entry for this line
            entry = {
                "ts": float(fields[0]),      # Timestamp (UNIX time in seconds)
                "src_ip": fields[2],         # Source IP address
                "dst_ip": fields[4],         # Destination IP address
                "dst_port": fields[5],       # Destination port
                "proto": fields[6],          # Protocol (e.g., tcp, udp, icmp)
            }
            entries.append(entry)  # Add entry to list

    return entries

def detect_ping_flood(entries, threshold=5, time_window=5):
    """
    Detect potential ping flood attacks based on ICMP echo requests.
    
    Args:
        entries (list): List of connection dictionaries (output of parse_zeek_conn_log).
        threshold (int): Minimum number of pings in a short period to be considered suspicious.
        time_window (int): Time window (in seconds) to count pings.
    
    Returns:
        suspicious (list): List of dictionaries describing suspicious ping flood activity.
    """
    
    # Filter entries to include only ICMP Echo Requests (type 8), which appear in Zeek logs as proto='icmp' and dst_port='8'
    icmp_echoes = [e for e in entries if e['proto'] == 'icmp' and e['dst_port'] == '8']

    # Sort the filtered entries by timestamp
    icmp_echoes.sort(key=lambda x: x['ts'])

    # Prepare result list
    suspicious = []

    # Group timestamps of pings by each destination IP
    from collections import defaultdict
    dst_ip_times = defaultdict(list)
    for e in icmp_echoes:
        dst_ip_times[e['dst_ip']].append(e['ts'])

    # For each destination IP, slide a window to detect bursts of pings
    for dst_ip, times in dst_ip_times.items():
        start_idx = 0
        for end_idx in range(len(times)):
            # Move start index forward if time difference exceeds the window
            while times[end_idx] - times[start_idx] > time_window:
                start_idx += 1

            # Count pings within this window
            window_count = end_idx - start_idx + 1

            # If the count exceeds threshold, mark as suspicious
            if window_count >= threshold:
                suspicious.append({
                    "dst_ip": dst_ip,
                    "start_time": times[start_idx],
                    "end_time": times[end_idx],
                    "count": window_count
                })
                break  # Stop after first detection for this IP

    return suspicious

# === Function: count_icmp_echo_requests ===
def count_icmp_echo_requests(entries):
    """
    Count total number of ICMP Echo Requests (type 8) per destination IP.
    
    Args:
        entries (list): Parsed connection log entries.
    
    Returns:
        counts (dict): Dictionary mapping destination IPs to total echo request counts.
    """
    counts = defaultdict(int)
    for e in entries:
        if e['proto'] == 'icmp' and e['dst_port'] == '8':
            counts[e['dst_ip']] += 1
    return counts

# === Function: to_readable ===
def to_readable(ts):
    """
    Convert a UNIX timestamp to a human-readable string format.
    
    Args:
        ts (float): Timestamp in seconds since epoch.
    
    Returns:
        str: Readable datetime string.
    """
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

# === Function: format_ping_flood_doc ===
def format_ping_flood_doc(pf, total_count):
    """
    Create a descriptive text summary of a detected ping flood incident.
    
    Args:
        pf (dict): Ping flood dictionary with start time, end time, etc.
        total_count (int): Total ICMP requests observed for that IP.
    
    Returns:
        str: Formatted descriptive document text.
    """
    start = to_readable(pf['start_time'])
    end = to_readable(pf['end_time'])
    dst_ip = pf['dst_ip']
    return (
        f"Ping flood detected targeting destination IP {dst_ip}. "
        f"{total_count} ICMP Echo Requests received between {start} and {end}."
    )

# === Function: ingest_ping_floods_to_chroma ===
def ingest_ping_floods_to_chroma(ping_floods, icmp_counts, collection):
    """
    Ingest detected ping floods into ChromaDB as structured documents with metadata.
    
    Args:
        ping_floods (list): List of detected ping flood dictionaries.
        icmp_counts (dict): Total ICMP echo request counts per IP.
        collection: ChromaDB collection to store documents.
    """
    for idx, pf in enumerate(ping_floods):
        dst_ip = pf['dst_ip']
        total_count = icmp_counts.get(dst_ip, pf['count'])
        
        # Create descriptive document text
        doc = format_ping_flood_doc(pf, total_count)
        
        # Metadata associated with this incident
        metadata = {
            "dst_ip": dst_ip,
            "start_time": pf['start_time'],
            "end_time": pf['end_time'],
            "count_in_window": pf['count'],
            "total_icmp_requests": total_count
        }
        
        # Add or update the document in Chroma
        collection.upsert(
            documents=[doc],
            metadatas=[metadata],
            ids=[f"ping_flood_{idx}"]
        )

if __name__ == "__main__":
    zeek_file = "./filtered_conn110.log"
    
    # === Parse connection log entries (extract timestamps, IPs, ports, protocols) ===
    entries = parse_zeek_conn_log(zeek_file)

    # === Parameters for detection ===
    threshold = 5          # Minimum number of ICMP Echo Requests to consider it a flood
    time_window = 5        # Time window in seconds to observe burst of packets

    # === Detect ping flood incidents based on defined parameters ===
    ping_floods = detect_ping_flood(entries, threshold=threshold, time_window=time_window)

    # === Count total ICMP Echo Requests per destination IP (for reporting) ===
    icmp_counts = count_icmp_echo_requests(entries)

    # === Print detection summary ===
    if not ping_floods:
        print("No ping floods detected.")
    else:
        print("Ping floods detected with ICMP Echo Request counts:\n")
        for pf in ping_floods:
            dst_ip = pf['dst_ip']
            total_count = icmp_counts.get(dst_ip, 0)
            start_time = to_readable(pf['start_time'])
            end_time = to_readable(pf['end_time'])
            print(f"- Destination IP {dst_ip} received {total_count} ICMP echo requests "
                  f"from {start_time} to {end_time}.")

        # === Initialize embedding model (to embed summary documents) ===
        embedding_model = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")

        # === Connect to ChromaDB and get or create ping flood collection ===
        chroma_client = PersistentClient(path="./chroma_db")
        collection = chroma_client.get_or_create_collection(
            name="ping_flood_alerts2",
            embedding_function=embedding_model
        )

        # === Ingest detected ping flood incidents into ChromaDB ===
        ingest_ping_floods_to_chroma(ping_floods, icmp_counts, collection)
        print(f"\nIngested {len(ping_floods)} ping flood alerts into ChromaDB.")


