#!/usr/bin/env python3
"""
SYN Flood Ingestion Script for ChromaDB
Detects TCP SYN flood patterns and ingests them into vector database for RAG retrieval
"""

from collections import defaultdict
from datetime import datetime
from chromadb import PersistentClient
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction


def parse_zeek_conn_log(file_path):
    """
    Parse Zeek conn.log file and extract TCP connection records.
    
    Args:
        file_path (str): Path to the Zeek conn.log file.
    
    Returns:
        list: List of dictionaries with connection data.
    """
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
                "conn_state": fields[11],  # Connection state is key for SYN detection
                "duration": float(fields[8]) if fields[8] != '-' else 0.0,
                "orig_bytes": int(fields[9]) if fields[9] != '-' else 0,
                "resp_bytes": int(fields[10]) if fields[10] != '-' else 0,
            }
            entries.append(entry)
    
    return entries


def detect_syn_flood(entries, threshold=10, time_window=20):
    """
    Detect potential SYN flood attacks based on TCP connection states.
    
    SYN flood indicators:
    - S0: Connection attempt seen, no reply
    - S1: Connection established, not terminated
    - REJ: Connection attempt rejected
    - RSTO: Connection established, originator aborted
    - RSTOS0: Originator sent SYN followed by RST
    
    Args:
        entries (list): List of connection dictionaries.
        threshold (int): Minimum number of SYN attempts to be considered suspicious.
        time_window (int): Time window (in seconds) to count SYN attempts.
    
    Returns:
        list: List of dictionaries describing suspicious SYN flood activity.
    """
    # SYN flood connection states
    syn_flood_states = ['S0', 'S1', 'REJ', 'RSTO', 'RSTOS0']
    
    # Filter TCP connections with SYN flood indicators
    syn_connections = [
        e for e in entries 
        if e['proto'] == 'tcp' and e['conn_state'] in syn_flood_states
    ]
    
    # Sort by timestamp
    syn_connections.sort(key=lambda x: x['ts'])
    
    suspicious = []
    
    # Group by destination IP (target of attack)
    dst_ip_conns = defaultdict(list)
    for conn in syn_connections:
        dst_ip_conns[conn['dst_ip']].append(conn)
    
    # Detect high-volume SYN attempts to single targets (many-to-one pattern)
    for dst_ip, conns in dst_ip_conns.items():
        if len(conns) < threshold:
            continue
        
        # Sliding window detection
        for i in range(len(conns)):
            window_conns = []
            for j in range(i, len(conns)):
                if conns[j]['ts'] - conns[i]['ts'] <= time_window:
                    window_conns.append(conns[j])
                else:
                    break
            
            if len(window_conns) >= threshold:
                # Get unique source IPs
                src_ips = list(set([c['src_ip'] for c in window_conns]))
                
                # Determine attack type
                if len(src_ips) >= 3:
                    attack_type = "Distributed SYN Flood (DDoS)"
                else:
                    attack_type = "Concentrated SYN Flood"
                
                suspicious.append({
                    "type": "many_to_one",
                    "attack_type": attack_type,
                    "target_ip": dst_ip,
                    "target_port": window_conns[0]['dst_port'],
                    "source_ips": src_ips[:10],  # Limit to first 10
                    "source_count": len(src_ips),
                    "syn_count": len(window_conns),
                    "conn_states": list(set([c['conn_state'] for c in window_conns])),
                    "start_time": datetime.fromtimestamp(window_conns[0]['ts']).strftime("%Y-%m-%d %H:%M:%S"),
                    "end_time": datetime.fromtimestamp(window_conns[-1]['ts']).strftime("%Y-%m-%d %H:%M:%S"),
                    "duration_seconds": window_conns[-1]['ts'] - window_conns[0]['ts']
                })
                break  # Found one window, move to next target
    
    # Group by source IP (scanning pattern)
    src_ip_conns = defaultdict(list)
    for conn in syn_connections:
        src_ip_conns[conn['src_ip']].append(conn)
    
    # Detect one-to-many pattern (scanning/reconnaissance)
    for src_ip, conns in src_ip_conns.items():
        if len(conns) < threshold:
            continue
        
        # Check for targeting multiple destinations
        unique_targets = list(set([c['dst_ip'] for c in conns]))
        
        if len(unique_targets) >= 3:
            suspicious.append({
                "type": "one_to_many",
                "attack_type": "SYN Scanning",
                "source_ip": src_ip,
                "target_ips": unique_targets[:10],
                "target_count": len(unique_targets),
                "syn_count": len(conns),
                "conn_states": list(set([c['conn_state'] for c in conns])),
                "start_time": datetime.fromtimestamp(conns[0]['ts']).strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": datetime.fromtimestamp(conns[-1]['ts']).strftime("%Y-%m-%d %H:%M:%S"),
                "duration_seconds": conns[-1]['ts'] - conns[0]['ts']
            })
    
    return suspicious


def format_syn_flood_alert(alert):
    """
    Convert SYN flood detection dictionary into a natural-language alert.
    
    Args:
        alert (dict): Dictionary with SYN flood detection metadata.
    
    Returns:
        str: Human-readable alert description.
    """
    if alert["type"] == "many_to_one":
        return (
            f"{alert['attack_type']}: {alert['syn_count']} SYN attempts detected to "
            f"{alert['target_ip']}:{alert['target_port']} from {alert['source_count']} "
            f"source(s) between {alert['start_time']} and {alert['end_time']}. "
            f"Connection states: {', '.join(alert['conn_states'])}. "
            f"Source IPs include: {', '.join(alert['source_ips'][:5])}..."
        )
    else:  # one_to_many
        return (
            f"{alert['attack_type']}: {alert['syn_count']} SYN attempts from "
            f"{alert['source_ip']} targeting {alert['target_count']} different IPs "
            f"between {alert['start_time']} and {alert['end_time']}. "
            f"Connection states: {', '.join(alert['conn_states'])}. "
            f"Targets include: {', '.join(alert['target_ips'][:5])}..."
        )


def ingest_syn_floods_to_chroma(log_file, collection_name="syn_flood_alerts", persist_dir="./chroma_db"):
    """
    Parse conn.log, detect SYN floods, and ingest into ChromaDB collection.
    
    Args:
        log_file (str): Path to Zeek conn.log file.
        collection_name (str): Name of ChromaDB collection.
        persist_dir (str): Directory for ChromaDB persistence.
    """
    print(f"\n{'='*70}")
    print("SYN FLOOD INGESTION TO CHROMADB")
    print(f"{'='*70}\n")
    
    # Parse log
    print(f"📖 Parsing log file: {log_file}")
    entries = parse_zeek_conn_log(log_file)
    print(f"   Found {len(entries)} total connections")
    
    # Detect SYN floods
    print(f"\n🔍 Detecting SYN flood patterns...")
    syn_floods = detect_syn_flood(entries, threshold=10, time_window=20)
    print(f"   Detected {len(syn_floods)} suspicious SYN flood events")
    
    if not syn_floods:
        print("\n⚠️  No SYN flood patterns detected. Nothing to ingest.")
        return
    
    # Initialize ChromaDB client
    print(f"\n💾 Connecting to ChromaDB: {persist_dir}")
    client = PersistentClient(path=persist_dir)
    
    # Create embedding function
    embedding_function = SentenceTransformerEmbeddingFunction(
        model_name="sentence-transformers/all-MiniLM-L6-v2"
    )
    
    # Get or create collection
    print(f"📦 Creating/accessing collection: {collection_name}")
    try:
        collection = client.get_collection(
            name=collection_name,
            embedding_function=embedding_function
        )
        print(f"   Existing collection found with {collection.count()} documents")
    except:
        collection = client.create_collection(
            name=collection_name,
            embedding_function=embedding_function,
            metadata={"description": "TCP SYN flood attack patterns and alerts"}
        )
        print(f"   New collection created")
    
    # Prepare documents for ingestion
    print(f"\n📝 Preparing {len(syn_floods)} documents for ingestion...")
    documents = []
    metadatas = []
    ids = []
    
    for i, alert in enumerate(syn_floods, 1):
        # Format as natural language
        doc_text = format_syn_flood_alert(alert)
        documents.append(doc_text)
        
        # Metadata
        metadata = {
            "type": alert["type"],
            "attack_type": alert["attack_type"],
            "syn_count": str(alert["syn_count"]),
            "start_time": alert["start_time"],
            "conn_states": ",".join(alert["conn_states"])
        }
        
        if alert["type"] == "many_to_one":
            metadata["target_ip"] = alert["target_ip"]
            metadata["target_port"] = alert["target_port"]
            metadata["source_count"] = str(alert["source_count"])
        else:
            metadata["source_ip"] = alert["source_ip"]
            metadata["target_count"] = str(alert["target_count"])
        
        metadatas.append(metadata)
        ids.append(f"syn_flood_{i}")
    
    # Ingest into ChromaDB
    print(f"🚀 Ingesting documents into ChromaDB...")
    collection.add(
        documents=documents,
        metadatas=metadatas,
        ids=ids
    )
    
    print(f"\n{'='*70}")
    print("✅ SYN FLOOD INGESTION COMPLETE!")
    print(f"{'='*70}")
    print(f"   Collection: {collection_name}")
    print(f"   Total documents: {collection.count()}")
    print(f"   Location: {persist_dir}\n")


if __name__ == "__main__":
    import sys
    
    # Default log file
    default_log = "./data/raw/filtered_conn110.log"
    
    # Allow command-line argument for log file
    log_file = sys.argv[1] if len(sys.argv) > 1 else default_log
    
    # Run ingestion
    ingest_syn_floods_to_chroma(log_file)
