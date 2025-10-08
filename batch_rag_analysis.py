# Batch processes multiple Zeek conn.log files through the RAG system,
# generating analysis text files for each input log for later evaluation

import os
import sys
from rag_query import generate_rag_analysis

def process_log_file(log_path):
    """
    Process a single conn.log file and generate a query for RAG analysis.
    
    Args:
        log_path: Path to the conn.log file
        
    Returns:
        str: Generated query describing the log file's traffic
    """
    try:
        # Parse the log file to extract basic statistics
        entries = parse_zeek_conn_log(log_path)
        
        if not entries:
            return None
        
        # Count ICMP traffic
        icmp_count = sum(1 for e in entries if e.get('proto') == 'icmp')
        
        # Extract unique IPs
        src_ips = set(e.get('src_ip') for e in entries if e.get('src_ip'))
        dst_ips = set(e.get('dst_ip') for e in entries if e.get('dst_ip'))
        
        # Generate query based on traffic characteristics
        if icmp_count > 0:
            # Focus on potential ping flood
            query = (
                f"Analyze potential ICMP ping flood activity in this network log. "
                f"The log contains {icmp_count} ICMP packets between {len(src_ips)} source IPs "
                f"and {len(dst_ips)} destination IPs. "
                f"Key destination IPs: {', '.join(list(dst_ips)[:3])}. "
                f"Determine if this represents a ping flood attack."
            )
        else:
            query = (
                f"Analyze this network traffic log for anomalous behavior. "
                f"Traffic involves {len(src_ips)} source IPs and {len(dst_ips)} destination IPs."
            )
        
        return query
        
    except Exception as e:
        print(f"Error processing {log_path}: {e}")
        return None


def parse_zeek_conn_log(file_path):
    """Parse Zeek conn.log file and return list of connection entries."""
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
                "dst_ip": fields[4],
                "dst_port": fields[5],
                "proto": fields[6],
            }
            entries.append(entry)
    return entries


def batch_process_logs(input_folder, output_folder):
    """
    Process all .log files in input_folder and save RAG analysis to output_folder.
    
    Args:
        input_folder: Directory containing conn.log files to analyze
        output_folder: Directory to save RAG analysis text files
    """
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)
    
    # Get all .log files
    log_files = [f for f in os.listdir(input_folder) if f.endswith('.log')]
    
    print(f"Found {len(log_files)} log files to process")
    print(f"Output will be saved to: {output_folder}\n")
    
    processed = 0
    failed = 0
    
    for log_file in log_files:
        log_path = os.path.join(input_folder, log_file)
        output_filename = log_file.rsplit('.', 1)[0] + '.txt'
        output_path = os.path.join(output_folder, output_filename)
        
        # Skip if already processed
        if os.path.exists(output_path):
            print(f"⏭️  Skipping {log_file} (already processed)")
            continue
        
        print(f"🔍 Processing {log_file}...")
        
        try:
            # Generate query from log file
            query = process_log_file(log_path)
            
            if query is None:
                print(f"⚠️  Skipped {log_file} (empty or invalid)")
                failed += 1
                continue
            
            # Run RAG analysis
            result = generate_rag_analysis(query)
            
            # Save result to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(result)
            
            print(f"✅ Completed {log_file} → {output_filename}")
            processed += 1
            
        except Exception as e:
            print(f"❌ Error processing {log_file}: {e}")
            failed += 1
    
    print(f"\n{'='*50}")
    print(f"Batch processing complete!")
    print(f"✅ Successfully processed: {processed}")
    print(f"❌ Failed: {failed}")
    print(f"📁 Results saved to: {output_folder}")


if __name__ == "__main__":
    # Configure paths
    input_folder = "./split_logs"  # Folder with conn_log_part_*.log files
    output_folder = "./rag_outputs"  # Folder to save analysis results
    
    # You can also pass paths as command-line arguments
    if len(sys.argv) > 2:
        input_folder = sys.argv[1]
        output_folder = sys.argv[2]
    
    print("="*50)
    print("🚀 Batch RAG Analysis")
    print("="*50)
    print(f"Input folder: {input_folder}")
    print(f"Output folder: {output_folder}\n")
    
    batch_process_logs(input_folder, output_folder)
