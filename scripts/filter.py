import pandas as pd
from io import StringIO
import os

# === Config ===
CONN_LOG_PATH = "./conn.log"  # Path to raw Zeek connection log
ANOMALY_CSV_PATH = "./20220110_anomalous_suspicious - 20220110_anomalous_suspicious.csv"  # Path to anomaly CSV
OUTPUT_PATH = "./filtered_conn.log"  # Path to save filtered connections
CHUNK_SIZE = 100_000  # Number of lines to process per chunk (adjust based on available memory)

# === Load anomaly rules from CSV ===
def load_anomaly_rules(path):
    """
    Loads anomaly rules from a CSV file and converts them into a list of dictionaries for matching.
    """
    df = pd.read_csv(path).fillna("None").astype(str)  # Fill missing values and ensure all fields are strings
    rules = []
    for _, row in df.iterrows():
        # Build a dictionary for each rule
        rules.append({
            "srcIP": row["srcIP"],
            "srcPort": row["srcPort"],
            "dstIP": row["dstIP"],
            "dstPort": row["dstPort"]
        })
    return rules

# === Check if a log row matches any anomaly rule ===
def conn_matches_any_rule(row, rules):
    """
    Checks whether a single connection log row matches any of the given anomaly rules.
    """
    for rule in rules:
        if (
            (rule["srcIP"] == "None" or row["id.orig_h"] == rule["srcIP"]) and
            (rule["dstIP"] == "None" or row["id.resp_h"] == rule["dstIP"]) and
            (rule["srcPort"] == "None" or str(row["id.orig_p"]) == rule["srcPort"]) and
            (rule["dstPort"] == "None" or str(row["id.resp_p"]) == rule["dstPort"])
        ):
            return True
    return False

# === Generator: Stream non-comment lines from Zeek conn.log ===
def stream_conn_log_lines(file_path):
    """
    Yields log lines from conn.log that are not comments (skip lines starting with "#").
    """
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.startswith("#"):
                yield line

# === Process conn.log file in chunks, filter, and write matching rows ===
def process_conn_log(conn_path, rules, output_path):
    print("🔁 Processing in chunks...")

    # Find header line (starts with #fields) to extract column names
    header = None
    with open(conn_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#fields"):
                header = line.strip().split("\t")[1:]  # Remove "#fields" and split columns
                break
    if not header:
        raise RuntimeError("No #fields header found in conn.log")

    # Stream log lines (excluding comments)
    line_gen = stream_conn_log_lines(conn_path)

    buffer = []  # Store current chunk of lines
    lines_read = 0  # Track number of lines read

    # Remove old output file to avoid appending to old results
    if os.path.exists(output_path):
        os.remove(output_path)

    while True:
        try:
            # Fill buffer up to CHUNK_SIZE lines
            while len(buffer) < CHUNK_SIZE:
                buffer.append(next(line_gen))
                lines_read += 1
        except StopIteration:
            # End of file reached
            pass

        if not buffer:
            break  # No more lines to process

        # Create DataFrame from chunk using header
        chunk_str = '\t'.join(header) + '\n' + ''.join(buffer)
        chunk = pd.read_csv(StringIO(chunk_str), sep="\t", low_memory=False).fillna("")

        # Filter rows that match any anomaly rule
        matched_rows = chunk[chunk.apply(lambda row: conn_matches_any_rule(row, rules), axis=1)]

        # Write matched rows to output file
        if not matched_rows.empty:
            mode = 'a' if os.path.exists(output_path) else 'w'
            header_write = not os.path.exists(output_path)
            matched_rows.to_csv(output_path, sep="\t", index=False, mode=mode, header=header_write)

        print(f"Processed {lines_read} lines, wrote {len(matched_rows)} matching rows.")

        buffer = []  # Reset buffer for next chunk

    print(f"Done. Filtered logs written to: {output_path}")

# === Main function ===
def main():
    # Check if required files exist
    if not os.path.exists(CONN_LOG_PATH):
        print(f"Conn log not found: {CONN_LOG_PATH}")
        return
    if not os.path.exists(ANOMALY_CSV_PATH):
        print(f"Anomaly CSV not found: {ANOMALY_CSV_PATH}")
        return

    print("📄 Loading anomaly rules...")
    rules = load_anomaly_rules(ANOMALY_CSV_PATH)

    # Process log using loaded rules
    process_conn_log(CONN_LOG_PATH, rules, OUTPUT_PATH)

# === Entry point ===
if __name__ == "__main__":
    main()
