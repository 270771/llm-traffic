# Loads anomaly CSV logs, converts them into descriptive text summaries with
# unique IDs, embeds them using a sentence-transformer,
# and stores them in a persistent ChromaDB collection for later retrieval

import chromadb
import pandas as pd
from sentence_transformers import SentenceTransformer
import os
import re

# === Initialize ChromaDB ===
# Initialize ChromaDB with persistence (data will be saved to ./chroma_db)
chroma_client = chromadb.PersistentClient(path="./chroma_db")
# For local host
#chroma_client = chromadb.HttpClient(host="localhost", port=8000)
# The collection here is where you will add your embeddings and documents related to your CSV anomaly logs
collection_csv = chroma_client.get_or_create_collection(name="anomaly_csv_logsc01") 

# === Embedding Model ===
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

# Check if the embedding works 
#embedding = embedding_model.encode("CPU usage spike detected in node 12")
#print(embedding)


# === Utility Function: Generate Unique IDs ===
def make_unique_ids(new_ids, existing_ids_set):
    """
    Generates unique IDs by appending numeric suffixes to avoid collisions.
    """
    unique_ids = []
    for _id in new_ids:
        candidate = _id
        suffix = 1
        while candidate in existing_ids_set:
            candidate = f"{_id}_{suffix}"
            suffix += 1
        unique_ids.append(candidate)
        existing_ids_set.add(candidate)
    return unique_ids


# === File Path ===
CSV_PATH = "./20220110_anomalous_suspicious - 20220110_anomalous_suspicious1.csv"


# === Load and summarize logs ===
def load_logs_from_csv(file_path):
    df = pd.read_csv(file_path).fillna("unknown")
    summaries = []
    ids = []
    metadatas = []

    for idx, row in df.iterrows():
        src_ip = row.get("srcIP", "unknown")
        src_port = row.get("srcPort", "unknown")
        dst_ip = row.get("dstIP", "unknown")
        dst_port = row.get("dstPort", "unknown")
        taxonomy = row.get("taxonomy", "unknown")
        heuristic = row.get("heuristic", "unknown")
        label = row.get("label", "unknown")

        # Create text summary for embedding (improved natural language format)
        summary = (
            f"Anomaly ID anomaly_{idx}: A {label} connection was detected from source IP {src_ip} "
            f"on port {src_port} to destination IP {dst_ip} on port {dst_port}. "
            f"This anomaly is categorized as '{taxonomy}' based on heuristic {heuristic}."
        )

        summaries.append(summary)
        ids.append(f"anomaly_{idx}")  # Use anomalyID as unique ID

        # Metadata dictionary (KEPT for structured filtering)
        meta = {
            "srcIP": src_ip,
            "srcPort": src_port,
            "dstIP": dst_ip,
            "dstPort": dst_port,
            "taxonomy": taxonomy,
            "heuristic": heuristic,
            "label": label
        }
        metadatas.append(meta)

    return summaries, ids, metadatas
#print("Successfully loaded and indexed Mawilab anomalies into ChromaDB!")

def ingest_csv_to_chromadb(file_path, collection):
    print(f"\n📄 Starting ingestion for file: {file_path}")
    summaries, ids, metadatas = load_logs_from_csv(file_path) # Convert raw data rows into descriptive text summaries
    print(f"Loaded {len(summaries)} rows from CSV.")
    
    # Get all existing IDs from collection to avoid collisions
    all_existing = collection.get()
    existing_ids_set = set(all_existing["ids"])
    
    # Generate unique IDs to prevent collisions (adds numeric suffixes if needed)
    unique_ids = make_unique_ids(ids, existing_ids_set)
    
    # Update summaries to reflect the unique IDs instead of the original idx-based IDs
    updated_summaries = []
    for original_summary, unique_id in zip(summaries, unique_ids):
        # Replace first occurrence of anomaly_<num> with the unique_id
        updated_summary = re.sub(r"anomaly_\d+", unique_id, original_summary, count=1)
        updated_summaries.append(updated_summary)
    
    # Convert each text summary into a numerical vector (embedding) using SentenceTransformer model
    embeddings = embedding_model.encode(updated_summaries).tolist()

    try:
        # Add the new data to ChromaDB (with metadata for structured filtering)
        collection.add(
            documents=updated_summaries, 
            embeddings=embeddings, 
            ids=unique_ids, 
            metadatas=metadatas
        )
        print(f"✅ Ingested {len(updated_summaries)} anomalies with unique IDs into '{collection.name}'.")
    except Exception as e:
        print("❌ ChromaDB add failed:", e)
        print(f"Trying to add {len(updated_summaries)} items")

    # Print collection contents for verification
    full_collection = collection.get()
    print("\n📊 Collection Contents:")
    for i, doc in enumerate(full_collection["documents"]):
        print(f"{full_collection['ids'][i]}: {doc}")
    
    # Print total number of entries in the collection after ingestion
    print(f"\n📈 Total entries in collection '{collection.name}': {len(full_collection['ids'])}")

# === Run Ingestion === 
# Process multiple CSV files (add more paths as needed)
csv_files_to_ingest = [
    "./20220110_anomalous_suspicious - 20220110_anomalous_suspicious1.csv",
    # Add more CSV files here:
    # "C:/Users/YourName/Downloads/20220109_anomalous_suspicious - 20220109_anomalous_suspicious.csv",
    # "C:/Users/YourName/Downloads/20220101_anomalous_suspicious - 20220101_anomalous_suspicious.csv"
]

for csv_path in csv_files_to_ingest:
    if os.path.exists(csv_path):
        ingest_csv_to_chromadb(csv_path, collection_csv)
    else:
        print(f"⚠️ File not found: {csv_path}")

print("\n" + "="*60)
print("🎉 All files processed! Knowledge base is ready.")
print("="*60)

# Test semantic search (optional but recommended)
query_text = "SYN flood attack targeting port 443"
query_embedding = embedding_model.encode(query_text).tolist()

results = collection_csv.query(query_embeddings=[query_embedding], n_results=3)

print("\nTop retrieved anomalies for your query:")
for doc in results["documents"][0]:
    print(doc)
