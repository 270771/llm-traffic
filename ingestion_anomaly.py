import chromadb
import pandas as pd
from sentence_transformers import SentenceTransformer

# === Initialize ChromaDB ===
# Initialize ChromaDB with persistence (data will be saved to ./chroma_db)
chroma_client = chromadb.PersistentClient(path="./chroma_db")
# For local host
#chroma_client = chromadb.HttpClient(host="localhost", port=8000)
# The collection here is where you will add your embeddings and documents related to your CSV anomaly logs
collection_csv = chroma_client.get_or_create_collection(name="anomaly_csv_logs4") 

# === Embedding Model ===
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

# Check if the embedding works 
#embedding = embedding_model.encode("CPU usage spike detected in node 12")
#print(embedding)

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

        # Create text summary for embedding
        summary = (
            f"Anomaly ID anomaly_{idx}: This is labeled as '{label}'. "
            f"Source IP: {src_ip}, Source Port: {src_port}, "
            f"Destination IP: {dst_ip}, Destination Port: {dst_port}. "
            f"Taxonomy classification: '{taxonomy}', heuristic code: {heuristic}."
        )

        summaries.append(summary)
        ids.append(f"anomaly_{idx}")  # Use anomalyID as unique ID

        # Metadata dictionary
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
    summaries, ids, metadatas = load_logs_from_csv(file_path) # Convert raw data rows into descriptive text summaries
    embeddings = embedding_model.encode(summaries).tolist() # Convert each text summary into a numerical vector (embedding) using your SentenceTransformer model

    # Check for existing data and delete duplicates
    existing = collection.get(ids=ids)
    if existing["ids"]:
        collection.delete(ids=existing["ids"])
        print(f"Deleted {len(existing['ids'])} existing anomaly rows.")

    # Add the new data to ChromaDB
    collection.add(documents=summaries, embeddings=embeddings, ids=ids, metadatas=metadatas)
    print(f"Ingested {len(summaries)} anomalies into '{collection.name}'.")

    # Print collection contents
    full_collection = collection.get()
    print("\nCollection Contents:")
    for i, doc in enumerate(full_collection["documents"]):
        print(f"{full_collection['ids'][i]}: {doc}")

# === Run Ingestion === 
ingest_csv_to_chromadb(CSV_PATH, collection_csv) #The knowledge base is fully built and stored inside ChromaDB.

# Test semantic search (optional but recommended)
query_text = "SYN flood attack targeting port 443"
query_embedding = embedding_model.encode(query_text).tolist()

results = collection_csv.query(query_embeddings=[query_embedding], n_results=3)

print("\nTop retrieved anomalies for your query:")
for doc in results["documents"][0]:
    print(doc)
