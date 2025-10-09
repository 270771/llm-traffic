# === Import necessary libraries ===
import os
import re
from dotenv import load_dotenv
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.chat_models import ChatOpenAI
from langchain.retrievers import EnsembleRetriever
from langchain.prompts import PromptTemplate
from langchain.schema import Document
from sentence_transformers import CrossEncoder

# === Load environment variables from .env file ===
load_dotenv()

# === Set environment settings ===
os.environ["TOKENIZERS_PARALLELISM"] = "false"  # Disable parallelism in tokenizers to avoid warning messages

# Embeddings
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# Cross-Encoder for reranking (more accurate than bi-encoder for relevance scoring)
cross_encoder = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')

# === Load Chroma Collections ===
ping_flood_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="ping_flood_alerts2"
)

anomaly_csv_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="anomaly_csv_logsc01"
)

heuristic_txt_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="heuristic_info_txt4"
)

# === Prompt Template ===
ping_flood_prompt = PromptTemplate(
    # Define input variable names to be dynamically filled in later
    input_variables=["ping_flood_alerts2", "anomaly_csv", "heuristic_context"],

    # Template string containing detailed instructions for the language model
    template="""
You are a cybersecurity analyst AI trained to detect, interpret, and explain ICMP ping flood attacks.

You are given:
- `ping_flood_alerts2`: Natural-language summaries of potential ping flood events.
- `anomaly_csv`: Structured anomaly records related to suspicious IPs or ports.
- `heuristic_context`: Documentation on the heuristics and taxonomies used in labeling anomalies.

Your goals:
1. Confirm whether each ping flood detection is consistent with known anomaly patterns.
2. Use heuristic context to explain why this behavior is considered a threat.
3. Recommend a concise, confident security action.

Respond in this format:
- Ping flood alert: [summary]
  Justified by anomaly: Matched anomaly ID [ID], heuristic [ID] ([desc]), taxonomy [name] ([desc]).
  → Action: [specific action like block IP, investigate source, rate-limit ICMP, etc.]

Be assertive — avoid vague words like “might” or “possibly”. Justify your answer with retrieved evidence.

------------
Ping Flood Alerts:
{ping_flood_alerts2}

Anomaly CSV Records:
{anomaly_csv}

Heuristic & Taxonomy Context:
{heuristic_context}
------------
"""
)

# === Utility: Extract IPs ===
def extract_ips(text):
    """
    Extract all IPv4 addresses from the input text using a regular expression.

    Args:
        text (str): Input text to scan.

    Returns:
        list: List of all matched IP addresses (strings).
    """
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)


# === Utility: Parse metadata filters from query ===
def parse_metadata_filter(query_text):
    """
    Extract optional metadata filters from user query text.
    Supports patterns like: "protocol tcp", "port 443", "taxonomy DoS", etc.

    Args:
        query_text (str): User query text.

    Returns:
        dict: Metadata filter dictionary for ChromaDB, or None if no filters found.
    """
    filter_dict = {}
    
    # Extract protocol filter (e.g., "protocol tcp", "icmp traffic")
    if re.search(r'\b(tcp|udp|icmp)\b', query_text, re.IGNORECASE):
        proto = re.search(r'\b(tcp|udp|icmp)\b', query_text, re.IGNORECASE).group(1).lower()
        # Note: protocol not stored in anomaly metadata, but we can filter by label/taxonomy
    
    # Extract port filter (e.g., "port 443", "port 80")
    port_match = re.search(r'\bport\s+(\d+)', query_text, re.IGNORECASE)
    if port_match:
        filter_dict["dstPort"] = port_match.group(1)
    
    # Extract taxonomy filter (e.g., "DoS", "PortScan", "HTTP")
    taxonomy_keywords = ["DoS", "DDoS", "PortScan", "HTTP", "NetworkScan", "AlphaFlow", "MultiPoints"]
    for keyword in taxonomy_keywords:
        if keyword.lower() in query_text.lower():
            filter_dict["taxonomy"] = keyword
            break
    
    # Extract label filter (e.g., "suspicious", "anomalous")
    if "suspicious" in query_text.lower():
        filter_dict["label"] = "suspicious"
    elif "anomalous" in query_text.lower():
        filter_dict["label"] = "anomalous"
    
    return filter_dict if filter_dict else None


# === Utility: Cross-Encoder Reranking ===
def rerank_with_cross_encoder(query, documents, top_k=None):
    """
    Rerank documents using a cross-encoder model for improved relevance scoring.
    Cross-encoders jointly encode (query, document) pairs for more accurate scoring
    than bi-encoders which encode them separately.

    Args:
        query (str): The user query.
        documents (list): List of document strings to rerank.
        top_k (int): Number of top documents to return after reranking (default: all).

    Returns:
        list: Reranked documents in order of relevance (highest score first).
    """
    if not documents:
        return []
    
    # Create (query, document) pairs
    pairs = [[query, doc] for doc in documents]
    
    # Score all pairs with cross-encoder
    scores = cross_encoder.predict(pairs)
    
    # Combine documents with scores and sort by score (descending)
    doc_score_pairs = list(zip(documents, scores))
    doc_score_pairs.sort(key=lambda x: x[1], reverse=True)
    
    # Extract just the documents (now reranked)
    reranked_docs = [doc for doc, score in doc_score_pairs]
    
    # Return top_k if specified, otherwise all
    if top_k:
        return reranked_docs[:top_k]
    return reranked_docs


# === Utility: Match anomalies using IPs ===
def match_anomaly_docs(ip_list, store, k=6, threshold=0.3, metadata_filter=None):
    """
    Given a list of IP addresses, search for related anomaly documents in the vector store.
    Uses MMR (Maximal Marginal Relevance) to retrieve diverse, non-redundant results.
    Filters out results below similarity threshold.
    Supports optional metadata filtering (e.g., protocol, port, taxonomy).

    Args:
        ip_list (list): List of IP addresses (str) to look up.
        store (Chroma): Chroma vector store object.
        k (int): Number of top similar documents to retrieve per IP.
        threshold (float): Minimum similarity score (0-1) to accept a result.
        metadata_filter (dict): Optional ChromaDB filter for metadata (e.g., {"taxonomy": "DoS"}).

    Returns:
        tuple: (list of matched documents, max_similarity_score)
    """
    matched_docs = []
    max_similarity = 0.0
    
    for ip in ip_list:
        # Build filter: combine metadata_filter with IP search
        # ChromaDB filter syntax: {"field": "value"} or {"field": {"$eq": "value"}}
        filter_dict = metadata_filter.copy() if metadata_filter else {}
        
        # Step 1: Use MMR for diverse retrieval (fetch more candidates than needed)
        # Note: MMR doesn't return scores directly, so we'll get scores separately
        if filter_dict:
            # Get diverse results with MMR and metadata filtering
            mmr_results = store.max_marginal_relevance_search(ip, k=k, fetch_k=k*3, filter=filter_dict)
            # Get scores for the same query to calculate similarity
            results_with_scores = store.similarity_search_with_score(ip, k=k*3, filter=filter_dict)
        else:
            # Get diverse results with MMR
            mmr_results = store.max_marginal_relevance_search(ip, k=k, fetch_k=k*3)
            # Get scores for the same query
            results_with_scores = store.similarity_search_with_score(ip, k=k*3)
        
        # Create a mapping of document content to similarity scores
        score_map = {}
        for doc, score in results_with_scores:
            # Convert distance to similarity (ChromaDB returns L2 distance, lower = more similar)
            similarity = 1.0 - (score / 2.0)
            score_map[doc.page_content] = similarity
            max_similarity = max(max_similarity, similarity)
        
        # Step 2: Filter MMR results by threshold and IP presence
        for doc in mmr_results:
            similarity = score_map.get(doc.page_content, 0.0)
            
            # Only include if above threshold and IP appears in document
            if similarity >= threshold and ip in doc.page_content:
                matched_docs.append(doc.page_content)
    
    # Remove duplicates
    return list(set(matched_docs)), max_similarity


# === Utility: Get prefix → taxonomy category map ===
def parse_heuristic_docs_for_prefixes(store):
    """
    Parse heuristic/taxonomy documents from the store and build a prefix-to-category mapping.

    Args:
        store (Chroma): Chroma vector store for heuristic/taxonomy data.

    Returns:
        dict: Dictionary mapping each prefix (str) to its category (str).
    """
    # Search using "prefixes" keyword to find taxonomy group documents
    docs = store.similarity_search("prefixes", k=5)
    prefix_map = {}
    for doc in docs:
        content = doc.page_content if isinstance(doc, Document) else str(doc)

        # Extract the "Category" line
        category_match = re.search(r"Category:\s*(.+)", content)
        # Extract the "Prefixes" line
        prefixes_match = re.search(r"Prefixes:\s*(.+)", content)

        if category_match and prefixes_match:
            category = category_match.group(1).strip()
            prefixes = [p.strip() for p in prefixes_match.group(1).split(",")]
            for prefix in prefixes:
                prefix_map[prefix] = category
    return prefix_map


# === Utility: Match heuristic/taxonomy context ===
def match_heuristic_docs(anomaly_docs, store, k=3):
    """
    For a given list of anomaly documents, this function extracts heuristic IDs and taxonomy prefixes,
    then uses them to retrieve relevant heuristic and taxonomy context documents from the knowledge base.

    Args:
        anomaly_docs (list): List of anomaly document strings.
        store (Chroma): Chroma vector store that holds heuristic/taxonomy information.
        k (int): Number of top similar results to retrieve per search.

    Returns:
        list: Deduplicated list of matched heuristic/taxonomy document strings.
    """

    heuristic_ids = set()      # To store unique heuristic codes found in anomaly docs (e.g., "20" for ping flood).
    taxonomy_prefixes = set()  # To store unique prefixes that might indicate taxonomy groupings (e.g., "ntscIC").

    # Extract heuristic IDs and taxonomy prefixes from each anomaly document
    for doc in anomaly_docs:
        # Find all numeric codes of 3 or 4 digits, which likely correspond to heuristic IDs
        heuristic_ids.update(re.findall(r'\b\d{3,4}\b', doc))
        # Find all longer alphabetic prefixes (≥4 letters), possible taxonomy prefixes
        taxonomy_prefixes.update(re.findall(r'\b[a-zA-Z]{4,}\b', doc))

    matched_docs = []

    # For each heuristic ID found, search in the store to retrieve heuristic documents
    # Use MMR for diversity
    for hid in heuristic_ids:
        results = store.max_marginal_relevance_search(hid, k=k, fetch_k=10)
        # Add contents if heuristic ID actually appears in the document text
        matched_docs.extend([doc.page_content for doc in results if hid in doc.page_content])

    # Get prefix-to-category map from taxonomy documents
    prefix_map = parse_heuristic_docs_for_prefixes(store)
    
    # For each taxonomy prefix found, if it matches a known category, create a short entry
    for prefix in taxonomy_prefixes:
        if prefix in prefix_map:
            entry = f"Category: {prefix_map[prefix]}\nPrefix: {prefix}"
            matched_docs.append(entry)

    # Remove duplicates and return
    return list(set(matched_docs))

# === RAG Analysis ===
def generate_rag_analysis(query_text, similarity_threshold=0.3):
    """
    Main function that performs Retrieval-Augmented Generation (RAG) analysis for a given user query.
    It integrates evidence from Chroma vector stores and generates a reasoned explanation using an LLM.
    Abstains from answering if evidence quality is below threshold.
    Supports metadata filtering for forensic precision.

    Args:
        query_text (str): User-provided summary or description of a ping flood alert.
        similarity_threshold (float): Minimum similarity score to proceed with analysis (default: 0.3).

    Returns:
        str: LLM-generated analytical response with justification and recommended action,
             or abstention message if evidence is insufficient.
    """

    # Extract any IP addresses mentioned in the query text
    alert_ips = extract_ips(query_text)
    
    # Parse optional metadata filters from query (e.g., "port 443", "DoS taxonomy")
    metadata_filter = parse_metadata_filter(query_text)
    
    # If no IPs found, search semantically for relevant alerts
    if not alert_ips:
        # Fallback: semantic search on the query itself
        anomaly_contents = []
        max_similarity = 0.0
    else:
        # Find anomaly records in the CSV store that mention these IPs (with threshold check and metadata filtering)
        anomaly_contents, max_similarity = match_anomaly_docs(
            alert_ips, 
            anomaly_csv_store, 
            threshold=similarity_threshold,
            metadata_filter=metadata_filter
        )

    # Check if evidence quality is sufficient
    if max_similarity < similarity_threshold and len(anomaly_contents) == 0:
        missing_info = []
        if not alert_ips:
            missing_info.append("no specific IP addresses identified")
        else:
            missing_info.append(f"no anomaly records found for IPs: {', '.join(alert_ips)}")
        
        if metadata_filter:
            missing_info.append(f"with filters: {metadata_filter}")
        
        return (
            f"⚠️ **UNDECIDABLE** - Insufficient evidence to provide reliable analysis.\n\n"
            f"**Reason:** Maximum similarity score ({max_similarity:.2f}) is below threshold ({similarity_threshold}).\n"
            f"**Missing context:** {'; '.join(missing_info)}.\n\n"
            f"**Recommendation:** Please provide:\n"
            f"  - More specific IP addresses or timestamps\n"
            f"  - Additional context about the suspicious activity\n"
            f"  - Relevant log entries or anomaly records\n"
        )

    # Retrieve heuristic/taxonomy context that matches the anomaly records
    heuristic_contents = match_heuristic_docs(anomaly_contents, heuristic_txt_store)

    # === Cross-Encoder Reranking for improved relevance ===
    # Rerank anomaly documents using cross-encoder for better precision
    if anomaly_contents:
        anomaly_contents = rerank_with_cross_encoder(query_text, anomaly_contents, top_k=6)
    
    # Rerank heuristic documents as well
    if heuristic_contents:
        heuristic_contents = rerank_with_cross_encoder(query_text, heuristic_contents, top_k=5)

    # Treat the user query itself as the main ping flood alert content
    ping_flood_contents = [query_text]

    # Assemble the context dictionary to populate the prompt template
    context = {
        "ping_flood_alerts2": "\n".join(ping_flood_contents) or "No alerts found.",
        "anomaly_csv": "\n".join(anomaly_contents) or "No anomaly data found.",
        "heuristic_context": "\n".join(heuristic_contents) or "No heuristic context available."
    }

    # Format the final prompt using the structured context
    prompt = ping_flood_prompt.format(**context)

    # Initialize ChatOpenAI LLM
    llm = ChatOpenAI(model_name="gpt-4.1-nano", temperature=0)

    # Send the prompt to the LLM and get its response
    response = llm.invoke([{"role": "user", "content": prompt}])
    return response.content


# === Raw Log File Processing Functions ===

def prepare_conn_log_for_llm(file_path):
    """
    Read and prepare a Zeek conn.log file for LLM analysis.
    Filters to ICMP traffic by default, falls back to all traffic if no ICMP found.
    
    Args:
        file_path (str): Path to the conn.log file.
        
    Returns:
        str: Formatted log text ready for analysis, or error message.
    """
    try:
        with open(file_path, 'r') as f:
            lines = [line.strip() for line in f if not line.startswith("#")]
        
        # Filter lines to those with proto field == 'icmp'
        icmp_lines = [line for line in lines if len(line.split('\t')) > 6 and line.split('\t')[6].lower() == 'icmp']
        
        # If no ICMP lines, fallback to all lines
        return "\n".join(icmp_lines) if icmp_lines else "\n".join(lines)
    except Exception as e:
        return f"Error reading file: {e}"


def cap_text(text, max_chars):
    """
    Truncate text cleanly at max_chars, preserving whole lines if possible.
    
    Args:
        text (str): Text to truncate.
        max_chars (int): Maximum character count.
        
    Returns:
        str: Truncated text.
    """
    if len(text) <= max_chars:
        return text
    
    lines = text.split('\n')
    capped = []
    current_len = 0
    
    for line in lines:
        if current_len + len(line) + 1 > max_chars:
            break
        capped.append(line)
        current_len += len(line) + 1
    
    return "\n".join(capped)


def generate_rag_analysis_from_log(conn_log_text):
    """
    Generate RAG analysis directly from raw Zeek conn.log text.
    This version is simpler and optimized for batch processing of log files.
    
    Args:
        conn_log_text (str): Raw conn.log content (tab-separated).
        
    Returns:
        str: LLM-generated analysis of the log file.
    """
    # Extract IPs from the log text
    alert_ips = extract_ips(conn_log_text)
    
    # Match anomaly documents using the extracted IPs (simplified version without threshold)
    matched_anomaly_docs = []
    for ip in alert_ips:
        results = anomaly_csv_store.similarity_search(ip, k=7)
        for doc in results:
            if ip in doc.page_content:
                matched_anomaly_docs.append(doc.page_content)
    
    anomaly_contents = list(set(matched_anomaly_docs))
    
    # Match heuristic documents based on anomaly data
    heuristic_contents = match_heuristic_docs(anomaly_contents, heuristic_txt_store)
    
    # Limit each section to reduce total tokens
    context = {
        "ping_flood_alerts2": cap_text(conn_log_text, 2500),
        "anomaly_csv": "\n".join(anomaly_contents) if anomaly_contents else "No anomaly data found.",
        "heuristic_context": "\n".join(heuristic_contents) if heuristic_contents else "No heuristic context available."
    }
    
    # Format the prompt
    prompt = ping_flood_prompt.format(**context)
    
    # Initialize ChatOpenAI LLM
    llm = ChatOpenAI(model_name="gpt-4.1-mini", temperature=0)
    
    # Send the prompt to the LLM and get its response
    response = llm.invoke([{"role": "user", "content": prompt}])
    return response.content


def run_folder_analysis(input_folder, output_folder):
    """
    Batch process all .log files in input_folder and save RAG analysis to output_folder.
    This is optimized for evaluation workflows where you have many log files to analyze.
    
    Args:
        input_folder (str): Directory containing conn.log files to analyze.
        output_folder (str): Directory to save RAG analysis text files.
    """
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)
    
    # Get all .log files
    log_files = [f for f in os.listdir(input_folder) if f.endswith(".log")]
    
    print(f"\n{'='*60}")
    print(f"🚀 Batch RAG Analysis - Processing {len(log_files)} log files")
    print(f"{'='*60}")
    print(f"📂 Input folder:  {input_folder}")
    print(f"📁 Output folder: {output_folder}\n")
    
    processed = 0
    skipped = 0
    failed = 0
    
    for fname in log_files:
        full_path = os.path.join(input_folder, fname)
        output_filename = fname.rsplit(".", 1)[0] + ".txt"
        output_path = os.path.join(output_folder, output_filename)
        
        # Skip if already processed
        if os.path.exists(output_path):
            print(f"⏭️  Skipping {fname} (already exists)")
            skipped += 1
            continue
        
        print(f"🔍 Processing {fname}...")
        
        try:
            # Read and prepare the log file
            log_text = prepare_conn_log_for_llm(full_path)
            
            if log_text.startswith("Error"):
                print(f"❌ Skipping {fname} due to read error: {log_text}")
                failed += 1
                continue
            
            # Generate RAG analysis
            rag_response = generate_rag_analysis_from_log(log_text)
            
            # Save to output file
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(rag_response)
            
            print(f"✅ Completed {fname} → {output_filename}")
            processed += 1
            
        except Exception as e:
            print(f"❌ Error processing {fname}: {e}")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"📊 Batch Processing Complete!")
    print(f"{'='*60}")
    print(f"✅ Successfully processed: {processed}")
    print(f"⏭️  Skipped (existing):    {skipped}")
    print(f"❌ Failed:                {failed}")
    print(f"📁 Results saved to: {output_folder}\n")


# === CLI Interface ===
if __name__ == "__main__":
    import sys
    
    # Check if running in batch mode (with command-line arguments)
    if len(sys.argv) >= 3:
        # Batch mode: python rag_query.py <input_folder> <output_folder>
        input_folder = sys.argv[1]
        output_folder = sys.argv[2]
        
        print("\n🔧 Running in BATCH MODE")
        run_folder_analysis(input_folder, output_folder)
        
    elif len(sys.argv) == 2 and sys.argv[1] in ['--help', '-h']:
        # Help mode
        print("""
╔════════════════════════════════════════════════════════════════╗
║   🛰️  AI-Assisted Backbone Traffic Anomaly Investigator       ║
╚════════════════════════════════════════════════════════════════╝

📚 USAGE:

1️⃣  Interactive Mode (Advanced RAG with thresholds & reranking):
   python rag_query.py
   
   Then describe suspicious events in natural language.
   Example: "Heavy ICMP ping storm to 3.30.218.60 at midnight"

2️⃣  Batch Mode (Process raw log files for evaluation):
   python rag_query.py <input_folder> <output_folder>
   
   Processes all .log files in input_folder and saves analysis
   to output_folder as .txt files.
   
   Example:
   python rag_query.py ./split_logs ./rag_outputs

3️⃣  Help:
   python rag_query.py --help

🔍 Features:
   • Cross-encoder reranking for precision
   • MMR for diverse retrieval
   • Similarity thresholds with abstention
   • Metadata filtering support
   • Batch processing for evaluation
        """)
        sys.exit(0)
        
    else:
        # Interactive mode: Advanced RAG system
        print("""
=========================================================
🛰️  AI-Assisted Backbone Traffic Anomaly Investigator

👋 Welcome, Analyst! You're about to consult your AI-powered co-pilot
for backbone traffic anomaly detection and expert-level interpretation.

This is the ADVANCED RAG mode with:
✨ Cross-encoder reranking
✨ Similarity thresholds & abstention
✨ MMR for diverse retrieval
✨ Metadata filtering support

💡 What you can enter:
- A quick note like "Heavy ICMP ping storm to 3.30.218.60 at midnight"
- A suspicious event summary: "Unexpected scan-like surge to data center"
- A curious observation: "Strange high-volume flow from unknown host"
- Metadata filters: "DoS attack on port 443 to 192.168.1.1"

Your AI partner will analyze it, cross-check your anomaly knowledge base,
reference heuristic and taxonomy context, and recommend decisive action.

Type 'exit' anytime to end your investigation.
For batch processing, use: python rag_query.py <input_folder> <output_folder>
""")

        while True:
            query = input("\n🕵️ Describe the suspicious network event you'd like me to analyze or type exit: ")
            if query.strip().lower() == "exit":
                print("✅ Session ended. Stay vigilant out there! 🚨")
                break

            # Run the RAG analysis and display result
            result = generate_rag_analysis(query)
            print("\n💡 AI-Generated Explanation & Action Plan:\n", result)


# === CLI Interface ===
if __name__ == "__main__":

    print("""
=========================================================
🛰️  AI-Assisted Backbone Traffic Anomaly Investigator

👋 Welcome, Analyst! You’re about to consult your AI-powered co-pilot
for backbone traffic anomaly detection and expert-level interpretation.

💡 What you can enter:
- A quick note like "Heavy ICMP ping storm to 3.30.218.60 at midnight"
- A suspicious event summary: "Unexpected scan-like surge to data center"
- A curious observation: "Strange high-volume flow from unknown host"

Your AI partner will analyze it, cross-check your anomaly knowledge base,
reference heuristic and taxonomy context, and recommend decisive action.

Type 'exit' anytime to end your investigation.
""")

    while True:
        query = input("\n🕵️ Describe the suspicious network event you'd like me to analyze or type exit: ")
        if query.strip().lower() == "exit":
            print("✅ Session ended. Stay vigilant out there! 🚨")
            break

        # Run the RAG analysis and display result
        result = generate_rag_analysis(query)
        print("\n💡 AI-Generated Explanation & Action Plan:\n", result)
