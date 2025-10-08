# === Import necessary libraries ===
import os
import re
from dotenv import load_dotenv
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import Chroma
from langchain.chat_models import ChatOpenAI
from langchain.retrievers import EnsembleRetriever
from langchain.prompts import PromptTemplate
from langchain.schema import Document

# === Load environment variables from .env file ===
load_dotenv()

# === Set environment settings ===
os.environ["TOKENIZERS_PARALLELISM"] = "false"  # Disable parallelism in tokenizers to avoid warning messages

# Embeddings
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

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


# === Utility: Match anomalies using IPs ===
def match_anomaly_docs(ip_list, store, k=6):
    """
    Given a list of IP addresses, search for related anomaly documents in the vector store.

    Args:
        ip_list (list): List of IP addresses (str) to look up.
        store (Chroma): Chroma vector store object.
        k (int): Number of top similar documents to retrieve per IP.

    Returns:
        list: Deduplicated list of anomaly document contents (strings) that mention the IPs.
    """
    matched_docs = []
    for ip in ip_list:
        results = store.similarity_search(ip, k=k)
        for doc in results:
            # Double-check that IP really appears in the document text
            if ip in doc.page_content:
                matched_docs.append(doc.page_content)
    # Remove duplicates
    return list(set(matched_docs))


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
    for hid in heuristic_ids:
        results = store.similarity_search(hid, k=k)
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
def generate_rag_analysis(query_text):
    """
    Main function that performs Retrieval-Augmented Generation (RAG) analysis for a given user query.
    It integrates evidence from Chroma vector stores and generates a reasoned explanation using an LLM.

    Args:
        query_text (str): User-provided summary or description of a ping flood alert.

    Returns:
        str: LLM-generated analytical response with justification and recommended action.
    """

    # Extract any IP addresses mentioned in the query text
    alert_ips = extract_ips(query_text)

    # Find anomaly records in the CSV store that mention these IPs
    anomaly_contents = match_anomaly_docs(alert_ips, anomaly_csv_store)

    # Retrieve heuristic/taxonomy context that matches the anomaly records
    heuristic_contents = match_heuristic_docs(anomaly_contents, heuristic_txt_store)

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
