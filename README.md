# LLM-Driven Backbone Traffic Analysis for Anomaly Detection and Generating Explanations


## About

This repository provides a fully working pipeline to build a semantic anomaly knowledge base using [MAWILab](http://www.fukuda-lab.org/mawilab/) backbone traffic anomaly logs, ChromaDB as a vector database, and sentence-transformer embeddings for semantic retrieval. The prepared knowledge base will be integrated into a Retrieval-Augmented Generation (RAG) system for advanced anomaly analysis and explanation.

---

## Features

- Ingest raw anomaly logs from MAWILab CSV files.
- Automatically summarize each anomaly into descriptive text.
- Generate semantic embeddings using Sentence Transformers (`all-MiniLM-L6-v2`).
- Store embeddings, summaries, IDs, and metadata in ChromaDB.
- Enable semantic anomaly search (ready for RAG integration).

---

## MawiLab Dataset

The MAWILab dataset contains labeled backbone traffic anomalies, including:

- Source and destination IP addresses and ports.
- Taxonomy categories describing anomaly types.
- Heuristic codes indicating specific attack or scan signatures.
- Labels (e.g., `anomalous`, `suspicious`).

> Example summary:  
> *Anomaly ID anomaly_53: This is labeled as 'anomalous'. Source IP: unknown, Source Port: unknown, Destination IP: 18.158.38.252, Destination Port: unknown. Taxonomy classification: 'ntscICecrqICecrprp', heuristic code: 20.*

---

## Setup

###  Create and activate virtual environment (recommended)

It is recommended to create and activate a virtual environment before installing dependencies to keep your project isolated.


```cmd
python -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows
```

### Install dependencies

```
pip install -r requirements.txt
```

## Knowledge Base

### Ingest Anomaly CSV File
Download and put your MAWILab CSV file (e.g., 20220110_anomalous_suspicious - 20220110_anomalous_suspicious1.csv) in the project root folder and run the script.

What this does:
- Loads the CSV file and handles any missing values by marking them as unknown.

- Creates a clear text summary for each anomaly (including IPs, ports, taxonomy, and heuristic).

- Generates embeddings from these summaries using a sentence transformer.

- Stores the summaries, embeddings, unique IDs, and metadata into a ChromaDB collection for later semantic search or analysis.

- Prints each ingested summary to verify successful insertion.

Hence, the constructed knowledge base consists of structured and semantically enriched representations of backbone traffic anomalies derived from the MAWILab dataset. Each entry integrates a natural-language summary capturing essential attributes—such as source and destination IP addresses and ports, taxonomy classification, heuristic code, and anomaly label—while missing values are explicitly annotated to preserve completeness. These summaries are further transformed into dense vector embeddings using a sentence transformer model, enabling semantic similarity search and retrieval. Combined with rich metadata and unique identifiers, this design allows for precise, context-aware querying and supports integration into downstream tasks such as retrieval-augmented generation (RAG) systems for advanced anomaly explanation and analysis. 

---

### Ingest Heuristic & Taxonomy Information

This script ingests heuristic code descriptions and anomaly taxonomy groups into ChromaDB, building a semantic knowledge base that enriches later retrieval and reasoning steps.

What it does
- Parses a text file containing:

- Heuristic codes (e.g., * 10:SYN attack, * 20:Ping flood).

- Taxonomy groups with their prefixes (e.g., NetworkScanTCP, DoS).

- Embeds and stores each entry as a document with metadata in ChromaDB (heuristic_info_txt4 collection).

Hence, in this step, heuristic codes and taxonomy groupings are systematically extracted and transformed into semantically rich vector representations. Each heuristic entry includes a unique numerical identifier, an explicit label, and an interpreted behavioral description derived from port usage and protocol characteristics. In parallel, taxonomy group information organizes various network behaviors and scan patterns into structured categories using descriptive prefixes. By embedding this information and storing it in ChromaDB with detailed metadata, the system enables advanced, context-aware retrieval of detection logic and categorization rules. This foundational layer supports subsequent analysis tasks by providing immediate access to underlying detection criteria, thereby enhancing interpretability and operational transparency in anomaly analysis workflows.

---
### Zeek Connection Log Filtering (`conn.log`)

#### Purpose

This script filters large Zeek `conn.log` files to extract connections matching known anomaly signatures derived from the MAWILab anomaly CSV file. This reduces noise and focuses further analysis on potentially suspicious or malicious connections. Since the CSV from MAWILab only lists high-level anomaly indicators, converting pcap to conn.log and then matching is necessary to bridge that detail gap.

####  How It Works

- **Load anomaly rules:**  
  Reads a CSV file containing rules with `srcIP`, `srcPort`, `dstIP`, and `dstPort`. Any empty fields in the CSV act as wildcards (meaning "any value" is acceptable).

- **Stream and chunk processing:**  
  Processes `conn.log` in chunks (default: 100,000 lines) to handle very large files without exhausting memory.

- **Matching logic:**  
  For each connection entry, checks if it matches any anomaly rule. Matching connections are written to a new filtered log file.

- **Output:**  
  Generates a new file (`filtered_conn.log`) that includes only the connections matching anomaly criteria for focused analysis.

#### Configuration

- `CONN_LOG_PATH`: Path to the original Zeek `conn.log` file.
- `ANOMALY_CSV_PATH`: Path to the MAWILab anomaly CSV file containing IP and port rules.
- `OUTPUT_PATH`: Path to save the filtered connection log.

#### When to Use

Use this script before embedding or further detection steps to reduce data size and focus on high-risk flows. It prepares the dataset for subsequent tasks like ping flood detection or semantic explanation using your knowledge base.

---
### Ingest Ping Flood

In this step, we analyze Zeek network connection logs from previous step to automatically detect potential ping flood attacks by identifying unusually high numbers of ICMP echo requests targeting specific destination IPs within a short time window. After detecting these suspicious events, we generate clear, human-readable summaries that describe when and where each ping flood occurred and how many packets were involved. We then embed these summaries and store them as a new collection in ChromaDB, expanding the knowledge base with concrete, real-world evidence of active or historical attacks. This allows the system to later cross-reference live detections with previously ingested anomalies and heuristics, enabling richer context-aware explanations and threat reasoning.


This module is responsible for detecting potential ICMP ping flood attacks from Zeek connection logs and ingesting structured summaries into ChromaDB for further analysis and retrieval.

#### Overview

- **Input**: Zeek `conn.log` file containing detailed network connection records.
- **Processing**:
  - Parses connection logs to extract timestamp, source IP, destination IP, destination port, and protocol.
  - Identifies bursts of ICMP Echo Requests (commonly used in ping floods) based on a configurable threshold and time window.
  - Generates human-readable summaries describing detected floods, including affected IP addresses and time ranges.
- **Output**:
  - Creates descriptive text documents summarizing each detected ping flood.
  - Embeds these summaries into dense vectors using a sentence transformer model.
  - Stores them in a ChromaDB collection (`ping_flood_alerts2`) with rich metadata for future semantic search and analysis.

#### Key Parameters

- `threshold`: Minimum number of ICMP Echo Requests required to trigger a flood alert (default: 5).
- `time_window`: Time window (seconds) within which these requests must occur (default: 5).

#### Why ICMP Echo Requests?

ICMP Echo Requests (commonly known as "pings") with destination port `8` are often leveraged in denial-of-service (DoS) attacks to overwhelm network targets. By clustering high-frequency pings within short time windows, this module effectively highlights potential flood attacks.

#### Usage

1. **Configure** the log file path in the script (`zeek_file`).
2. **Adjust** detection parameters if needed (`threshold`, `time_window`).
3. **Run** the script to parse logs, detect floods, and ingest alerts into ChromaDB.
4. **Review** printed summaries and verify successful ingestion.

> The ingested ping flood summaries can later be retrieved and analyzed in combination with anomaly knowledge base entries and heuristic taxonomy information in your RAG system.

----
### RAG Analysis Module (Retrieval-Augmented Generation)

#### Overview

This module implements a **Retrieval-Augmented Generation (RAG)** pipeline that integrates Chroma-based vector retrieval with a large language model (LLM) to support advanced cybersecurity analysis of potential ping flood attacks.

#### How It Works

- **Semantic Retrieval**: The system extracts IP addresses from the input query and performs similarity searches against three Chroma collections:
  - `ping_flood_alerts2`: Embedded summaries of detected ping flood events.
  - `anomaly_csv_logs4`: Structured anomaly records derived from the MAWILab dataset.
  - `heuristic_info_txt4`: Heuristic codes and anomaly taxonomy descriptions.

- **Evidence Integration**: Retrieved documents are merged to form a comprehensive context containing event descriptions, anomaly details, and heuristic/taxonomy explanations.

- **Prompt-Guided Reasoning**: A structured prompt template instructs the LLM, which is gpt-4.1-nano in this study,to generate an evidence-based, transparent analysis that explicitly references anomaly IDs, heuristic codes, and taxonomy categories. The response includes a final security recommendation.

#### Key Features

- **Explainability**: Outputs justify detections with clear references to supporting evidence, improving interpretability and analyst trust.
- **Precision Matching**: IP-based retrieval and semantic filtering ensure only the most relevant logs and heuristic information are used.
- **Actionable Insights**: Final outputs provide concise security actions, such as blocking IP addresses or rate-limiting ICMP traffic.

#### Usage

To run the module, execute:

```bash
python rag_query.py



# Query Samples: Analyze heuristic code 20 (Ping flood) event and provide supporting anomaly evidence with source IPs.
