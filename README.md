# ReGAIN: Retrieval-Grounded AI Framework for Network Traffic Analysis

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## Overview

**ReGAIN** (Retrieval-Grounded AI Framework for Network Traffic Analysis) is a novel LLM-driven framework for intelligent network traffic analysis that combines structured preprocessing, semantic embeddings, vector-based retrieval, and large language model reasoning to deliver high-accuracy, explainable network security analysis.

### Performance Highlights

- **99.3% accuracy** and **99.2% recall** on annotated logs  
- **97.6% accuracy** with **perfect recall** on unseen logs  
- **Evidence-backed explanations** reducing hallucinations and improving operator trust  
- **Human-in-the-loop interaction** for iterative forensic analysis  

Unlike traditional traffic analysis systems—whether rule-based or machine learning–driven—ReGAIN provides transparent, interpretable diagnoses by explicitly citing supporting evidence from a semantic knowledge base. This addresses critical limitations: high false positives, limited explainability, and slow incident response.

**Paper**: _ReGAIN: Retrieval-Grounded AI Framework for Network Traffic Analysis_ (2025)  
**Code & Data**: [github.com/270771/llm-traffic](https://github.com/270771/llm-traffic)

---

## System Architecture

ReGAIN comprises four main components:

```
┌─────────────────────────────────────────────────────────────────┐
│                    1. Data Ingestion & Summarization            │
│  MAWILab Dataset (.csv, .log, pcap) → Normalized Records        │
│              → Natural Language Summaries                       │
└──────────────────────────┬──────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│         2. Semantic Vectorization & Knowledge Base Builder      │
│  Summaries → Embeddings (all-MiniLM-L6-v2)                      │
│           → ChromaDB Vector Store + Metadata                    │
└──────────────────────────┬──────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│           3. Retrieval-Augmented Reasoning (LLM)                │
│  User Query → Semantic Search → MMR + Cross-Encoder             │
│            → Evidence Retrieval → GPT-4 Analysis                │
└──────────────────────────┬──────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────────┐
│              4. Human-in-the-Loop Interaction                   │
│  Diagnosis + Citations + Actions → Analyst Refinement           │
│              → Iterative Forensic Investigation                 │
└─────────────────────────────────────────────────────────────────┘
```

### Component Descriptions

1. **Data Ingestion & Summarization**: Normalizes heterogeneous traffic telemetry (logs, CSVs, pcaps) into structured records and natural-language summaries

2. **Semantic Vectorization**: Encodes summaries into 384-D dense embeddings and stores them with rich metadata in ChromaDB for efficient retrieval

3. **Retrieval-Augmented Reasoning**: Employs hybrid retrieval (semantic + metadata filtering), MMR diversity, cross-encoder reranking, and GPT-4-based explanation generation with evidence citations

4. **Human-in-the-Loop**: Supports iterative query refinement and forensic workflows with transparent, evidence-backed outputs

---

## Quick Start

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/270771/llm-traffic.git
cd llm-traffic

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure API Key

Create a `.env` file in the project root:

```bash
OPENAI_API_KEY=your_openai_api_key_here
```

### 3. Build Knowledge Base

Execute the ingestion scripts in order:

```bash
# Step 1: Ingest MAWILab anomaly records
python ingestion_anomaly.py

# Step 2: Ingest heuristic and taxonomy information
python ingestion_heur_tax

# Step 3: Detect and ingest historical ping flood patterns
python ingestion_pingflood.py
```

This populates three ChromaDB collections:
- `anomaly_csv_logsc01`: Structured anomaly records  
- `heuristic_info_txt4`: Detection rules and behavioral taxonomy  
- `ping_flood_alerts2`: Historical ping flood events  

### 4. Run ReGAIN Analysis

**Interactive Mode** (Natural language queries):
```bash
python rag_query.py
```

Example queries:
```
"Heavy ICMP ping storm to 3.30.218.60 at midnight"
"Explain unusual ICMP activity toward 203.0.113.5 around 10:05"
"DoS attack on port 443 involving 192.168.1.1"
```

**Batch Mode** (Process multiple log files):
```bash
python rag_query.py <input_folder> <output_folder>
```

Example:
```bash
python rag_query.py ./c101split/test1 ./rag_outputs_c101
```

**Help**:
```bash
python rag_query.py --help
```

---

## Performance Evaluation

ReGAIN was evaluated on ICMP ping flood detection using the MAWILab v1.1 dataset with chronological train/test split.

### Results: Known Logs (Training Data)

| Metric | Ground Truth | Expert Review |
|--------|--------------|---------------|
| Accuracy | **99.26%** | **98.00%** |
| Precision | 98.74% | 99.12% |
| Recall | 99.24% | 95.63% |
| F1 Score | 98.99% | 97.34% |
| AUC-ROC | 0.99 | 0.98 |

### Results: Unknown Logs (Unseen Test Data - c101)

| Metric | Ground Truth | Expert Review |
|--------|--------------|---------------|
| Accuracy | **97.56%** | **97.74%** |
| Precision | 74.48% | 76.36% |
| Recall | **100.0%** | **100.0%** |
| F1 Score | 85.35% | 86.58% |
| AUC-ROC | 0.99 | 0.99 |

### Key Findings

✅ **Near-perfect sensitivity**: 100% recall ensures no ping floods are missed  
✅ **High precision on known data**: Controlled false positive rates  
✅ **Perfect recall on unseen data**: Maintained even on chronologically-split test set  
✅ **Expert validation**: Confirms robustness and generalization capability  
✅ **Strong discriminative power**: AUC-ROC ≥ 0.98 across all scenarios  

The precision-recall trade-off on unseen data reflects a conservative design: the system prioritizes sensitivity to ensure no attacks are missed, accepting a moderate increase in false positives that can be efficiently triaged given the transparent, evidence-backed explanations.

---

## Dataset

### MAWILab v1.1 Backbone Traffic

ReGAIN uses the [MAWILab v1.1 dataset](http://www.fukuda-lab.org/mawilab/), which provides labeled backbone traffic anomalies from the WIDE backbone network.

**Data Components**:
1. **Packet Captures (pcap)**: Raw network traffic traces  
2. **Anomaly CSVs**: Dual-labeled structured annotations:
   - **Heuristic labels**: Signature/flag/port/type-code driven  
   - **Taxonomy labels**: Behavioral categories (DoS, scans, tunneling)  

**Record Schema**:
- **5-tuple**: Source/destination IP:port, protocol  
- **Heuristic codes**: Attack-specific signatures  
  - `20`: ICMP ping flood  
  - `10`: SYN attack  
  - Others: Port scans, tunneling, etc.  
- **Taxonomy**: Behavioral classification (e.g., `ntscICecrqICecrprp`)  
- **Severity**: `anomalous`, `suspicious`, `notice`, `benign`  

**Example Record**:
```
Anomaly ID: anomaly_53
Label: anomalous
Source: unknown:unknown → Destination: 18.158.38.252:unknown
Protocol: ICMP | Taxonomy: ntscICecrqICecrprp | Heuristic: 20
```

### Chronological Train/Test Split

To assess generalization and prevent temporal leakage:
- **Known/Training Data (inragsplit)**: Earlier days for framework development  
- **Unknown/Test Data (c101split)**: Later days held out for unseen traffic evaluation  

This methodology ensures performance metrics reflect real-world deployment where the system encounters novel attack patterns.

---

## Knowledge Base Construction

### 1. Anomaly CSV Ingestion (`ingestion_anomaly.py`)

**Purpose**: Convert MAWILab anomaly records into semantically searchable documents.

**Process**:
1. Load anomaly CSV and handle missing values  
2. Generate natural-language summaries for each anomaly  
3. Create 384-D embeddings using `all-MiniLM-L6-v2`  
4. Store in ChromaDB collection `anomaly_csv_logsc01` with metadata  

**Output**: Semantic knowledge base of 10K+ historical anomaly patterns.

---

### 2. Heuristic & Taxonomy Ingestion (`ingestion_heur_tax`)

**Purpose**: Encode detection logic and attack categorization rules.

**Process**:
1. Parse heuristic codes (e.g., `20: Ping flood attack`)  
2. Extract taxonomy group definitions with behavioral prefixes  
3. Embed descriptions and store in `heuristic_info_txt4`  

**Output**: Searchable repository of detection criteria for LLM grounding.

---

### 3. Ping Flood Detection (`ingestion_pingflood.py`)

**Purpose**: Identify historical ping flood attacks in Zeek connection logs.

**Process**:
1. Parse Zeek `conn.log` files for ICMP traffic  
2. Detect echo request bursts using configurable heuristics  
3. Generate attack summaries with timestamps and targets  
4. Store in `ping_flood_alerts2` collection  

**Configuration**:
- `threshold`: Minimum ICMP requests to trigger detection (default: 5)  
- `time_window`: Time window in seconds (default: 5)  

---

## RAG Analysis Engine

### Advanced Retrieval Features

- **Cross-Encoder Reranking**: Improves relevance precision over bi-encoder retrieval  
- **MMR Diversity**: Prevents redundant context using Maximal Marginal Relevance  
- **Similarity Thresholds**: Abstains when evidence quality is insufficient  
- **Metadata Filtering**: Supports forensic constraints (protocol, port, time window, taxonomy)  

### Dual Operation Modes

**1. Interactive Mode** (Advanced RAG with Human-in-the-Loop)
- Natural language queries  
- Evidence-based reasoning with explicit citations  
- Abstention on low-confidence cases (`UNDECIDABLE` outputs)  
- Iterative query refinement  

**2. Batch Mode** (Large-Scale Evaluation)
- Processes folders of log files  
- Optimized for throughput (simplified retrieval)  
- Progress tracking with status indicators  
- Automatic resume (skips existing outputs)  

### Prompt Engineering

The structured prompt template enforces:
1. **Grounded reasoning**: LLM must cite retrieved evidence IDs  
2. **Consistent schema**: `{verdict, justification, mitigation}`  
3. **Abstention mechanism**: Output `UNDECIDABLE` when evidence is lacking  
4. **Actionable outputs**: 1-2 concrete security recommendations  

**Example Output**:
```
Verdict: ATTACK (ICMP ping flood)
Evidence: Anomaly_57 [356 ICMP type=8 to 3.20.63.105 in 5s]
Reasoning: Heuristic 20 and taxonomy tscICecrqICecrprp confirm ping flood.
Mitigation: (1) Block source IPs at firewall, (2) Apply ICMP rate limiting.
```

---

## Evaluation Methodology

### Four-Scenario Evaluation Matrix

| Scenario | Ground Truth Source | Data Type | Figure |
|----------|-------------------|-----------|--------|
| Known–Ground Truth | Automated labels | Training data | 3(b) |
| Unknown–Ground Truth | Automated labels | Test data (c101) | 3(c) |
| Known–Expert | Manual expert labels | Training data | 4(b) |
| Unknown–Expert | Manual expert labels | Test data (c101) | 4(c) |

### Running Evaluations

```bash
python evaluate_rag.py
```

**Configuration** (edit paths in `evaluate_rag.py`):
```python
# Example: Figure 4(c) - Unknown–Expert evaluation
ground_truth_txt_path = "./c101_manual_gt_labels.txt"
rag_outputs_folder = "./rag_outputs_c101split1"
```

### Metrics

- **Confusion Matrix**: TP, TN, FP, FN distribution  
- **ROC Curve**: TPR vs. FPR across thresholds  
- **AUC**: Area under ROC curve  
- **Classification Report**: Precision, Recall, F1-Score, Accuracy  

### Expert Adjudication Process

Manual review addressed:
1. Prediction-ground truth mismatches  
2. Under-represented cases in anomaly CSVs  
3. Ambiguous log entries requiring domain expertise  

**Validation Heuristics**:
- ≥10 ICMP echo requests from same source → ping flood  
- 5-9 requests + CSV corroboration → flag for review  
- <5 requests → not an attack  

This process corrects for incomplete ground truth and validates generalization.

---

## Preprocessing Utilities

### Log Splitting (`preprocessing/split_conn_log.py`)

Divides large Zeek logs into manageable chunks for parallel processing.

### Ground Truth Labeling (`preprocessing/label_ping_flood_logs.py`)

Generates automated ground truth labels:
- Detects ping floods using configurable heuristics  
- Outputs JSON with per-file boolean labels  
- Used as baseline for RAG system validation  

### Connection Log Filtering (`filter.py`)

Filters Zeek logs to extract connections matching MAWILab signatures:
- Reduces noise for focused analysis  
- Supports wildcard matching on IP/port fields  
- Memory-efficient chunked processing (100K lines/chunk)  

---

## Project Structure

```
llm-traffic/
├── ingestion_anomaly.py           # MAWILab CSV → ChromaDB
├── ingestion_heur_tax             # Heuristic/taxonomy → ChromaDB
├── ingestion_pingflood.py         # Ping flood detection → ChromaDB
├── rag_query.py                   # ReGAIN analysis engine (interactive + batch)
├── evaluate_rag.py                # Evaluation framework
├── filter.py                      # Zeek log filtering
├── preprocessing/
│   ├── split_conn_log.py          # Log file splitter
│   └── label_ping_flood_logs.py   # Automated labeling
├── chroma_db/                     # ChromaDB vector store
│   ├── anomaly_csv_logsc01/       # Anomaly records collection
│   ├── heuristic_info_txt4/       # Heuristics/taxonomy collection
│   └── ping_flood_alerts2/        # Ping flood alerts collection
├── inragsplit/                    # Known/training log files
│   └── ping_flood_labels.json     # Automated ground truth (known)
├── c101split/test1/               # Unknown/test log files  
│   └── ping_flood_labels.json     # Automated ground truth (unknown)
├── manual_gt_labels.txt           # Expert labels (known data)
├── c101_manual_gt_labels.txt      # Expert labels (unknown data)
├── rag_outputs_inragsplit2/       # RAG outputs (known data)
├── rag_outputs_c101split1/        # RAG outputs (unknown data)
├── requirements.txt               # Python dependencies
├── README.md                      # This file
├── BATCH_PROCESSING_GUIDE.md      # Detailed batch mode documentation
└── EVALUATION_SETUP.md            # Complete evaluation configuration guide
```

---

## Technical Stack

### Models & Embeddings

| Component | Model | Configuration |
|-----------|-------|--------------|
| Embedding | `all-MiniLM-L6-v2` | 384-D dense vectors |
| Cross-Encoder | `ms-marco-MiniLM-L-6-v2` | Reranking top-k |
| LLM (Interactive) | GPT-4.1-nano | temperature=0, max_tokens=2048 |
| LLM (Batch) | GPT-4.1-mini | temperature=0, capped context |

### Infrastructure

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Vector Store | ChromaDB v1.0.15 | Persistent embedding storage |
| Orchestration | LangChain | Retrieval + prompt assembly |
| Parsing | Zeek | Flow/ICMP log extraction from pcaps |
| Computation | Sentence-Transformers | Local embedding generation |

### Performance Optimizations

- **Token management**: Context capping at 2500 chars (batch mode)  
- **Memory efficiency**: Chunked log processing (100K lines/chunk)  
- **Retrieval efficiency**: MMR with `fetch_k=3×k` for diversity  
- **Batch throughput**: Folder-level parallelization support  

---

## Citation

If you use ReGAIN in your research, please cite:

To be added

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **NSF**: Grants 2113945, 2200538, 2416992, 2230610 at NC A&T SU  
- **MAWILab**: WIDE project for traffic anomaly dataset  
- **LangChain & ChromaDB**: RAG infrastructure  
- **Sentence Transformers**: Semantic embedding framework  

---

## Contact & Support
 
- **Paper**: (to be added)  

---