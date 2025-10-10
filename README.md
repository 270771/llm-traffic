# ReGAIN: Retrieval-Grounded AI Framework for Network Traffic Analysis

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## Abstract

**ReGAIN** (Retrieval-Grounded AI Framework for Network Traffic Analysis) is a retrieval-augmented generation (RAG) system designed for automated network security threat detection and analysis. The framework integrates vector-based semantic search with large language model reasoning to identify network attacks with high accuracy while providing explainable, evidence-backed diagnostics. Our evaluation on ICMP ping flood and TCP SYN flood attacks demonstrates strong detection performance (AUC 0.91-0.99, accuracy 95.95-98.82%) on real-world backbone traffic from the MAWILab dataset.

## Key Contributions

1. **Hybrid RAG Architecture**: Combines semantic embeddings (ChromaDB), metadata filtering, and GPT-4 reasoning for explainable threat detection
2. **Multi-Source Knowledge Integration**: Ingests heterogeneous data (anomaly records, heuristic rules, network logs) into unified vector store
3. **State-Based Classification**: Leverages TCP connection states and ICMP patterns for definitive attack identification
4. **High Performance**: Achieves 95.95-98.82% accuracy with AUC 0.91-0.99 across automated and expert-validated evaluations
5. **Expert Validation**: Independent manual labeling confirms robustness with 95.95% accuracy and 97.20% precision on SYN floods


---

## System Architecture

The ReGAIN framework consists of four primary components:

### 1. Data Ingestion Pipeline
- Processes heterogeneous network data (Zeek logs, CSV anomaly records, heuristic rules)
- Generates natural language summaries for semantic encoding
- Normalizes multi-source telemetry into unified format

### 2. Vector Knowledge Base
- Encodes summaries using Sentence Transformers (`all-MiniLM-L6-v2`, 384-D embeddings)
- Stores vectors in ChromaDB with rich metadata (IP addresses, protocols, timestamps, heuristic codes)
- Supports efficient similarity search and metadata filtering

### 3. Retrieval-Augmented Generation
- Semantic search: Identifies relevant historical patterns via cosine similarity
- Cross-encoder reranking: Refines retrieval precision
- LLM reasoning: GPT-4 analyzes retrieved context and generates explanations
- Evidence citation: Returns grounded responses with supporting data

### 4. Evaluation Framework
- Automated ground truth generation from connection states (S0 = attack, SH/SF/RSTR/OTH = normal)
- Expert label validation for verification
- Comprehensive metrics: Accuracy, Precision, Recall, F1-Score, AUC-ROC
- Visualization: Confusion matrices and ROC curves

---

## Installation

### Prerequisites
- Python 3.11 or higher
- OpenAI API key (for GPT-4 access)

### Setup

```bash
# Clone repository
git clone https://github.com/270771/llm-traffic.git
cd llm-traffic

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Configure API key
echo "OPENAI_API_KEY=your_key_here" > .env
```

---

## Usage

### Building the Knowledge Base

Execute ingestion scripts to populate ChromaDB:

```bash
# Ingest MAWILab anomaly records
python src/ingestion/ingestion_anomaly.py

# Ingest heuristic rules and taxonomy
python src/ingestion/ingestion_heur_tax.py

# Ingest ping flood patterns
python src/ingestion/ingestion_pingflood.py

# Ingest SYN flood patterns  
python src/ingestion/ingestion_synflood.py
```

**Output**: Three ChromaDB collections containing ~10K+ embedded anomaly records, detection rules, and attack patterns.

### Running Detection Queries

**Ping Flood Detection**:
```bash
python src/query/rag_query.py
```

**SYN Flood Detection**:
```bash
python src/query/rag_query_syn.py
```

**Batch Processing**:
```bash
python src/query/rag_query.py <input_logs_folder> <output_results_folder>
```

### Evaluation

Run comprehensive evaluation on both attack types:

```bash
# Ping flood evaluation
python src/run_all_evaluations.py

# SYN flood evaluation
python src/run_syn_evaluations.py
```

**Outputs**: 
- Confusion matrices (`results/{attack_type}/{expert|ground_truth}/confusion_matrix.png`)
- ROC curves (`results/{attack_type}/{expert|ground_truth}/roc_curve.png`)
- Metrics summary (`results/FINAL_EVALUATION_SUMMARY.txt`)

---

## Performance Results

### ICMP Ping Flood Detection

| Evaluation Set | Accuracy | Precision | Recall | F1-Score | AUC |
|----------------|----------|-----------|--------|----------|-----|
| Ground Truth   | 97.56%   | 74.48%    | 100.0% | 85.37%   | 0.99|
| Expert Labels  | 97.74%   | 76.36%    | 100.0% | 86.60%   | 0.99|

**Confusion Matrix (Ground Truth)**: TP=356, TN=4522, FP=122, FN=0  
**Confusion Matrix (Expert Labels)**: TP=365, TN=4522, FP=113, FN=0

### TCP SYN Flood Detection

| Evaluation Set | Accuracy | Precision | Recall | F1-Score | AUC |
|----------------|----------|-----------|--------|----------|-----|
| Ground Truth   | 98.82%   | 100.0%    | 98.64% | 99.32%   | 0.99|
| Expert Labels  | 95.95%   | 97.20%    | 98.07% | 97.63%   | 0.91|

**Confusion Matrix (Ground Truth)**: TP=4075, TN=609, FP=0, FN=56  
**Confusion Matrix (Expert Labels)**: TP=3960, TN=587, FP=114, FN=78

### Key Findings

✅ **Perfect Recall on Ping Floods**: 100% detection rate ensures no ping flood attacks are missed  
✅ **Perfect Precision on SYN Floods (GT)**: Zero false positives with automated ground truth  
✅ **High Accuracy**: >95% across all evaluation scenarios  
✅ **Expert Validation**: Manual expert labels provide independent verification with 95-98% accuracy  
✅ **Strong Discriminative Power**: AUC-ROC of 0.91-0.99 indicates excellent classification capability  
✅ **State-Based Ground Truth**: Connection state analysis (S0 vs. SH/SF/RSTR/OTH) provides definitive automated labeling  
✅ **Robustness**: Consistent performance across different labeling methodologies demonstrates system reliability

---

## Dataset

### MAWILab v1.1

We use the [MAWILab v1.1 dataset](http://www.fukuda-lab.org/mawilab/), a collection of labeled network anomalies from the WIDE backbone network in Japan.

**Data Sources**:
1. **Anomaly Records (CSV)**: Dual-labeled annotations with heuristic codes and behavioral taxonomy
2. **Network Logs (Zeek format)**: Connection-level telemetry with TCP states and protocol metadata
3. **Traffic Captures (pcap)**: Raw packet data for validation

**Key Features**:
- 10K+ labeled anomalies (ping floods, SYN floods, port scans, DoS attacks)
- Real-world backbone traffic (not synthetic)
- Temporal diversity for train/test splitting
- Rich metadata: 5-tuple, protocol, connection states, timestamps

**Attack Types Evaluated**:
- **ICMP Ping Flood** (Heuristic code: 20): Volumetric ICMP echo request attacks
- **TCP SYN Flood** (Heuristic code: 10): Half-open connection exhaustion attacks

**Connection State Indicators**:
- `S0`: SYN sent, no response → **Attack signature**
- `SH`, `SF`, `RSTR`, `RSTO`, `OTH`: Responses received → **Normal traffic**

---

## Project Structure

```
llm-traffic/
├── src/
│   ├── analysis/              # Protocol and TCP state analyzers
│   │   ├── analyze_protocols.py
│   │   └── analyze_tcp_states.py
│   ├── ingestion/             # Data ingestion and vectorization
│   │   ├── ingestion_anomaly.py
│   │   ├── ingestion_heur_tax.py
│   │   ├── ingestion_pingflood.py
│   │   └── ingestion_synflood.py
│   ├── preprocessing/         # Log preprocessing utilities
│   │   ├── label_ping_flood_logs.py
│   │   └── split_conn_log.py
│   ├── query/                 # RAG query interfaces
│   │   ├── rag_query.py       # Ping flood detection
│   │   └── rag_query_syn.py   # SYN flood detection
│   ├── evaluate_rag.py        # Legacy evaluation script
│   ├── filter.py              # Log filtering utility
│   ├── run_all_evaluations.py     # Ping flood evaluation
│   ├── run_syn_evaluations.py     # SYN flood evaluation
│   └── run_syn_rag_batches.py     # Batch processing utility
├── data/
│   ├── raw/                   # Original MAWILab data
│   ├── processed/             # Preprocessed logs and splits
│   └── ground_truth/          # Expert labels and annotations
├── database/
│   └── chroma_db/             # ChromaDB vector store
├── results/
│   ├── ping_flood/            # Evaluation results for ping floods
│   ├── syn_flood/             # Evaluation results for SYN floods
│   └── FINAL_EVALUATION_SUMMARY.txt
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── LICENSE                    # MIT License
```

---

## Technical Details

### Embedding Model
- **Model**: `sentence-transformers/all-MiniLM-L6-v2`
- **Dimensions**: 384
- **Advantages**: Fast inference, strong semantic similarity, low computational cost

### Vector Database
- **System**: ChromaDB
- **Collections**: 
  - `anomaly_csv_logsc01`: Anomaly records
  - `heuristic_info_txt4`: Detection rules
  - `ping_flood_alerts2`: Ping flood patterns
  - `syn_flood_alerts`: SYN flood patterns
- **Search**: Cosine similarity with metadata filtering

### Language Model
- **Model**: GPT-4 (gpt-4.1-nano, gpt-4.1-mini variants)
- **Role**: Evidence-based reasoning and explanation generation
- **Prompting**: Few-shot with retrieval context and explicit citation requirements

### Evaluation Methodology
1. **Automated Labeling**: Extract connection states from Zeek logs (field 11)
2. **Expert Validation**: Manual review by domain experts
3. **Metrics**: Sklearn implementations of accuracy, precision, recall, F1, AUC
4. **Visualization**: Matplotlib confusion matrices and ROC curves

---

## Citation

If you use this work in your research, please cite:

```bibtex
@article{regain2025,
  title={ReGAIN: Retrieval-Grounded AI Framework for Network Traffic Analysis},
  author={[Authors]},
  journal={[Conference/Journal]},
  year={2025}
}
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **MAWILab** for providing the labeled backbone traffic dataset
- **WIDE Project** for maintaining the traffic monitoring infrastructure
- **Sentence Transformers** for efficient semantic embedding models
- **ChromaDB** for scalable vector storage and retrieval
- **OpenAI** for GPT-4 API access

---

## Contact

For questions, issues, or collaboration opportunities:
- **GitHub Issues**: [https://github.com/270771/llm-traffic/issues](https://github.com/270771/llm-traffic/issues)
- **Repository**: [https://github.com/270771/llm-traffic](https://github.com/270771/llm-traffic)

---

## Future Work

- **Multi-Attack Detection**: Extend framework to port scans, DDoS, and tunneling attacks
- **Real-Time Analysis**: Integrate streaming data pipelines for live detection
- **Explainability Enhancement**: Generate natural language incident reports
- **Human-in-the-Loop**: Interactive refinement and forensic investigation workflows
- **Model Optimization**: Fine-tune embedding models on network-specific terminology


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

---

## Contact & Support
 
- **Paper**: (to be added)  

---