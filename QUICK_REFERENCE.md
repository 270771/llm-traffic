# ReGAIN Quick Reference Guide

## 📋 Common Commands

### Analysis
```bash
# Interactive forensics mode
python rag_query.py

# Batch process a folder of logs
python rag_query.py data/processed/inragsplit data/processed/rag_outputs_new

# Show help
python rag_query.py --help
```

### Evaluation
```bash
# Run all 4 evaluation scenarios
python run_all_evaluations.py

# Run single evaluation (requires manual configuration)
python evaluate_rag.py
```

### Data Ingestion
```bash
# Ingest anomaly CSV data
python scripts/ingestion_anomaly.py

# Ingest ping flood alerts
python scripts/ingestion_pingflood.py
```

### Preprocessing
```bash
# Split large connection logs
python preprocessing/split_conn_log.py

# Generate ground truth labels
python preprocessing/label_ping_flood_logs.py
```

## 📂 Key File Locations

| What | Where |
|------|-------|
| Main engine | `rag_query.py` |
| Evaluation runner | `run_all_evaluations.py` |
| Evaluation results | `evaluation_results/` |
| Raw data | `data/raw/` |
| Processed logs | `data/processed/` |
| Ground truth labels | `data/ground_truth/` |
| ChromaDB | `database/chroma_db/` |
| Scripts | `scripts/` |
| API keys | `.env` |

## 🎯 Evaluation Scenarios

All configured in `run_all_evaluations.py`:

| Scenario | Dataset | Labels | Files | Accuracy |
|----------|---------|--------|-------|----------|
| **Fig 3(b)** | Known | Auto GT | 2149 | 99.26% |
| **Fig 3(c)** | Unknown | Auto GT | 5000 | 97.56% |
| **Fig 4(b)** | Known | Expert | 2148 | 98.00% |
| **Fig 4(c)** | Unknown | Expert | 5000 | 97.74% |

## 🔧 Configuration

### Environment Variables (.env)
```bash
OPENAI_API_KEY=your_api_key_here
```

### ChromaDB Collections
- `anomaly_csv_logsc01` - 10K+ anomaly records
- `heuristic_info_txt4` - Heuristics/taxonomy knowledge
- `ping_flood_alerts2` - Ping flood detection alerts

### Model Configuration
- **Embeddings**: all-MiniLM-L6-v2 (384-D vectors)
- **Reranking**: cross-encoder/ms-marco-MiniLM-L-6-v2
- **LLM**: 
  - Interactive: gpt-4.1-nano
  - Batch: gpt-4.1-mini
  - Temperature: 0

## 📊 Output Files

### RAG Analysis Output
Each log file produces a `.txt` analysis file:
```
data/processed/rag_outputs_*/conn_log_part_1.txt
```

### Evaluation Output
```
evaluation_results/
├── evaluation_summary.txt              # Overall results
├── fig3b_known_gt_confusion_matrix.png
├── fig3b_known_gt_roc_curve.png
├── fig3c_unknown_gt_confusion_matrix.png
├── fig3c_unknown_gt_roc_curve.png
├── fig4b_known_expert_confusion_matrix.png
├── fig4b_known_expert_roc_curve.png
├── fig4c_unknown_expert_confusion_matrix.png
└── fig4c_unknown_expert_roc_curve.png
```

## 🐛 Troubleshooting

### Common Issues

**ChromaDB not found**
```bash
# Check database location
ls database/chroma_db/
# Re-run ingestion if needed
python scripts/ingestion_anomaly.py
```

**API key error**
```bash
# Check .env file exists
cat .env
# Should contain: OPENAI_API_KEY=sk-...
```

**Module not found**
```bash
# Activate virtual environment
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

**Path errors in evaluation**
```bash
# Verify paths in run_all_evaluations.py match actual structure
# All paths should start with data/processed/ or data/ground_truth/
```

## 💡 Tips

1. **Large datasets**: Use batch mode instead of interactive
2. **Debugging**: Check individual log analysis before batch processing
3. **Performance**: Evaluation runs faster on smaller subsets (modify SCENARIOS in run_all_evaluations.py)
4. **Reproducibility**: Results use temperature=0 for deterministic outputs
5. **Visualizations**: All charts saved as high-res PNG (300 DPI)

## 📚 Documentation

- **README.md** - Project overview and setup
- **PROJECT_STRUCTURE.md** - Complete directory structure
- **This file** - Quick reference commands

## 🔗 Related Files

- Requirements: `requirements.txt`
- License: `LICENSE`
- Git config: `.gitignore`
