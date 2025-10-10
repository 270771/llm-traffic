# Baseline Methods for Network Attack Detection

This directory contains baseline implementations for comparing the RAG+LLM approach against traditional network intrusion detection methods.

## Overview

To address the reviewer's comment about needing baseline comparisons, we've implemented five baseline approaches:

### 1. **Rule-Based Detection** (`rule_based.py`)
- Similar to Snort/Suricata/Zeek rules
- Uses heuristic thresholds for attack detection
- **Ping Flood Rules:**
  - ICMP packet count ≥ threshold
  - ICMP traffic ratio ≥ 30%
  - Time window ≤ 60 seconds
- **SYN Flood Rules:**
  - S0 (failed) connection count ≥ threshold
  - S0 ratio ≥ 50%
  - SYN rate ≥ 10 per second

### 2. **Support Vector Machine** (`traditional_ml.py`)
- RBF kernel SVM with probability estimates
- Feature extraction from Zeek logs (30 features)
- StandardScaler normalization

### 3. **Random Forest** (`traditional_ml.py`)
- 100 decision trees
- Max depth = 20
- Handles non-linear relationships well

### 4. **1D Convolutional Neural Network** (`deep_learning.py`)
- PyTorch implementation
- 2 conv layers with batch normalization
- Dropout regularization (0.5)
- Binary classification output

### 5. **LSTM Recurrent Neural Network** (`deep_learning.py`)
- PyTorch implementation
- 2-layer LSTM with dropout (0.3)
- Captures temporal patterns in features

## Features Extracted

All ML/DL models use 30 engineered features from Zeek logs:

**Protocol Features:**
- ICMP/TCP/UDP traffic ratios
- Connection state distributions (S0, SF, etc.)

**Temporal Features:**
- Time span, flow rate
- Duration statistics (avg, min, max)

**Volume Features:**
- Bytes and packets (orig/resp)
- Byte and packet ratios

**Diversity Features:**
- Unique source/destination IPs and ports
- IP/port diversity metrics

## Usage

### Quick Start - Run All Baselines

```bash
# Ping flood detection with ground truth labels
python src/baselines/run_comparison.py \
    --attack-type ping_flood \
    --log-folder ./data/processed/c101split/test1 \
    --labels ./data/processed/c101split/test1/ping_flood_labels.json \
    --label-type json \
    --output-dir ./results/baseline_comparison/ping_gt \
    --rag-folder ./data/processed/rag_outputs_c101split1

# Ping flood with expert labels
python src/baselines/run_comparison.py \
    --attack-type ping_flood \
    --log-folder ./data/processed/c101split/test1 \
    --labels ./data/ground_truth/c101_manual_gt_labels.txt \
    --label-type txt \
    --output-dir ./results/baseline_comparison/ping_expert \
    --rag-folder ./data/processed/rag_outputs_c101split1

# SYN flood detection
python src/baselines/run_comparison.py \
    --attack-type syn_flood \
    --log-folder ./data/processed/syn_flood/logs \
    --labels ./data/ground_truth/syn_flood/expert_labels.txt \
    --label-type txt \
    --output-dir ./results/baseline_comparison/syn_expert
```

### Run Individual Baselines

#### Rule-Based Detector
```python
from baselines.rule_based import RuleBasedDetector

detector = RuleBasedDetector(attack_type='ping_flood')
results = detector.evaluate(
    log_folder='./data/processed/c101split/test1',
    labels_path='./data/processed/c101split/test1/ping_flood_labels.json',
    label_type='json',
    output_dir='./results/rule_based'
)
```

#### SVM
```python
from baselines.traditional_ml import TraditionalMLBaseline

svm = TraditionalMLBaseline(model_type='svm', attack_type='ping_flood')
svm.train(
    log_folder='./data/processed/c101split/test1',
    labels_path='./data/processed/c101split/test1/ping_flood_labels.json',
    label_type='json'
)
results = svm.evaluate(
    log_folder='./data/processed/c101split/test1',
    labels_path='./data/processed/c101split/test1/ping_flood_labels.json',
    label_type='json',
    output_dir='./results/svm'
)
```

#### Random Forest
```python
from baselines.traditional_ml import TraditionalMLBaseline

rf = TraditionalMLBaseline(model_type='random_forest', attack_type='ping_flood')
rf.train(...)
results = rf.evaluate(...)
```

#### CNN
```python
from baselines.deep_learning import DeepLearningBaseline

cnn = DeepLearningBaseline(model_type='cnn', attack_type='ping_flood')
cnn.train(
    log_folder='./data/processed/c101split/test1',
    labels_path='./data/processed/c101split/test1/ping_flood_labels.json',
    label_type='json',
    epochs=50,
    batch_size=32
)
results = cnn.evaluate(...)
```

#### LSTM
```python
from baselines.deep_learning import DeepLearningBaseline

lstm = DeepLearningBaseline(model_type='lstm', attack_type='ping_flood')
lstm.train(epochs=50, batch_size=32, ...)
results = lstm.evaluate(...)
```

## Output Files

The comparison script generates:

```
results/baseline_comparison/
├── comparison_summary.csv              # Table of all metrics
├── comparison_summary.txt              # Formatted text summary
├── detailed_results.json               # Complete results
├── metrics_comparison.png              # Bar charts of all metrics
├── confusion_matrices_comparison.png   # All confusion matrices
├── rule_based/
│   ├── rule_based_metrics.json
│   ├── rule_based_confusion_matrix.png
│   └── rule_based_roc_curve.png
├── svm/
│   ├── svm_metrics.json
│   ├── svm_confusion_matrix.png
│   └── svm_roc_curve.png
├── random_forest/
│   ├── random_forest_metrics.json
│   ├── random_forest_confusion_matrix.png
│   └── random_forest_roc_curve.png
├── cnn/
│   ├── cnn_metrics.json
│   ├── cnn_confusion_matrix.png
│   └── cnn_roc_curve.png
└── lstm/
    ├── lstm_metrics.json
    ├── lstm_confusion_matrix.png
    └── lstm_roc_curve.png
```

## Dependencies

Ensure all required packages are installed:

```bash
pip install scikit-learn torch pandas matplotlib seaborn
```

All dependencies are already in `requirements.txt`.

## Performance Expectations

Based on typical IDS performance on similar datasets:

- **Rule-Based**: Fast, interpretable, but may have high false positives
- **SVM**: Good accuracy, slower training on large datasets
- **Random Forest**: Robust, handles imbalanced data well
- **CNN**: Good at feature learning, requires sufficient data
- **LSTM**: Captures temporal patterns, longer training time
- **RAG+LLM**: High accuracy + explainability (our contribution)

## Comparison Metrics

All methods are evaluated on:

1. **Accuracy**: Overall correctness
2. **Precision**: Attack detection precision (low false positives)
3. **Recall**: Attack detection completeness (low false negatives)
4. **F1-Score**: Harmonic mean of precision and recall
5. **AUC-ROC**: Area under ROC curve
6. **Confusion Matrix**: TP, TN, FP, FN breakdown

## Notes for Paper

### Advantages of RAG+LLM Over Baselines:

1. **Explainability**: Natural language explanations vs black-box predictions
2. **Evidence Grounding**: Citations to specific anomaly records and heuristics
3. **Context Integration**: Combines multiple knowledge sources (anomaly CSV, heuristics, taxonomy)
4. **Adaptability**: Can handle new attack patterns without retraining
5. **Domain Knowledge**: Leverages pre-trained LLM reasoning capabilities

### When Baselines Fail:

- **Rule-Based**: Brittle thresholds, high maintenance, evasion-prone
- **ML/DL**: Black-box predictions, no explanations, require labeled training data
- **All Traditional Methods**: Cannot provide reasoning or evidence for decisions

### RAG+LLM Unique Value:

Even if traditional methods achieve similar accuracy, RAG+LLM provides:
- **Actionable insights** through natural language explanations
- **Forensic value** through evidence citations
- **Analyst trust** through transparent reasoning
- **Reduced investigation time** through comprehensive summaries

This addresses the reviewer's concern by demonstrating that our contribution is not just accuracy, but **accuracy + explainability + evidence grounding**.
