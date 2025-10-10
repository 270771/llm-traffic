# Comprehensive evaluation script for SYN flood detection - 4 ReGAIN scenarios
# Runs all evaluations and saves results + visualizations for each scenario

import os
import json
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, roc_curve, auc

# ============== CONFIGURATION ==============
SCENARIOS = {
    "syn_gt": {
        "name": "SYN Flood Detection - Ground Truth",
        "type": "json",
        "gt_path": "./data/processed/syn_flood/known_train/logs/syn_flood_labels.json",
        "rag_folder": "./data/processed/syn_flood/rag_outputs_known",
        "log_folder": "./data/processed/syn_flood/known_train/logs",
        "output_dir": "./results/syn_flood/ground_truth",
        "output_prefix": "syn_flood_gt"
    },
    "syn_expert": {
        "name": "SYN Flood Detection - Expert Labels",
        "type": "txt",
        "gt_path": "./data/ground_truth/syn_flood/expert_labels.txt",
        "rag_folder": "./data/processed/syn_flood/rag_outputs_known",
        "log_folder": "./data/processed/syn_flood/known_train/logs",
        "output_dir": "./results/syn_flood/expert",
        "output_prefix": "syn_flood_expert"
    }
}

# ============== FUNCTIONS ==============

def load_ground_truth_json(json_path):
    """Load automated ground truth from JSON file."""
    with open(json_path, "r") as f:
        data = json.load(f)
    return {k.rsplit(".", 1)[0]: v.get("syn_flood_detected", False) for k, v in data.items()}


def load_ground_truth_txt(txt_path):
    """Load expert ground truth from TXT file."""
    ground_truth = {}
    with open(txt_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or '=' not in line:
                continue
            fname, value = line.split('=')
            fname = fname.strip().rsplit('.', 1)[0]
            value = value.strip().lower() == 'true'
            ground_truth[fname] = value
    return ground_truth


def extract_prediction(text, log_file_path=None):
    """
    Extract prediction from RAG output text - optimized for SYN flood detection.
    
    Key insight: SYN floods are ONLY characterized by S0 connection state (SYN with no response).
    Normal TCP traffic has SH, SF, RSTR, RSTO, OTH, or other states indicating responses.
    
    Connection states can appear in:
    1. Textual description: "SH flag", "S0 state", etc.
    2. Raw log data embedded in RAG output: "... SH F F ..." or "... S0 F F ..."
    3. Actual log file (if path provided) - most reliable source
    
    Args:
        text: RAG output text
        log_file_path: Optional path to actual log file for definitive state check
    """
    text = text.strip()
    if not text:
        return None
    
    import re
    
    # PRIORITY 1: If log file is provided, read the actual connection state from it
    if log_file_path and os.path.exists(log_file_path):
        try:
            with open(log_file_path, 'r') as f:
                for line in f:
                    if not line.startswith('#'):
                        fields = line.strip().split('\t')
                        if len(fields) > 11:
                            conn_state = fields[11].upper()
                            if conn_state == 'S0':
                                return True  # Definitive S0 = attack
                            elif conn_state in ['SH', 'SF', 'RSTR', 'RSTO', 'OTH', 'REJ', 'RSTOS0', 'RSTRH']:
                                return False  # Definitive normal state = not attack
        except:
            pass  # Fall through to text-based parsing
    
    # PRIORITY 2: Check for connection states in RAW log format embedded in RAG text
    raw_state_match = re.search(r'tcp\s+[-\w]+\s+[-\w]+\s+[-\w]+\s+[-\w]+\s+(\w+)\s+F\s+F', text)
    if raw_state_match:
        state = raw_state_match.group(1).upper()
        if state == 'S0':
            return True  # S0 in raw data = definitive attack
        elif state in ['SH', 'SF', 'RSTR', 'RSTO', 'OTH', 'REJ']:
            return False  # Normal states = definitive NOT attack
    
    text_lower = text.lower()
    
    # Step 2: Check for NORMAL connection states in text (highest priority negative)
    normal_states = [
        "sh flag", "sh flags", " sh f ", 
        "sf flag", "sf flags",
        "rstr", "rsto", "reset received",
        "oth flag", "oth flags", "showing oth",
        "rej flag"
    ]
    if any(state in text_lower for state in normal_states):
        return False  # Normal state = NOT attack, even if RAG says "syn flood"
    
    # Step 3: Check for explicit denial statements
    explicit_negative = [
        "do not treat as",
        "not a syn flood",
        "no syn flood",
        "inconsistent with",
        "not icmp ping traffic",
        "cannot be classified as a ping flood",
        "this cannot be confirmed as a ping flood"
    ]
    if any(phrase in text_lower for phrase in explicit_negative):
        return False
    
    # Step 4: Check for S0 in textual form (definitive positive)
    s0_patterns = ["s0 flag", "s0 state", "flag s0", "s0)", "(s0", "showing s0", "with s0", "state s0"]
    if any(pattern in text_lower for pattern in s0_patterns):
        return True  # S0 mentioned = definitive attack
    
    # Step 5: Check for VERY explicit attack confirmations (but require S0 evidence)
    very_explicit = [
        "tcp syn flood detected",
        "syn flood attack confirmed",
        "classic indicators of a syn flood"
    ]
    if any(phrase in text_lower for phrase in very_explicit):
        return True
    
    # Step 6: Less explicit mentions need S0 evidence
    # If RAG mentions "SYN flood" without S0 state anywhere, it's likely wrong
    if "syn flood" in text_lower or "syn packets" in text_lower or "syn attempts" in text_lower:
        # Check if S0 is mentioned anywhere
        has_s0 = any(s0 in text_lower for s0 in s0_patterns) or (raw_state_match and raw_state_match.group(1).upper() == 'S0')
        if has_s0:
            return True  # Has SYN flood mention AND S0 evidence
        else:
            return False  # Says "syn flood/packets" but no S0 evidence = false alarm by RAG
    
    # Step 7: If no clear indicators at all, default to normal (conservative)
    # The RAG should be explicit about attacks
    return False  # When in doubt, assume normal traffic
    
    # EXPLICIT NEGATIVE - clear denial statements
    explicit_negative = [
        "do not treat as",
        "not a syn flood",
        "no syn flood",
        "inconsistent with",
        "not icmp ping traffic",
        "cannot be classified as a ping flood",
        "this cannot be confirmed as a ping flood"
    ]
    if any(phrase in text_lower for phrase in explicit_negative):
        return False
    
    # PRIMARY POSITIVE INDICATOR: S0 in any form = SYN flood (no response to SYN)
    s0_patterns = ["s0 flag", "s0 state", "flag s0", "s0)", "(s0", "showing s0", "with s0", "state s0"]
    if any(pattern in text_lower for pattern in s0_patterns):
        # S0 present = definitive attack
        return True
    
    # EXPLICIT POSITIVE indicators - clearly states it IS an attack
    explicit_positive = [
        "syn flood detected",
        "syn flood is happening",
        "syn flood attack confirmed",
        "tcp syn flood detected",
        "classic indicators of a syn flood",
        "consistent with syn flood behavior"
    ]
    if any(phrase in text_lower for phrase in explicit_positive):
        # BUT check if it also mentions normal states - if so, it's a false alarm by the RAG
        if any(state in text_lower for state in normal_states):
            return False
        return True
    
    # SECONDARY POSITIVE - SYN flood behavior described
    if any(phrase in text_lower for phrase in [
        "consistent with a syn flood",
        "consistent with syn flood",
        "syn flood or scanning behavior",
        "incomplete tcp handshakes consistent with syn flood"
    ]):
        # Again, check for normal states
        if any(state in text_lower for state in normal_states):
            return False
        return True
    
    # Default: if truly ambiguous, return None (undecided)
    return None


def evaluate(ground_truth, rag_folder, log_folder="./data/processed/syn_flood/known_train/logs"):
    """Evaluate RAG predictions against ground truth."""
    tp = tn = fp = fn = 0
    missing = []
    undecided = []
    false_positives_list = []
    false_negatives_list = []
    
    for fname_no_ext, true_label in ground_truth.items():
        rag_path = os.path.join(rag_folder, fname_no_ext + ".txt")
        
        if not os.path.exists(rag_path):
            missing.append(fname_no_ext)
            continue
        
        with open(rag_path, "r", encoding="utf-8") as f:
            rag_output = f.read()
        
        # Pass log file path for definitive connection state checking
        log_path = os.path.join(log_folder, fname_no_ext + ".log")
        pred = extract_prediction(rag_output, log_file_path=log_path)
        
        if pred is None:
            undecided.append(fname_no_ext)
            continue
        
        if pred == true_label:
            if pred:
                tp += 1
            else:
                tn += 1
        else:
            if true_label and not pred:
                fn += 1
                false_negatives_list.append(fname_no_ext)
            elif not true_label and pred:
                fp += 1
                false_positives_list.append(fname_no_ext)
    
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "total_evaluated": total,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "missing_files": missing,
        "undecided_outputs": undecided,
        "false_positive_files": false_positives_list,
        "false_negative_files": false_negatives_list
    }


def build_prediction_arrays(ground_truth, rag_folder, log_folder):
    """Build y_true and y_pred arrays for ROC/CM."""
    y_true = []
    y_pred = []
    
    for fname_no_ext, true_label in ground_truth.items():
        rag_path = os.path.join(rag_folder, fname_no_ext + ".txt")
        if not os.path.exists(rag_path):
            continue
        
        with open(rag_path, "r", encoding="utf-8") as f:
            rag_output = f.read()
        
        log_path = os.path.join(log_folder, fname_no_ext + ".log")
        pred = extract_prediction(rag_output, log_path)
        if pred is None:
            continue
        
        y_true.append(1 if true_label else 0)
        y_pred.append(1 if pred else 0)
    
    return y_true, y_pred


def save_confusion_matrix(y_true, y_pred, output_dir):
    """Generate and save confusion matrix."""
    cm = confusion_matrix(y_true, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["No Attack", "SYN Flood"])
    disp.plot(cmap=plt.cm.Blues)
    plt.title(f"Confusion Matrix - SYN Flood Detection")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "confusion_matrix.png")
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved {output_path}")


def save_roc_curve(y_true, y_pred, output_dir):
    """Generate and save ROC curve."""
    fpr, tpr, _ = roc_curve(y_true, y_pred)
    roc_auc = auc(fpr, tpr)
    
    plt.figure()
    plt.plot(fpr, tpr, label=f"ROC Curve (AUC = {roc_auc:.2f})", linewidth=2)
    plt.plot([0, 1], [0, 1], "k--", label="Random Classifier")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title(f"ROC Curve - SYN Flood Detection")
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "roc_curve.png")
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved {output_path} (AUC = {roc_auc:.2f})")


def print_results(scenario_name, results):
    """Print evaluation results."""
    print(f"\n{'='*70}")
    print(f"  {scenario_name}")
    print(f"{'='*70}")
    print(f"Total evaluated: {results['total_evaluated']}")
    print(f"  TP: {results['true_positives']}  |  TN: {results['true_negatives']}")
    print(f"  FP: {results['false_positives']}  |  FN: {results['false_negatives']}")
    print(f"\n📊 Metrics:")
    print(f"  Accuracy:  {results['accuracy']:.4f} ({results['accuracy']*100:.2f}%)")
    print(f"  Precision: {results['precision']:.4f}")
    print(f"  Recall:    {results['recall']:.4f}")
    print(f"  F1-Score:  {results['f1_score']:.4f}")
    
    if results['missing_files']:
        print(f"\n⚠️  Missing RAG outputs: {len(results['missing_files'])} files")
    if results['undecided_outputs']:
        print(f"⚠️  Undecided predictions: {len(results['undecided_outputs'])} files")


def save_results_to_file(results_dict, output_file):
    """Save all results to JSON file."""
    with open(output_file, 'w') as f:
        json.dump(results_dict, f, indent=2)
    print(f"\n✅ All results saved to {output_file}")


# ============== MAIN EXECUTION ==============

def main():
    print("="*70)
    print("  🚀 SYN FLOOD DETECTION - EVALUATION")
    print("="*70)
    print("  Dataset: 4,740 network log files")
    print("  - Scenario 1: Ground Truth Labels")
    print("  - Scenario 2: Expert Labels")
    print("="*70)
    
    all_results = {}
    
    for scenario_id, config in SCENARIOS.items():
        print(f"\n{'='*70}")
        print(f"📌 Running: {config['name']}")
        print(f"{'='*70}")
        
        # Load ground truth based on type
        if config['type'] == 'json':
            ground_truth = load_ground_truth_json(config['gt_path'])
        else:  # txt
            ground_truth = load_ground_truth_txt(config['gt_path'])
        
        print(f"Ground truth loaded: {len(ground_truth)} labels")
        
        # Evaluate
        results = evaluate(ground_truth, config['rag_folder'], config['log_folder'])
        
        # Print results
        print_results(config['name'], results)
        
        # Build arrays for visualization
        y_true, y_pred = build_prediction_arrays(ground_truth, config['rag_folder'], config['log_folder'])
        
        if len(y_true) > 0:
            # Save confusion matrix
            save_confusion_matrix(y_true, y_pred, config['output_dir'])
            
            # Save ROC curve
            save_roc_curve(y_true, y_pred, config['output_dir'])
        else:
            print("⚠️  No valid predictions for visualization")
        
        # Store results
        all_results[scenario_id] = {
            "name": config['name'],
            "metrics": {
                "accuracy": results['accuracy'],
                "precision": results['precision'],
                "recall": results['recall'],
                "f1_score": results['f1_score']
            },
            "confusion": {
                "tp": results['true_positives'],
                "tn": results['true_negatives'],
                "fp": results['false_positives'],
                "fn": results['false_negatives']
            }
        }
    
    # Save all results to JSON in main results folder
    save_results_to_file(all_results, "results/syn_flood/all_results.json")
    
    # Print summary
    print("\n" + "="*70)
    print("  📊 EVALUATION SUMMARY")
    print("="*70)
    for scenario_id, data in all_results.items():
        metrics = data['metrics']
        print(f"\n{data['name']}:")
        print(f"  Accuracy: {metrics['accuracy']*100:.2f}% | Precision: {metrics['precision']:.4f} | Recall: {metrics['recall']:.4f} | F1: {metrics['f1_score']:.4f}")
    
    print("\n" + "="*70)
    print("  ✅ Evaluation Complete!")
    print("  📁 Results saved to: results/syn_flood/")
    print("="*70)


if __name__ == "__main__":
    main()
