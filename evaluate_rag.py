# Evaluates the RAG-based detection system by comparing extracted predictions from
# text outputs against ground truth labels, calculating classification metrics,
# and visualizing performance with a confusion matrix and ROC curve

import os
import json
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, roc_curve, auc, classification_report

# Load ground truth labels from JSON (automated detection from label_ping_flood_logs.py)
def load_ground_truth_from_json(json_path):
    """
    Load automated ground truth labels from JSON.
    Expected format: {"conn_log_part_1.log": {"ping_flood_detected": true, ...}, ...}
    """
    with open(json_path, "r") as f:
        data = json.load(f)
    # Strip ".log" extension from keys for matching filenames without extension
    return {k.rsplit(".", 1)[0]: v.get("ping_flood_detected", False) for k, v in data.items()}


# Load ground truth labels from a .txt file with format: filename = True/False
def load_ground_truth_from_txt(txt_path):
    """
    Load ground truth labels from text file.
    Expected format: conn_log_part_1 = True
    """
    ground_truth = {}
    with open(txt_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or '=' not in line:
                continue  # skip empty or malformed lines
            fname, value = line.split('=')
            fname = fname.strip().rsplit('.', 1)[0]  # Remove ".log" if present
            value = value.strip().lower() == 'true'
            ground_truth[fname] = value
    return ground_truth


# Extract a prediction (True/False) from RAG-generated response
def extract_prediction(text):
    """
    Parse RAG output to determine if ping flood was detected.
    Returns True if attack detected, False if not, None if unclear.
    """
    text = text.strip()
    if not text:
        return None
    
    # Check for explicit UNDECIDABLE response
    if "UNDECIDABLE" in text.upper():
        return None
    
    # Protect against "conn.log" splitting issues
    protected_text = text.replace("conn.log", "conn_log")
    sentences = protected_text.split(".")
    first_sentence = sentences[0].replace("conn_log", "conn.log").lower()
    
    # Look for negative indicators in first sentence
    if "no ping flood" in first_sentence or "no attack" in first_sentence:
        return False
    if "not detected" in first_sentence or "not a ping flood" in first_sentence:
        return False
    
    # Look for positive indicators
    if "ping flood" in first_sentence and "detected" in first_sentence:
        return True
    if "attack" in first_sentence:
        return True
    
    # Default to True if uncertain (can adjust based on evaluation needs)
    return True


# Compare ground truth to predictions in RAG output files
def evaluate(ground_truth, rag_folder):
    """
    Evaluate RAG predictions against ground truth labels.
    
    Returns dict with metrics and lists of misclassified files.
    """
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
        
        pred = extract_prediction(rag_output)
        
        if pred is None:
            undecided.append(fname_no_ext)
            continue
        
        # Compare prediction to ground truth
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


if __name__ == "__main__":
    # ========== CONFIGURATION ==========
    # Choose evaluation mode:
    # - "auto" = Use automated labels from JSON (ping_flood_labels.json)
    # - "manual" = Use manual labels from TXT file (manual_gt_labels.txt)
    EVALUATION_MODE = "auto"  # Change to "manual" for human expert labels
    
    if EVALUATION_MODE == "auto":
        ground_truth_path = "./split_logs/ping_flood_labels.json"
        print("📊 Using AUTOMATED ground truth labels (sliding-window detection)")
        ground_truth = load_ground_truth_from_json(ground_truth_path)
    else:
        ground_truth_path = "./manual_gt_labels.txt"
        print("👤 Using MANUAL ground truth labels (human expert)")
        ground_truth = load_ground_truth_from_txt(ground_truth_path)
    
    rag_outputs_folder = "./rag_outputs"
    # ===================================
    
    print("="*60)
    print("🔬 RAG System Evaluation")
    print("="*60)
    print(f"Ground truth: {ground_truth_path}")
    print(f"RAG outputs: {rag_outputs_folder}")
    print(f"Total ground truth samples: {len(ground_truth)}\n")
    results = evaluate(ground_truth, rag_outputs_folder)
    
    # Print summary
    print("=== Evaluation Results ===")
    print(f"Total evaluated: {results['total_evaluated']}")
    print(f"Accuracy: {results['accuracy']:.2%}")
    print(f"Precision: {results['precision']:.2%}")
    print(f"Recall: {results['recall']:.2%}")
    print(f"F1 Score: {results['f1_score']:.2%}")
    print(f"\nTrue Positives: {results['true_positives']}")
    print(f"True Negatives: {results['true_negatives']}")
    print(f"False Positives: {results['false_positives']}")
    print(f"False Negatives: {results['false_negatives']}")
    
    if results["missing_files"]:
        print(f"\n⚠️  Missing RAG output files ({len(results['missing_files'])}): {results['missing_files'][:5]}")
    if results["undecided_outputs"]:
        print(f"\n⚠️  Undecided RAG outputs ({len(results['undecided_outputs'])}): {results['undecided_outputs'][:5]}")
    if results["false_positive_files"]:
        print(f"\n❌ False Positives ({len(results['false_positive_files'])}):")
        for f in results["false_positive_files"][:10]:
            print(f"   - {f}")
    if results["false_negative_files"]:
        print(f"\n❌ False Negatives ({len(results['false_negative_files'])}):")
        for f in results["false_negative_files"][:10]:
            print(f"   - {f}")
    
    # Build lists for sklearn metrics
    y_true = []
    y_pred = []
    
    for fname_no_ext, true_label in ground_truth.items():
        rag_path = os.path.join(rag_outputs_folder, fname_no_ext + ".txt")
        if not os.path.exists(rag_path):
            continue
        with open(rag_path, "r", encoding="utf-8") as f:
            rag_output = f.read()
        pred = extract_prediction(rag_output)
        if pred is None:
            continue
        y_true.append(1 if true_label else 0)
        y_pred.append(1 if pred else 0)
    
    # Print sklearn classification report
    print("\n" + "="*60)
    print("Detailed Classification Report:")
    print("="*60)
    print(classification_report(y_true, y_pred, target_names=["No Attack", "Ping Flood"]))
    
    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["No Attack", "Ping Flood"])
    disp.plot(cmap=plt.cm.Blues)
    plt.title("RAG System Confusion Matrix")
    plt.tight_layout()
    plt.savefig("confusion_matrix.png", dpi=300)
    print("\n📊 Confusion matrix saved to: confusion_matrix.png")
    plt.show()
    
    # ROC Curve
    fpr, tpr, _ = roc_curve(y_true, y_pred)
    roc_auc = auc(fpr, tpr)
    
    plt.figure()
    plt.plot(fpr, tpr, linewidth=2, label=f"ROC Curve (AUC = {roc_auc:.2f})")
    plt.plot([0, 1], [0, 1], "k--", linewidth=1, label="Random Classifier")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate (Recall)")
    plt.title("Receiver Operating Characteristic (ROC) Curve")
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig("roc_curve.png", dpi=300)
    print("📊 ROC curve saved to: roc_curve.png")
    plt.show()
