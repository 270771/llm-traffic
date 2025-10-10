# Ping Flood evaluation script - Ground Truth and Expert Labels
# Evaluates RAG performance on ping flood detection

import os
import json
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, roc_curve, auc

# ============== CONFIGURATION ==============
SCENARIOS = {
    "ping_gt": {
        "name": "Ping Flood Detection - Ground Truth",
        "type": "json",
        "gt_path": "./data/processed/c101split/test1/ping_flood_labels.json",
        "rag_folder": "./data/processed/rag_outputs_c101split1",
        "output_prefix": "ping_flood_gt"
    },
    "ping_expert": {
        "name": "Ping Flood Detection - Expert Labels",
        "type": "txt",
        "gt_path": "./data/ground_truth/c101_manual_gt_labels.txt",
        "rag_folder": "./data/processed/rag_outputs_c101split1",
        "output_prefix": "ping_flood_expert"
    }
}

# ============== FUNCTIONS ==============

def load_ground_truth_json(json_path):
    """Load automated ground truth from JSON file."""
    with open(json_path, "r") as f:
        data = json.load(f)
    return {k.rsplit(".", 1)[0]: v.get("ping_flood_detected", False) for k, v in data.items()}


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


def extract_prediction(text):
    """Extract prediction from RAG output text."""
    text = text.strip()
    if not text:
        return None
    
    protected_text = text.replace("conn.log", "conn_log")
    sentences = protected_text.split(".")
    first_sentence = sentences[0].replace("conn_log", "conn.log").lower()
    
    if "no" in first_sentence or "not" in first_sentence:
        return False
    else:
        return True


def evaluate(ground_truth, rag_folder):
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
        
        pred = extract_prediction(rag_output)
        
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


def build_prediction_arrays(ground_truth, rag_folder):
    """Build y_true and y_pred arrays for ROC/CM."""
    y_true = []
    y_pred = []
    
    for fname_no_ext, true_label in ground_truth.items():
        rag_path = os.path.join(rag_folder, fname_no_ext + ".txt")
        if not os.path.exists(rag_path):
            continue
        
        with open(rag_path, "r", encoding="utf-8") as f:
            rag_output = f.read()
        
        pred = extract_prediction(rag_output)
        if pred is None:
            continue
        
        y_true.append(1 if true_label else 0)
        y_pred.append(1 if pred else 0)
    
    return y_true, y_pred


def save_confusion_matrix(y_true, y_pred, output_prefix):
    """Generate and save confusion matrix."""
    cm = confusion_matrix(y_true, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["No Attack", "Ping Flood"])
    disp.plot(cmap=plt.cm.Blues)
    
    # Remove title - keep only axis labels
    plt.title("")
    output_path = os.path.join("ping_evaluation_results", f"{output_prefix}_confusion_matrix.png")
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved {output_path}")


def save_roc_curve(y_true, y_pred, output_prefix):
    """Generate and save ROC curve."""
    fpr, tpr, _ = roc_curve(y_true, y_pred)
    roc_auc = auc(fpr, tpr)
    
    plt.figure()
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}", linewidth=2)
    plt.plot([0, 1], [0, 1], "k--", linewidth=1)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    # Remove title - keep only axis labels
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    output_path = os.path.join("ping_evaluation_results", f"{output_prefix}_roc_curve.png")
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved {output_path} (AUC = {roc_auc:.2f})")


def print_results(scenario_name, results):
    """Print evaluation results."""
    print(f"\n{'='*70}")
    print(f"  {scenario_name}")
    print(f"{'='*70}")
    print(f"Total evaluated: {results['total_evaluated']}")
    print(f"Accuracy:        {results['accuracy']:.2%}")
    print(f"Precision:       {results['precision']:.2%}")
    print(f"Recall:          {results['recall']:.2%}")
    print(f"F1 Score:        {results['f1_score']:.2%}")
    print(f"\nConfusion Matrix:")
    print(f"  True Positives:  {results['true_positives']}")
    print(f"  True Negatives:  {results['true_negatives']}")
    print(f"  False Positives: {results['false_positives']}")
    print(f"  False Negatives: {results['false_negatives']}")
    
    if results["missing_files"]:
        print(f"\n⚠️  Missing RAG outputs: {len(results['missing_files'])} files")
    if results["undecided_outputs"]:
        print(f"⚠️  Undecided outputs: {len(results['undecided_outputs'])} files")


def save_results_summary(all_results, output_file="ping_evaluation_results/evaluation_summary.txt"):
    """Save comprehensive results summary to file."""
    with open(output_file, "w") as f:
        f.write("="*80 + "\n")
        f.write("  Ping Flood Detection - Evaluation Results\n")
        f.write("="*80 + "\n\n")
        
        for scenario_key, scenario_config in SCENARIOS.items():
            results = all_results[scenario_key]
            f.write(f"\n{scenario_config['name']}\n")
            f.write("-"*80 + "\n")
            f.write(f"Ground Truth: {scenario_config['gt_path']}\n")
            f.write(f"RAG Outputs:  {scenario_config['rag_folder']}\n\n")
            f.write(f"Total Evaluated: {results['total_evaluated']}\n")
            f.write(f"Accuracy:        {results['accuracy']:.4f} ({results['accuracy']:.2%})\n")
            f.write(f"Precision:       {results['precision']:.4f} ({results['precision']:.2%})\n")
            f.write(f"Recall:          {results['recall']:.4f} ({results['recall']:.2%})\n")
            f.write(f"F1 Score:        {results['f1_score']:.4f} ({results['f1_score']:.2%})\n\n")
            f.write(f"Confusion Matrix:\n")
            f.write(f"  TP: {results['true_positives']:<6} TN: {results['true_negatives']:<6}\n")
            f.write(f"  FP: {results['false_positives']:<6} FN: {results['false_negatives']:<6}\n")
            f.write("\n")
        
        # Summary table
        f.write("\n" + "="*80 + "\n")
        f.write("Summary Table\n")
        f.write("="*80 + "\n")
        f.write(f"{'Scenario':<25} {'Acc':<8} {'Prec':<8} {'Rec':<8} {'F1':<8}\n")
        f.write("-"*80 + "\n")
        for scenario_key, scenario_config in SCENARIOS.items():
            results = all_results[scenario_key]
            name = scenario_config['output_prefix']
            f.write(f"{name:<25} {results['accuracy']:.4f}  {results['precision']:.4f}  "
                   f"{results['recall']:.4f}  {results['f1_score']:.4f}\n")
    
    print(f"\n✓ Saved comprehensive summary to {output_file}")


# ============== MAIN EXECUTION ==============

if __name__ == "__main__":
    print("\n" + "="*70)
    print("  PING FLOOD DETECTION - EVALUATION")
    print("="*70)
    
    # Create output directory
    os.makedirs("ping_evaluation_results", exist_ok=True)
    
    all_results = {}
    
    for scenario_key, scenario_config in SCENARIOS.items():
        print(f"\n\n🔍 Running: {scenario_config['name']}")
        print("-"*70)
        
        # Load ground truth based on type
        if scenario_config['type'] == 'json':
            ground_truth = load_ground_truth_json(scenario_config['gt_path'])
        else:  # txt
            ground_truth = load_ground_truth_txt(scenario_config['gt_path'])
        
        print(f"  Loaded {len(ground_truth)} ground truth labels")
        
        # Evaluate
        results = evaluate(ground_truth, scenario_config['rag_folder'])
        all_results[scenario_key] = results
        
        # Print results
        print_results(scenario_config['name'], results)
        
        # Build prediction arrays
        y_true, y_pred = build_prediction_arrays(ground_truth, scenario_config['rag_folder'])
        
        # Generate and save visualizations
        print(f"\n📊 Generating visualizations...")
        save_confusion_matrix(y_true, y_pred, scenario_config['output_prefix'])
        save_roc_curve(y_true, y_pred, scenario_config['output_prefix'])
    
    # Save comprehensive summary
    save_results_summary(all_results)
    
    print("\n" + "="*70)
    print("  ✅ All evaluations complete!")
    print("="*70)
    print("\nGenerated files:")
    print("  - 4 visualization files (2 confusion matrices + 2 ROC curves)")
    print("  - evaluation_summary.txt (comprehensive results)")
    print()
