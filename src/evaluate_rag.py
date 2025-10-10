# Evaluates the RAG-based detection system by comparing extracted predictions from
# text outputs against JSON ground truth labels/human expert labels, calculating classification metrics,
# and visualizing performance with a confusion matrix and ROC curve

# Note: comment/uncomment the respective code based on which comparison you want to make
##################################################################################################

# Evaluate RAG against Ground Truth Code
# import os
# import json
# import matplotlib.pyplot as plt
# from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, roc_curve, auc
#
# def load_ground_truth(json_path):
#     with open(json_path, "r") as f:
#         data = json.load(f)
#     # Strip ".log" extension from keys for matching filenames without extension
#     return {k.rsplit(".", 1)[0]: v.get("ping_flood_detected", False) for k, v in data.items()}
#
#
# def extract_prediction(text):
#     text = text.strip()
#     if not text:
#         return None  # Handle empty text
#
#     # Protect "conn.log" from splitting
#     protected_text = text.replace("conn.log", "conn_log")
#
#     # Split into sentences
#     sentences = protected_text.split(".")
#
#     # Restore the original conn.log if needed (not used here but can be if needed downstream)
#     first_sentence = sentences[0].replace("conn_log", "conn.log").lower()
#
#     # If 'no' or 'not' appears in the first sentence, assume no attack
#     if "no" in first_sentence or "not" in first_sentence:
#         return False
#     else:
#         return True
#
#
# # Evaluate RAG output predictions against ground truth labels
# def evaluate(ground_truth, rag_folder):
#     # Initialize counts for TP, TN, FP, FN
#     tp = tn = fp = fn = 0
#     missing = []          # files not found
#     undecided = []        # predictions not extractable
#     false_positives_list = []  # to track false positive filenames
#     false_negatives_list = []
#
#     # Loop through each ground truth label
#     for fname_no_ext, true_label in ground_truth.items():
#         rag_path = os.path.join(rag_folder, fname_no_ext + ".txt")
#
#         # If the RAG output file doesn't exist
#         if not os.path.exists(rag_path):
#             missing.append(fname_no_ext)
#             continue
#
#         # Read the RAG-generated output
#         with open(rag_path, "r", encoding="utf-8") as f:
#             rag_output = f.read()
#
#         # Extract the predicted label
#         pred = extract_prediction(rag_output)
#
#         # If prediction could not be extracted
#         if pred is None:
#             undecided.append(fname_no_ext)
#             continue
#
#         # Compare prediction to ground truth
#         if pred == true_label:
#             if pred:  # both are True
#                 tp += 1
#             else:     # both are False
#                 tn += 1
#         else:
#             if true_label and not pred:  # missed a true case
#                 fn += 1
#                 false_negatives_list.append(fname_no_ext)
#             elif not true_label and pred:  # incorrectly flagged
#                 fp += 1
#                 false_positives_list.append(fname_no_ext)
#
#     # Calculate metrics
#     total = tp + tn + fp + fn
#     accuracy = (tp + tn) / total if total > 0 else 0
#     precision = tp / (tp + fp) if (tp + fp) > 0 else 0
#     recall = tp / (tp + fn) if (tp + fn) > 0 else 0
#     f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
#
#     # Return detailed metrics
#     return {
#         "total_evaluated": total,
#         "true_positives": tp,
#         "true_negatives": tn,
#         "false_positives": fp,
#         "false_negatives": fn,
#         "accuracy": accuracy,
#         "precision": precision,
#         "recall": recall,
#         "f1_score": f1_score,
#         "missing_files": missing,
#         "undecided_outputs": undecided,
#         "false_positive_files": false_positives_list,
#         "false_negative_files": false_negatives_list
#     }
#
#
# # Run evaluation with specified file paths
# if __name__ == "__main__":
#     # Path to ground truth JSON
#     # gt_json_path = "./c101split/test3/ping_flood_labels.json"
#     gt_json_path = "./c101split/test1/ping_flood_labels.json"
#     # gt_json_path = "./fc110split/ping_flood_labels.json"
#     # gt_json_path = "./inragsplit/ping_flood_labels.json"
#     # Folder containing RAG-generated text outputs
#     rag_outputs_folder = "./rag_outputs_c101split1"
#     # rag_outputs_folder = "./rag_outputs_c101split3withanom"
#     # rag_outputs_folder = "./rag_outputs_fc110split"
#     # rag_outputs_folder = "./rag_outputs_inragsplit2"
#     # Load ground truth and evaluate
#     ground_truth = load_ground_truth(gt_json_path)
#     results = evaluate(ground_truth, rag_outputs_folder)
#
#     # Print summary of evaluation metrics
#     print("=== Evaluation Results ===")
#     print(f"Total evaluated: {results['total_evaluated']}")
#     print(f"Accuracy: {results['accuracy']:.2%}")
#     print(f"Precision: {results['precision']:.2%}")
#     print(f"Recall: {results['recall']:.2%}")
#     print(f"F1 Score: {results['f1_score']:.2%}")
#     print(f"True Positives: {results['true_positives']}")
#     print(f"True Negatives: {results['true_negatives']}")
#     print(f"False Positives: {results['false_positives']}")
#     print(f"False Negatives: {results['false_negatives']}")
#
#     # Print info about missing or undecided predictions
#     if results["missing_files"]:
#         print(f"\nMissing RAG output files for: {results['missing_files']}")
#     if results["undecided_outputs"]:
#         print(f"\nUndecided RAG outputs for: {results['undecided_outputs']}")
#     if results["false_positive_files"]:
#         print(f"\nFalse Positives ({len(results['false_positive_files'])}):")
#         for fp_file in results["false_positive_files"]:
#             print(f" - {fp_file}")
#     if results["false_negative_files"]:
#         print(f"\nFalse Negatives ({len(results['false_negative_files'])}):")
#         for fp_file in results["false_negative_files"]:
#             print(f" - {fp_file}")
#
#
# # Build y_true and y_pred lists from ground truth and predictions
# y_true = []
# y_pred = []
#
# for fname_no_ext, true_label in ground_truth.items():
#     rag_path = os.path.join(rag_outputs_folder, fname_no_ext + ".txt")
#     if not os.path.exists(rag_path):
#         continue
#     with open(rag_path, "r", encoding="utf-8") as f:
#         rag_output = f.read()
#     pred = extract_prediction(rag_output)
#     if pred is None:
#         continue
#     y_true.append(1 if true_label else 0)
#     y_pred.append(1 if pred else 0)
#
# # Confusion matrix
# cm = confusion_matrix(y_true, y_pred)
# disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["No Attack", "Ping Flood"])
# disp.plot(cmap=plt.cm.Blues)
# plt.title("Confusion Matrix")
# plt.show()
#
# # ROC curve and AUC
# fpr, tpr, _ = roc_curve(y_true, y_pred)
# roc_auc = auc(fpr, tpr)
#
# plt.figure()
# plt.plot(fpr, tpr, label=f"ROC Curve (AUC = {roc_auc:.2f})")
# plt.plot([0, 1], [0, 1], "k--")
# plt.xlabel("False Positive Rate")
# plt.ylabel("True Positive Rate")
# plt.title("Receiver Operating Characteristic (ROC) Curve")
# plt.legend(loc="lower right")
# plt.grid(True)
# plt.show()

##################################################################################################
# Evaluate RAG against Human Expert
import os
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, roc_curve, auc

# Load ground truth labels from a .txt file and format of each line as filename = True/False
def load_ground_truth_from_txt(txt_path):
    ground_truth = {}
    with open(txt_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or '=' not in line:
                continue # skip empty or malformed lines
            fname, value = line.split('=')
            fname = fname.strip().rsplit('.', 1)[0]  # Remove ".log"
            value = value.strip().lower() == 'true'
            ground_truth[fname] = value
    return ground_truth

# Extract a prediction (True/False) from a RAG-generated response, return None if the output is unclear/empty
def extract_prediction(text):
    text = text.strip()
    if not text:
        return None
    # Protect against "conn.log" splitting issues by temporarily replacing it
    protected_text = text.replace("conn.log", "conn_log")
    sentences = protected_text.split(".")
    first_sentence = sentences[0].replace("conn_log", "conn.log").lower()
    # If the first sentence contains "no" or "not", interpret as a negative prediction
    if "no" in first_sentence or "not" in first_sentence:
        return False
    else:
        return True

# Compare ground truth to predictions in RAG output .txt files
def evaluate(ground_truth, rag_folder):
    tp = tn = fp = fn = 0
    # File tracking
    missing = []
    undecided = []
    false_positives_list = []
    false_negatives_list = []
    # Loop through all ground truth files
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
        # Compare prediction to ground truth and count metrics
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
    # ground_truth_txt_path = "./manual_gt_labels.txt"
    # rag_outputs_folder = "./rag_outputs_inragsplit2"

    ground_truth_txt_path = "./c101_manual_gt_labels.txt"
    rag_outputs_folder = "./rag_outputs_c101split1"

    ground_truth = load_ground_truth_from_txt(ground_truth_txt_path)
    results = evaluate(ground_truth, rag_outputs_folder)

    print("=== Evaluation Results ===")
    print(f"Total evaluated: {results['total_evaluated']}")
    print(f"Accuracy: {results['accuracy']:.2%}")
    print(f"Precision: {results['precision']:.2%}")
    print(f"Recall: {results['recall']:.2%}")
    print(f"F1 Score: {results['f1_score']:.2%}")
    print(f"True Positives: {results['true_positives']}")
    print(f"True Negatives: {results['true_negatives']}")
    print(f"False Positives: {results['false_positives']}")
    print(f"False Negatives: {results['false_negatives']}")

    if results["missing_files"]:
        print(f"\nMissing RAG output files for: {results['missing_files']}")
    if results["undecided_outputs"]:
        print(f"\nUndecided RAG outputs for: {results['undecided_outputs']}")
    if results["false_positive_files"]:
        print(f"\nFalse Positives ({len(results['false_positive_files'])}):")
        for f in results["false_positive_files"]:
            print(f" - {f}")
    if results["false_negative_files"]:
        print(f"\nFalse Negatives ({len(results['false_negative_files'])}):")
        for f in results["false_negative_files"]:
            print(f" - {f}")

# Build y_true and y_pred lists from ground truth and predictions
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

# Confusion matrix
cm = confusion_matrix(y_true, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["No Attack", "Ping Flood"])
disp.plot(cmap=plt.cm.Blues)
plt.title("Confusion Matrix")
plt.show()

# ROC curve and AUC
fpr, tpr, _ = roc_curve(y_true, y_pred)
roc_auc = auc(fpr, tpr)

plt.figure()
plt.plot(fpr, tpr, label=f"ROC Curve (AUC = {roc_auc:.2f})")
plt.plot([0, 1], [0, 1], "k--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("Receiver Operating Characteristic (ROC) Curve")
plt.legend(loc="lower right")
plt.grid(True)
plt.show()
