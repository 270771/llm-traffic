"""
Rule-based baseline detector (similar to Snort/Suricata/Zeek rules).
Implements simple heuristic rules for ping flood and SYN flood detection.
"""

import os
import json
import numpy as np
from collections import defaultdict
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve
)
import matplotlib.pyplot as plt


class RuleBasedDetector:
    """Rule-based network attack detector using heuristic thresholds."""
    
    def __init__(self, attack_type='ping_flood'):
        """
        Args:
            attack_type: 'ping_flood' or 'syn_flood'
        """
        self.attack_type = attack_type
        
        # Default thresholds (similar to IDS rules)
        if attack_type == 'ping_flood':
            self.rules = {
                'icmp_threshold': 5,        # Min ICMP echo requests
                'time_window': 60,          # Seconds
                'icmp_ratio_threshold': 0.3 # 30% ICMP traffic
            }
        elif attack_type == 'syn_flood':
            self.rules = {
                's0_threshold': 5,          # Min failed connections
                's0_ratio_threshold': 0.5,  # 50% failed connections
                'syn_rate_threshold': 10    # SYNs per second
            }
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")
    
    def parse_zeek_log(self, log_path):
        """Parse Zeek conn.log file."""
        records = []
        with open(log_path, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                fields = line.strip().split('\t')
                if len(fields) >= 22:
                    records.append(fields)
        return records
    
    def detect_ping_flood(self, log_path):
        """
        Detect ping flood using rule-based heuristics.
        
        Rules (inspired by Snort/Suricata):
        1. ICMP echo request count >= threshold
        2. High ICMP traffic ratio
        3. Short time window
        
        Returns:
            detected: Boolean indicating if attack detected
            confidence: Confidence score (0-1)
            details: Dictionary with detection details
        """
        records = self.parse_zeek_log(log_path)
        
        if not records:
            return False, 0.0, {}
        
        # Count ICMP traffic
        icmp_count = 0
        total_count = len(records)
        timestamps = []
        
        for record in records:
            proto = record[6] if len(record) > 6 else ''
            if proto == 'icmp':
                icmp_count += 1
            
            ts = float(record[0]) if len(record) > 0 else 0
            timestamps.append(ts)
        
        # Calculate metrics
        icmp_ratio = icmp_count / total_count if total_count > 0 else 0
        time_span = max(timestamps) - min(timestamps) if timestamps else 0
        
        # Apply rules
        rule_matches = 0
        
        # Rule 1: ICMP count threshold
        if icmp_count >= self.rules['icmp_threshold']:
            rule_matches += 1
        
        # Rule 2: ICMP ratio threshold
        if icmp_ratio >= self.rules['icmp_ratio_threshold']:
            rule_matches += 1
        
        # Rule 3: Time window (within specified seconds)
        if time_span > 0 and time_span <= self.rules['time_window']:
            rule_matches += 1
        
        # Detection logic: at least 2 out of 3 rules must match
        detected = rule_matches >= 2
        confidence = rule_matches / 3.0  # 0.33, 0.66, or 1.0
        
        details = {
            'icmp_count': icmp_count,
            'icmp_ratio': icmp_ratio,
            'time_span': time_span,
            'total_flows': total_count,
            'rules_matched': rule_matches
        }
        
        return detected, confidence, details
    
    def detect_syn_flood(self, log_path):
        """
        Detect SYN flood using rule-based heuristics.
        
        Rules (inspired by Snort/Suricata):
        1. High number of S0 (failed) connections
        2. High ratio of S0 to total TCP connections
        3. High SYN rate (connections per second)
        
        Returns:
            detected: Boolean indicating if attack detected
            confidence: Confidence score (0-1)
            details: Dictionary with detection details
        """
        records = self.parse_zeek_log(log_path)
        
        if not records:
            return False, 0.0, {}
        
        # Count TCP and connection states
        tcp_count = 0
        s0_count = 0  # Failed connections (typical in SYN flood)
        timestamps = []
        
        for record in records:
            proto = record[6] if len(record) > 6 else ''
            conn_state = record[11] if len(record) > 11 else ''
            
            if proto == 'tcp':
                tcp_count += 1
                if conn_state == 'S0':
                    s0_count += 1
            
            ts = float(record[0]) if len(record) > 0 else 0
            timestamps.append(ts)
        
        # Calculate metrics
        s0_ratio = s0_count / tcp_count if tcp_count > 0 else 0
        time_span = max(timestamps) - min(timestamps) if timestamps else 0
        syn_rate = tcp_count / max(time_span, 1)
        
        # Apply rules
        rule_matches = 0
        
        # Rule 1: S0 count threshold
        if s0_count >= self.rules['s0_threshold']:
            rule_matches += 1
        
        # Rule 2: S0 ratio threshold
        if s0_ratio >= self.rules['s0_ratio_threshold']:
            rule_matches += 1
        
        # Rule 3: High SYN rate
        if syn_rate >= self.rules['syn_rate_threshold']:
            rule_matches += 1
        
        # Detection logic: at least 2 out of 3 rules must match
        detected = rule_matches >= 2
        confidence = rule_matches / 3.0
        
        details = {
            's0_count': s0_count,
            's0_ratio': s0_ratio,
            'tcp_count': tcp_count,
            'syn_rate': syn_rate,
            'time_span': time_span,
            'rules_matched': rule_matches
        }
        
        return detected, confidence, details
    
    def predict(self, log_folder, filenames):
        """
        Make predictions on multiple log files.
        
        Args:
            log_folder: Path to folder containing .log files
            filenames: List of filenames (without .log extension)
            
        Returns:
            predictions: Dictionary mapping filename to prediction (0 or 1)
            probabilities: Dictionary mapping filename to confidence score
        """
        predictions = {}
        probabilities = {}
        
        for fname in filenames:
            log_path = os.path.join(log_folder, fname + '.log')
            
            if not os.path.exists(log_path):
                predictions[fname] = 0
                probabilities[fname] = 0.0
                continue
            
            # Detect based on attack type
            if self.attack_type == 'ping_flood':
                detected, confidence, _ = self.detect_ping_flood(log_path)
            elif self.attack_type == 'syn_flood':
                detected, confidence, _ = self.detect_syn_flood(log_path)
            else:
                detected, confidence = False, 0.0
            
            predictions[fname] = 1 if detected else 0
            probabilities[fname] = confidence
        
        return predictions, probabilities
    
    def load_ground_truth_json(self, json_path):
        """Load ground truth from JSON file."""
        with open(json_path, "r") as f:
            data = json.load(f)
        
        if self.attack_type == 'ping_flood':
            key = 'ping_flood_detected'
        elif self.attack_type == 'syn_flood':
            key = 'syn_flood_detected'
        else:
            key = 'attack_detected'
        
        return {k.rsplit(".", 1)[0]: v.get(key, False) for k, v in data.items()}
    
    def load_ground_truth_txt(self, txt_path):
        """Load ground truth from TXT file (expert labels)."""
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
    
    def evaluate(self, log_folder, labels_path, label_type='json', output_dir=None):
        """
        Evaluate the detector and generate metrics.
        
        Args:
            log_folder: Path to folder containing .log files
            labels_path: Path to ground truth labels
            label_type: 'json' or 'txt'
            output_dir: Directory to save results (optional)
        """
        # Load labels
        if label_type == 'json':
            labels = self.load_ground_truth_json(labels_path)
        else:
            labels = self.load_ground_truth_txt(labels_path)
        
        # Make predictions
        filenames = list(labels.keys())
        predictions, probabilities = self.predict(log_folder, filenames)
        
        # Align predictions with ground truth
        y_true = []
        y_pred = []
        y_prob = []
        
        for fname in filenames:
            if fname in predictions:
                y_true.append(1 if labels[fname] else 0)
                y_pred.append(predictions[fname])
                y_prob.append(probabilities[fname])
        
        y_true = np.array(y_true)
        y_pred = np.array(y_pred)
        y_prob = np.array(y_prob)
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # ROC AUC
        try:
            auc_score = roc_auc_score(y_true, y_prob)
        except ValueError:
            auc_score = 0.0
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        
        results = {
            'model_type': 'rule_based',
            'attack_type': self.attack_type,
            'rules': self.rules,
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'auc': float(auc_score),
            'confusion_matrix': {
                'TP': int(tp),
                'TN': int(tn),
                'FP': int(fp),
                'FN': int(fn)
            },
            'total_samples': len(y_true)
        }
        
        # Print results
        print("\n" + "="*60)
        print(f"RULE-BASED - {self.attack_type.replace('_', ' ').title()} Detection")
        print("="*60)
        print(f"Rules: {self.rules}")
        print(f"\nAccuracy:  {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1-Score:  {f1:.4f}")
        print(f"AUC-ROC:   {auc_score:.4f}")
        print(f"\nConfusion Matrix:")
        print(f"  TP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}")
        print("="*60 + "\n")
        
        # Save results if output directory provided
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
            # Save metrics
            with open(os.path.join(output_dir, 'rule_based_metrics.json'), 'w') as f:
                json.dump(results, f, indent=2)
            
            # Plot confusion matrix
            self._plot_confusion_matrix(cm, output_dir)
            
            # Plot ROC curve
            self._plot_roc_curve(y_true, y_prob, auc_score, output_dir)
        
        return results
    
    def _plot_confusion_matrix(self, cm, output_dir):
        """Plot and save confusion matrix."""
        from sklearn.metrics import ConfusionMatrixDisplay
        
        fig, ax = plt.subplots(figsize=(8, 6))
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Normal', 'Attack'])
        disp.plot(ax=ax, cmap='Blues', values_format='d')
        plt.title('Rule-Based Detector - Confusion Matrix')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'rule_based_confusion_matrix.png'), dpi=300)
        plt.close()
    
    def _plot_roc_curve(self, y_true, y_prob, auc_score, output_dir):
        """Plot and save ROC curve."""
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, linewidth=2, label=f'AUC = {auc_score:.4f}')
        plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random Classifier')
        plt.xlabel('False Positive Rate', fontsize=12)
        plt.ylabel('True Positive Rate', fontsize=12)
        plt.title('Rule-Based Detector - ROC Curve', fontsize=14)
        plt.legend(fontsize=11)
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'rule_based_roc_curve.png'), dpi=300)
        plt.close()
    
    def set_rules(self, rules_dict):
        """Update detection rules."""
        self.rules.update(rules_dict)
        print(f"Updated rules: {self.rules}")


if __name__ == "__main__":
    # Example usage
    print("Rule-Based Detector - Example Usage")
    print("="*60)
    
    # Ping Flood Detector
    print("\n1. Ping Flood Detector")
    ping_detector = RuleBasedDetector(attack_type='ping_flood')
    print(f"   Default rules: {ping_detector.rules}")
    
    # SYN Flood Detector
    print("\n2. SYN Flood Detector")
    syn_detector = RuleBasedDetector(attack_type='syn_flood')
    print(f"   Default rules: {syn_detector.rules}")
    
    print("\nReady to detect attacks!")
