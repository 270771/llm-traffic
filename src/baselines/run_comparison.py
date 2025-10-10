"""
Comprehensive baseline comparison script.
Runs all baseline methods (Rule-based, SVM, Random Forest, CNN, LSTM) and RAG system
side-by-side for direct comparison.
"""

import os
import sys
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .rule_based import RuleBasedDetector
from .traditional_ml import TraditionalMLBaseline
from .deep_learning import DeepLearningBaseline


class BaselineComparison:
    """Comprehensive comparison of all baseline methods."""
    
    def __init__(self, attack_type='ping_flood'):
        """
        Args:
            attack_type: 'ping_flood' or 'syn_flood'
        """
        self.attack_type = attack_type
        self.results = {}
    
    def load_rag_results(self, rag_folder, labels_dict):
        """
        Load and evaluate RAG system results.
        
        Args:
            rag_folder: Folder containing RAG output .txt files
            labels_dict: Ground truth labels
            
        Returns:
            Dictionary with metrics
        """
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, f1_score,
            confusion_matrix, roc_auc_score
        )
        
        tp = tn = fp = fn = 0
        predictions = {}
        
        for fname_no_ext, true_label in labels_dict.items():
            rag_path = os.path.join(rag_folder, fname_no_ext + ".txt")
            
            if not os.path.exists(rag_path):
                continue
            
            with open(rag_path, "r", encoding="utf-8") as f:
                rag_output = f.read()
            
            # Extract prediction (same logic as evaluate_rag.py)
            pred = self._extract_rag_prediction(rag_output)
            
            if pred is None:
                continue
            
            predictions[fname_no_ext] = pred
            
            # Update confusion matrix
            if pred == true_label:
                if pred:
                    tp += 1
                else:
                    tn += 1
            else:
                if true_label and not pred:
                    fn += 1
                elif not true_label and pred:
                    fp += 1
        
        # Calculate metrics
        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total if total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score_val = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        # For AUC, we need probabilities - use binary predictions as proxy
        y_true = []
        y_pred = []
        for fname, pred in predictions.items():
            if fname in labels_dict:
                y_true.append(1 if labels_dict[fname] else 0)
                y_pred.append(1 if pred else 0)
        
        try:
            auc = roc_auc_score(y_true, y_pred) if len(set(y_true)) > 1 else 0.0
        except:
            auc = 0.0
        
        return {
            'model_type': 'RAG+LLM',
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score_val,
            'auc': auc,
            'confusion_matrix': {
                'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn
            },
            'total_samples': total
        }
    
    def _extract_rag_prediction(self, text):
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
    
    def run_all_baselines(self, log_folder, labels_path, label_type='json', 
                          output_dir='./results/baseline_comparison',
                          rag_folder=None):
        """
        Run all baseline methods and compare results.
        
        Args:
            log_folder: Path to folder containing .log files
            labels_path: Path to ground truth labels
            label_type: 'json' or 'txt'
            output_dir: Directory to save comparison results
            rag_folder: Path to RAG outputs (optional)
        """
        os.makedirs(output_dir, exist_ok=True)
        
        print("\n" + "="*80)
        print("COMPREHENSIVE BASELINE COMPARISON")
        print(f"Attack Type: {self.attack_type.replace('_', ' ').title()}")
        print("="*80 + "\n")
        
        # 1. Rule-Based Detector
        print("[1/5] Running Rule-Based Detector (Snort/Suricata-style)...")
        rule_detector = RuleBasedDetector(attack_type=self.attack_type)
        rule_results = rule_detector.evaluate(
            log_folder, labels_path, label_type,
            output_dir=os.path.join(output_dir, 'rule_based')
        )
        self.results['Rule-Based'] = rule_results
        
        # 2. SVM
        print("[2/5] Running SVM Classifier...")
        svm = TraditionalMLBaseline(model_type='svm', attack_type=self.attack_type)
        svm.train(log_folder, labels_path, label_type)
        svm_results = svm.evaluate(
            log_folder, labels_path, label_type,
            output_dir=os.path.join(output_dir, 'svm')
        )
        self.results['SVM'] = svm_results
        
        # 3. Random Forest
        print("[3/5] Running Random Forest Classifier...")
        rf = TraditionalMLBaseline(model_type='random_forest', attack_type=self.attack_type)
        rf.train(log_folder, labels_path, label_type)
        rf_results = rf.evaluate(
            log_folder, labels_path, label_type,
            output_dir=os.path.join(output_dir, 'random_forest')
        )
        self.results['Random Forest'] = rf_results
        
        # 4. CNN
        print("[4/5] Running CNN Classifier...")
        cnn = DeepLearningBaseline(model_type='cnn', attack_type=self.attack_type)
        cnn.train(log_folder, labels_path, label_type, epochs=50, batch_size=32)
        cnn_results = cnn.evaluate(
            log_folder, labels_path, label_type,
            output_dir=os.path.join(output_dir, 'cnn')
        )
        self.results['CNN'] = cnn_results
        
        # 5. LSTM
        print("[5/5] Running LSTM Classifier...")
        lstm = DeepLearningBaseline(model_type='lstm', attack_type=self.attack_type)
        lstm.train(log_folder, labels_path, label_type, epochs=50, batch_size=32)
        lstm_results = lstm.evaluate(
            log_folder, labels_path, label_type,
            output_dir=os.path.join(output_dir, 'lstm')
        )
        self.results['LSTM'] = lstm_results
        
        # 6. RAG+LLM (if folder provided)
        if rag_folder:
            print("[6/6] Evaluating RAG+LLM System...")
            if label_type == 'json':
                from baselines.traditional_ml import TraditionalMLBaseline
                temp = TraditionalMLBaseline(model_type='svm', attack_type=self.attack_type)
                labels = temp.load_ground_truth_json(labels_path)
            else:
                from baselines.traditional_ml import TraditionalMLBaseline
                temp = TraditionalMLBaseline(model_type='svm', attack_type=self.attack_type)
                labels = temp.load_ground_truth_txt(labels_path)
            
            rag_results = self.load_rag_results(rag_folder, labels)
            self.results['RAG+LLM'] = rag_results
        
        # Generate comparison visualizations
        self._generate_comparison_report(output_dir)
        
        print("\n" + "="*80)
        print("BASELINE COMPARISON COMPLETE")
        print(f"Results saved to: {output_dir}")
        print("="*80 + "\n")
    
    def _generate_comparison_report(self, output_dir):
        """Generate comprehensive comparison report."""
        
        # 1. Create summary table
        summary_data = []
        for model_name, results in self.results.items():
            summary_data.append({
                'Model': model_name,
                'Accuracy': f"{results['accuracy']:.4f}",
                'Precision': f"{results['precision']:.4f}",
                'Recall': f"{results['recall']:.4f}",
                'F1-Score': f"{results['f1_score']:.4f}",
                'AUC-ROC': f"{results['auc']:.4f}",
                'TP': results['confusion_matrix']['TP'],
                'TN': results['confusion_matrix']['TN'],
                'FP': results['confusion_matrix']['FP'],
                'FN': results['confusion_matrix']['FN']
            })
        
        df = pd.DataFrame(summary_data)
        
        # Save as CSV
        csv_path = os.path.join(output_dir, 'comparison_summary.csv')
        df.to_csv(csv_path, index=False)
        print(f"\n✓ Summary table saved to: {csv_path}")
        
        # Save as formatted text
        txt_path = os.path.join(output_dir, 'comparison_summary.txt')
        with open(txt_path, 'w') as f:
            f.write("="*100 + "\n")
            f.write(f"BASELINE COMPARISON SUMMARY - {self.attack_type.replace('_', ' ').title()} Detection\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*100 + "\n\n")
            f.write(df.to_string(index=False))
            f.write("\n\n" + "="*100 + "\n")
        
        # Print to console
        print("\n" + df.to_string(index=False))
        
        # 2. Generate comparison plots
        self._plot_metrics_comparison(output_dir)
        self._plot_confusion_matrices(output_dir)
        
        # 3. Save detailed JSON results
        json_path = os.path.join(output_dir, 'detailed_results.json')
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"✓ Detailed results saved to: {json_path}")
    
    def _plot_metrics_comparison(self, output_dir):
        """Plot side-by-side comparison of all metrics."""
        metrics = ['accuracy', 'precision', 'recall', 'f1_score', 'auc']
        metric_labels = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC-ROC']
        
        # Prepare data
        models = list(self.results.keys())
        data = {metric: [self.results[model][metric] for model in models] 
                for metric in metrics}
        
        # Create subplots
        fig, axes = plt.subplots(2, 3, figsize=(18, 10))
        axes = axes.flatten()
        
        # Plot each metric
        for idx, (metric, label) in enumerate(zip(metrics, metric_labels)):
            ax = axes[idx]
            values = data[metric]
            bars = ax.bar(range(len(models)), values, color=sns.color_palette("husl", len(models)))
            
            # Highlight best performer
            best_idx = values.index(max(values))
            bars[best_idx].set_color('gold')
            bars[best_idx].set_edgecolor('black')
            bars[best_idx].set_linewidth(2)
            
            ax.set_xlabel('Model', fontsize=11)
            ax.set_ylabel(label, fontsize=11)
            ax.set_title(f'{label} Comparison', fontsize=12, fontweight='bold')
            ax.set_xticks(range(len(models)))
            ax.set_xticklabels(models, rotation=45, ha='right')
            ax.set_ylim(0, 1.1)
            ax.grid(axis='y', alpha=0.3)
            
            # Add value labels on bars
            for i, v in enumerate(values):
                ax.text(i, v + 0.02, f'{v:.3f}', ha='center', va='bottom', fontsize=9)
        
        # Remove extra subplot
        fig.delaxes(axes[5])
        
        plt.suptitle(f'Baseline Comparison - {self.attack_type.replace("_", " ").title()} Detection',
                     fontsize=16, fontweight='bold', y=0.995)
        plt.tight_layout()
        
        plot_path = os.path.join(output_dir, 'metrics_comparison.png')
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"✓ Metrics comparison plot saved to: {plot_path}")
    
    def _plot_confusion_matrices(self, output_dir):
        """Plot all confusion matrices side-by-side."""
        from sklearn.metrics import ConfusionMatrixDisplay
        
        n_models = len(self.results)
        n_cols = 3
        n_rows = (n_models + n_cols - 1) // n_cols
        
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(15, 5 * n_rows))
        axes = axes.flatten() if n_models > 1 else [axes]
        
        for idx, (model_name, results) in enumerate(self.results.items()):
            cm_dict = results['confusion_matrix']
            cm = np.array([[cm_dict['TN'], cm_dict['FP']], 
                          [cm_dict['FN'], cm_dict['TP']]])
            
            disp = ConfusionMatrixDisplay(confusion_matrix=cm, 
                                         display_labels=['Normal', 'Attack'])
            disp.plot(ax=axes[idx], cmap='Blues', values_format='d')
            axes[idx].set_title(f'{model_name}', fontsize=12, fontweight='bold')
        
        # Remove extra subplots
        for idx in range(n_models, len(axes)):
            fig.delaxes(axes[idx])
        
        plt.suptitle(f'Confusion Matrices - {self.attack_type.replace("_", " ").title()} Detection',
                     fontsize=16, fontweight='bold')
        plt.tight_layout()
        
        plot_path = os.path.join(output_dir, 'confusion_matrices_comparison.png')
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"✓ Confusion matrices plot saved to: {plot_path}")


def main():
    """Main function for running baseline comparison."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run comprehensive baseline comparison')
    parser.add_argument('--attack-type', type=str, default='ping_flood',
                       choices=['ping_flood', 'syn_flood'],
                       help='Type of attack to detect')
    parser.add_argument('--log-folder', type=str, required=True,
                       help='Path to folder containing .log files')
    parser.add_argument('--labels', type=str, required=True,
                       help='Path to ground truth labels (JSON or TXT)')
    parser.add_argument('--label-type', type=str, default='json',
                       choices=['json', 'txt'],
                       help='Type of ground truth file')
    parser.add_argument('--output-dir', type=str, 
                       default='./results/baseline_comparison',
                       help='Directory to save results')
    parser.add_argument('--rag-folder', type=str, default=None,
                       help='Path to RAG output folder (optional)')
    
    args = parser.parse_args()
    
    # Run comparison
    comparison = BaselineComparison(attack_type=args.attack_type)
    comparison.run_all_baselines(
        log_folder=args.log_folder,
        labels_path=args.labels,
        label_type=args.label_type,
        output_dir=args.output_dir,
        rag_folder=args.rag_folder
    )


if __name__ == "__main__":
    main()
