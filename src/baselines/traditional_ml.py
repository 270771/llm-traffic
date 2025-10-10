"""
Traditional Machine Learning baselines for network attack detection.
Implements SVM and Random Forest classifiers.
"""

import os
import json
import numpy as np
import pickle
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve, classification_report
)
import matplotlib.pyplot as plt
from .feature_extraction import ZeekFeatureExtractor


class TraditionalMLBaseline:
    """Base class for traditional ML baselines."""
    
    def __init__(self, model_type='svm', attack_type='ping_flood'):
        """
        Args:
            model_type: 'svm' or 'random_forest'
            attack_type: 'ping_flood' or 'syn_flood'
        """
        self.model_type = model_type
        self.attack_type = attack_type
        self.model = None
        self.scaler = StandardScaler()
        self.feature_extractor = ZeekFeatureExtractor()
        
        if model_type == 'svm':
            # Linear SVM with probability estimates
            self.model = SVC(kernel='rbf', probability=True, random_state=42)
        elif model_type == 'random_forest':
            # Random Forest with 100 trees
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")
    
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
    
    def train(self, log_folder, labels_path, label_type='json'):
        """
        Train the model.
        
        Args:
            log_folder: Path to folder containing .log files
            labels_path: Path to ground truth labels (JSON or TXT)
            label_type: 'json' or 'txt'
        """
        # Load labels
        if label_type == 'json':
            labels = self.load_ground_truth_json(labels_path)
        else:
            labels = self.load_ground_truth_txt(labels_path)
        
        # Extract features
        print(f"Extracting features from {len(labels)} log files...")
        X, y, filenames = self.feature_extractor.extract_dataset(log_folder, labels)
        
        print(f"Dataset shape: X={X.shape}, y={y.shape}")
        print(f"Positive samples: {np.sum(y)}, Negative samples: {len(y) - np.sum(y)}")
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        print(f"Training {self.model_type} model...")
        self.model.fit(X_scaled, y)
        
        # Training accuracy
        y_pred = self.model.predict(X_scaled)
        train_acc = accuracy_score(y, y_pred)
        print(f"Training accuracy: {train_acc:.4f}")
        
        return X_scaled, y, filenames
    
    def predict(self, log_folder, filenames):
        """
        Make predictions on new data.
        
        Args:
            log_folder: Path to folder containing .log files
            filenames: List of filenames (without .log extension)
            
        Returns:
            predictions: Dictionary mapping filename to prediction (0 or 1)
            probabilities: Dictionary mapping filename to probability of attack
        """
        predictions = {}
        probabilities = {}
        
        for fname in filenames:
            log_path = os.path.join(log_folder, fname + '.log')
            
            if not os.path.exists(log_path):
                predictions[fname] = 0
                probabilities[fname] = 0.0
                continue
            
            # Extract features
            features = self.feature_extractor.extract_flow_features(log_path)
            X = np.array([list(features.values())])
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Predict
            pred = self.model.predict(X_scaled)[0]
            prob = self.model.predict_proba(X_scaled)[0][1]  # Probability of class 1
            
            predictions[fname] = int(pred)
            probabilities[fname] = float(prob)
        
        return predictions, probabilities
    
    def evaluate(self, log_folder, labels_path, label_type='json', output_dir=None):
        """
        Evaluate the model and generate metrics.
        
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
            'model_type': self.model_type,
            'attack_type': self.attack_type,
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
        print(f"{self.model_type.upper()} - {self.attack_type.replace('_', ' ').title()} Detection")
        print("="*60)
        print(f"Accuracy:  {accuracy:.4f}")
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
            with open(os.path.join(output_dir, f'{self.model_type}_metrics.json'), 'w') as f:
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
        plt.title(f'{self.model_type.upper()} - Confusion Matrix')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{self.model_type}_confusion_matrix.png'), dpi=300)
        plt.close()
    
    def _plot_roc_curve(self, y_true, y_prob, auc_score, output_dir):
        """Plot and save ROC curve."""
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, linewidth=2, label=f'AUC = {auc_score:.4f}')
        plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random Classifier')
        plt.xlabel('False Positive Rate', fontsize=12)
        plt.ylabel('True Positive Rate', fontsize=12)
        plt.title(f'{self.model_type.upper()} - ROC Curve', fontsize=14)
        plt.legend(fontsize=11)
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{self.model_type}_roc_curve.png'), dpi=300)
        plt.close()
    
    def save_model(self, filepath):
        """Save trained model and scaler."""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'model_type': self.model_type,
            'attack_type': self.attack_type
        }
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load trained model and scaler."""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.model_type = model_data['model_type']
        self.attack_type = model_data['attack_type']
        print(f"Model loaded from {filepath}")


if __name__ == "__main__":
    # Example usage
    print("Traditional ML Baseline - Example Usage")
    print("="*60)
    
    # SVM Example
    print("\n1. Training SVM...")
    svm = TraditionalMLBaseline(model_type='svm', attack_type='ping_flood')
    
    # Random Forest Example
    print("\n2. Training Random Forest...")
    rf = TraditionalMLBaseline(model_type='random_forest', attack_type='ping_flood')
    
    print("\nReady to train on actual data!")
