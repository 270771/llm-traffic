"""
Deep Learning baselines for network attack detection.
Implements CNN and LSTM models using PyTorch.
"""

import os
import json
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve
)
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from .feature_extraction import ZeekFeatureExtractor


class NetworkTrafficDataset(Dataset):
    """PyTorch Dataset for network traffic features."""
    
    def __init__(self, X, y):
        self.X = torch.FloatTensor(X)
        self.y = torch.FloatTensor(y)
    
    def __len__(self):
        return len(self.y)
    
    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


class CNN1D(nn.Module):
    """1D CNN for network traffic classification."""
    
    def __init__(self, input_dim, num_filters=64, kernel_size=3):
        super(CNN1D, self).__init__()
        
        # Reshape input to (batch, 1, features) for 1D conv
        self.conv1 = nn.Conv1d(1, num_filters, kernel_size=kernel_size, padding=kernel_size//2)
        self.bn1 = nn.BatchNorm1d(num_filters)
        self.conv2 = nn.Conv1d(num_filters, num_filters*2, kernel_size=kernel_size, padding=kernel_size//2)
        self.bn2 = nn.BatchNorm1d(num_filters*2)
        self.pool = nn.MaxPool1d(2)
        
        # Calculate flattened dimension
        self.flat_dim = (num_filters * 2) * (input_dim // 2)
        
        self.fc1 = nn.Linear(self.flat_dim, 128)
        self.dropout = nn.Dropout(0.5)
        self.fc2 = nn.Linear(128, 1)
        
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()
    
    def forward(self, x):
        # Reshape: (batch, features) -> (batch, 1, features)
        x = x.unsqueeze(1)
        
        # Conv layers
        x = self.relu(self.bn1(self.conv1(x)))
        x = self.relu(self.bn2(self.conv2(x)))
        x = self.pool(x)
        
        # Flatten
        x = x.view(x.size(0), -1)
        
        # Fully connected layers
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.sigmoid(self.fc2(x))
        
        return x


class LSTM(nn.Module):
    """LSTM for network traffic classification."""
    
    def __init__(self, input_dim, hidden_dim=64, num_layers=2):
        super(LSTM, self).__init__()
        
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # LSTM layer
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=0.3)
        
        # Fully connected layer
        self.fc = nn.Linear(hidden_dim, 1)
        self.sigmoid = nn.Sigmoid()
    
    def forward(self, x):
        # Reshape: (batch, features) -> (batch, 1, features) for sequence
        x = x.unsqueeze(1)
        
        # LSTM
        lstm_out, _ = self.lstm(x)
        
        # Take output from last time step
        x = lstm_out[:, -1, :]
        
        # Fully connected
        x = self.sigmoid(self.fc(x))
        
        return x


class DeepLearningBaseline:
    """Deep Learning baseline for network attack detection."""
    
    def __init__(self, model_type='cnn', attack_type='ping_flood', device='cpu'):
        """
        Args:
            model_type: 'cnn' or 'lstm'
            attack_type: 'ping_flood' or 'syn_flood'
            device: 'cpu' or 'cuda'
        """
        self.model_type = model_type
        self.attack_type = attack_type
        self.device = torch.device(device if torch.cuda.is_available() else 'cpu')
        self.model = None
        self.scaler = StandardScaler()
        self.feature_extractor = ZeekFeatureExtractor()
        self.input_dim = len(self.feature_extractor.get_feature_names())
    
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
    
    def train(self, log_folder, labels_path, label_type='json', 
              epochs=50, batch_size=32, learning_rate=0.001):
        """
        Train the model.
        
        Args:
            log_folder: Path to folder containing .log files
            labels_path: Path to ground truth labels
            label_type: 'json' or 'txt'
            epochs: Number of training epochs
            batch_size: Batch size
            learning_rate: Learning rate
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
        
        # Create dataset and dataloader
        dataset = NetworkTrafficDataset(X_scaled, y)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        # Initialize model
        if self.model_type == 'cnn':
            self.model = CNN1D(input_dim=self.input_dim).to(self.device)
        elif self.model_type == 'lstm':
            self.model = LSTM(input_dim=self.input_dim).to(self.device)
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
        
        # Loss and optimizer
        criterion = nn.BCELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        
        # Training loop
        print(f"\nTraining {self.model_type.upper()} model...")
        self.model.train()
        
        for epoch in range(epochs):
            total_loss = 0
            for batch_X, batch_y in dataloader:
                batch_X = batch_X.to(self.device)
                batch_y = batch_y.to(self.device)
                
                # Forward pass
                outputs = self.model(batch_X).squeeze()
                loss = criterion(outputs, batch_y)
                
                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
            
            avg_loss = total_loss / len(dataloader)
            
            if (epoch + 1) % 10 == 0:
                print(f"Epoch [{epoch+1}/{epochs}], Loss: {avg_loss:.4f}")
        
        print("Training complete!")
        
        # Evaluate on training data
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X_scaled).to(self.device)
            y_pred_prob = self.model(X_tensor).squeeze().cpu().numpy()
            y_pred = (y_pred_prob > 0.5).astype(int)
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
        self.model.eval()
        predictions = {}
        probabilities = {}
        
        with torch.no_grad():
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
                X_tensor = torch.FloatTensor(X_scaled).to(self.device)
                prob = self.model(X_tensor).squeeze().cpu().item()
                pred = 1 if prob > 0.5 else 0
                
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
        """Save trained model."""
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'model_type': self.model_type,
            'attack_type': self.attack_type,
            'input_dim': self.input_dim,
            'scaler': self.scaler
        }, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load trained model."""
        checkpoint = torch.load(filepath, map_location=self.device)
        
        self.model_type = checkpoint['model_type']
        self.attack_type = checkpoint['attack_type']
        self.input_dim = checkpoint['input_dim']
        self.scaler = checkpoint['scaler']
        
        # Initialize model
        if self.model_type == 'cnn':
            self.model = CNN1D(input_dim=self.input_dim).to(self.device)
        elif self.model_type == 'lstm':
            self.model = LSTM(input_dim=self.input_dim).to(self.device)
        
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.eval()
        
        print(f"Model loaded from {filepath}")


if __name__ == "__main__":
    # Example usage
    print("Deep Learning Baseline - Example Usage")
    print("="*60)
    
    # Check device
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"Using device: {device}\n")
    
    # CNN Example
    print("1. CNN Model initialized")
    cnn = DeepLearningBaseline(model_type='cnn', attack_type='ping_flood', device=device)
    
    # LSTM Example
    print("2. LSTM Model initialized")
    lstm = DeepLearningBaseline(model_type='lstm', attack_type='ping_flood', device=device)
    
    print("\nReady to train on actual data!")
