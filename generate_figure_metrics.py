"""
Figure: All Metrics Comparison (Line Chart)
Shows Accuracy, Precision, Recall, F1 Score for each method
Generates separate versions for Ping Flood and SYN Flood attacks
"""

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Set style
plt.rcParams['font.size'] = 11
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 14
plt.rcParams['legend.fontsize'] = 11

# Attack type configurations
attack_configs = {
    'ping_flood': {
        'name': 'Ping Flood',
        'rag_data': {
            'Accuracy': 97.74,
            'Precision': 76.36,
            'Recall': 100.00,
            'F1': 86.60
        }
    },
    'syn_flood': {
        'name': 'SYN Flood',
        'rag_data': {
            'Accuracy': 98.82,
            'Precision': 100.00,
            'Recall': 98.64,
            'F1': 99.32
        }
    }
}

# Baseline data (same for both attacks)
baseline_data = {
    'Method': ['Rule-Based\nIDS', 'SVM', 'Random\nForest', 'CNN', 'LSTM'],
    'Accuracy': [88.5, 92.3, 93.8, 94.2, 95.1],
    'Precision': [67.5, 80.8, 75.4, 85.5, 79.8],
    'Recall': [89.3, 91.2, 93.8, 94.8, 95.6],
    'F1': [76.9, 85.7, 82.3, 89.9, 86.9],
}

def generate_figure(attack_type):
    config = attack_configs[attack_type]
    
    # Create data with ReGAIN appended
    data = {
        'Method': baseline_data['Method'] + ['ReGAIN'],
        'Accuracy': baseline_data['Accuracy'] + [config['rag_data']['Accuracy']],
        'Precision': baseline_data['Precision'] + [config['rag_data']['Precision']],
        'Recall': baseline_data['Recall'] + [config['rag_data']['Recall']],
        'F1': baseline_data['F1'] + [config['rag_data']['F1']],
    }
    
    df = pd.DataFrame(data)
    
    # Create figure
    fig, ax = plt.subplots(figsize=(14, 8))
    fig.patch.set_facecolor('white')
    
    # Set positions
    x = np.arange(len(df))
    
    # Colors
    color_accuracy = '#E57373'   # Light red/coral
    color_precision = '#FFB74D'  # Light orange  
    color_recall = '#4FC3F7'     # Light cyan/turquoise
    color_f1 = '#81C784'         # Light green
    
    # Create line plots with markers
    ax.plot(x, df['Accuracy'], marker='o', markersize=10, linewidth=2.5, 
            label='Accuracy', color=color_accuracy, markeredgecolor='white', 
            markeredgewidth=2)
    ax.plot(x, df['Precision'], marker='s', markersize=10, linewidth=2.5,
            label='Precision', color=color_precision, markeredgecolor='white',
            markeredgewidth=2)
    ax.plot(x, df['Recall'], marker='^', markersize=10, linewidth=2.5,
            label='Recall', color=color_recall, markeredgecolor='white',
            markeredgewidth=2)
    ax.plot(x, df['F1'], marker='D', markersize=9, linewidth=2.5,
            label='F1 Score', color=color_f1, markeredgecolor='white',
            markeredgewidth=2)
    
    # Add value labels for accuracy points
    for i, (xpos, ypos) in enumerate(zip(x, df['Accuracy'])):
        ax.text(xpos, ypos + 1.5,
                f'{df["Accuracy"].iloc[i]:.1f}%' if i < 5 else f'{df["Accuracy"].iloc[i]:.2f}%',
                ha='center', va='bottom', fontsize=9, fontweight='bold', 
                color=color_accuracy)
    
    # Customize
    ax.set_ylabel('Performance (%)', fontweight='bold', fontsize=13)
    ax.set_xlabel('Method', fontweight='bold', fontsize=13)
    ax.set_xticks(x)
    ax.set_xticklabels(df['Method'], fontsize=11)
    ax.set_ylim([60, 105])
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.legend(loc='lower right', fontsize=11, framealpha=0.9)
    
    plt.tight_layout()
    
    # Save
    output_file = f'results/figure_metrics_{attack_type}.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ {config['name']} figure saved: {output_file}")
    
    # High-res version
    highres_file = f'results/figure_metrics_{attack_type}_highres.png'
    plt.savefig(highres_file, dpi=600, bbox_inches='tight', facecolor='white')
    print(f"✓ High-res version saved: {highres_file}")
    
    plt.close()

# Generate figures for both attack types
print("Generating metrics comparison figures...\n")
generate_figure('ping_flood')
generate_figure('syn_flood')
print("\nAll figures generated successfully!")
