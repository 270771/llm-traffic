"""
Figure: Horizontal Bar Chart - Accuracy Comparison
Generates separate versions for Ping Flood and SYN Flood attacks
"""

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Set style
plt.rcParams['font.size'] = 11
plt.rcParams['axes.labelsize'] = 13
plt.rcParams['axes.titlesize'] = 15

# Attack type configurations
attack_configs = {
    'ping_flood': {
        'name': 'Ping Flood',
        'accuracy': 97.74
    },
    'syn_flood': {
        'name': 'SYN Flood',
        'accuracy': 98.82
    }
}

# Baseline data
baseline_data = {
    'Method': ['Rule-Based\nIDS', 'SVM', 'Random\nForest', 'CNN', 'LSTM'],
    'Accuracy': [88.5, 92.3, 93.8, 94.2, 95.1]
}

def generate_figure(attack_type):
    config = attack_configs[attack_type]
    
    # Data with ReGAIN appended
    data = {
        'Method': baseline_data['Method'] + ['ReGAIN'],
        'Accuracy': baseline_data['Accuracy'] + [config['accuracy']]
    }
    
    df = pd.DataFrame(data)

    # Create figure
    fig, ax = plt.subplots(figsize=(12, 8))
    fig.patch.set_facecolor('white')

    # Reverse order so RAG is at top
    methods_rev = df['Method'].tolist()[::-1]
    accuracy_rev = df['Accuracy'].tolist()[::-1]

    # Define colors - matching exact user figure
    # Each method gets its own distinct color
    colors_horizontal = [
        '#FF8A65',  # RAG - coral/salmon
        '#4DD0E1',  # LSTM - cyan
        '#4DD0E1',  # CNN - cyan
        '#4DD0E1',  # Random Forest - cyan
        '#FFB74D',  # SVM - orange
        '#FFB74D'   # Rule-Based - orange
    ]

    bars = ax.barh(methods_rev, accuracy_rev, color=colors_horizontal,
                  edgecolor='black', linewidth=1.0, alpha=0.9, height=0.65)

    # Make RAG bar (top) extra special
    bars[0].set_edgecolor('#D84315')
    bars[0].set_linewidth(2)

    # Add value labels
    for i, (bar, val, method) in enumerate(zip(bars, accuracy_rev, methods_rev)):
        width = bar.get_width()
        ax.text(width + 0.3, bar.get_y() + bar.get_height()/2,
               f'{val:.2f}%' if i == 0 else f'{val:.1f}%', 
               ha='left', va='center', 
               fontweight='bold' if i == 0 else 'normal',
               fontsize=12, color='black')

        ax.set_xlabel('Accuracy (%)', fontweight='bold', fontsize=14)
    ax.set_xlim([86, 100])
    ax.grid(axis='x', alpha=0.3, linestyle='--')

    # Add reference lines
    ax.axvline(x=95, color='gray', linestyle=':', linewidth=1.5, alpha=0.6)
    ax.axvline(x=90, color='gray', linestyle=':', linewidth=1.5, alpha=0.4)

    plt.tight_layout()

    # Save
    output_file = f'results/figure_accuracy_{attack_type}.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ {config['name']} figure saved: {output_file}")

    # High-res version
    highres_file = f'results/figure_accuracy_{attack_type}_highres.png'
    plt.savefig(highres_file, dpi=600, bbox_inches='tight', facecolor='white')
    print(f"✓ High-res version saved: {highres_file}")

    plt.close()

# Generate figures for both attack types
print("Generating accuracy comparison figures...\n")
generate_figure('ping_flood')
generate_figure('syn_flood')
print("\nAll figures generated successfully!")
