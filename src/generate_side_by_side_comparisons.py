"""
Generate side-by-side bar chart comparisons for both Ground Truth and Expert evaluations
"""

import os
import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

plt.style.use('seaborn-v0_8-paper')
sns.set_palette("husl")


def create_side_by_side_gt_comparison(ping_path, syn_path, output_dir):
    """Side-by-side comparison for Ground Truth results"""
    print("Creating Ground Truth side-by-side comparison...")
    
    with open(ping_path, 'r') as f:
        ping_data = json.load(f)
    with open(syn_path, 'r') as f:
        syn_data = json.load(f)
    
    # Extract GT results
    ping_gt = ping_data['ping_gt']['metrics']
    syn_gt = syn_data['syn_gt']['metrics']
    
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    ping_values = [ping_gt['accuracy']*100, ping_gt['precision']*100, 
                   ping_gt['recall']*100, ping_gt['f1_score']*100]
    syn_values = [syn_gt['accuracy']*100, syn_gt['precision']*100, 
                  syn_gt['recall']*100, syn_gt['f1_score']*100]
    
    x = np.arange(len(metrics))
    width = 0.28  # Thinner bars
    
    fig, ax = plt.subplots(figsize=(9, 5))  # More compact size
    bars1 = ax.bar(x - width/2, ping_values, width, label='Ping Flood', 
                   color='#3498db', edgecolor='black', linewidth=1.2, alpha=0.9)
    bars2 = ax.bar(x + width/2, syn_values, width, label='SYN Flood', 
                   color='#e74c3c', edgecolor='black', linewidth=1.2, alpha=0.9)
    
    # Add value labels on bars
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}%',
                    ha='center', va='bottom', fontsize=8, weight='bold')
    
    ax.set_xlabel('Performance Metrics', fontsize=13, weight='bold', labelpad=8)
    ax.set_ylabel('Percentage (%)', fontsize=13, weight='bold', labelpad=8)
    ax.set_title('Ground Truth Performance Comparison: Ping Flood vs SYN Flood', 
                 fontsize=14, weight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=12)
    ax.legend(fontsize=12, loc='lower right', framealpha=0.95)
    ax.set_ylim([0, 105])
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add horizontal line at 95% for reference
    ax.axhline(y=95, color='gray', linestyle=':', linewidth=1.5, alpha=0.5)
    ax.text(3.7, 96, '95%', fontsize=10, color='gray', style='italic')
    
    plt.tight_layout()
    output_file = os.path.join(output_dir, 'side_by_side_GT_comparison.png')
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {os.path.basename(output_file)}")


def create_side_by_side_expert_comparison(ping_path, syn_path, output_dir):
    """Side-by-side comparison for Expert evaluation results"""
    print("Creating Expert evaluation side-by-side comparison...")
    
    with open(ping_path, 'r') as f:
        ping_data = json.load(f)
    with open(syn_path, 'r') as f:
        syn_data = json.load(f)
    
    # Extract Expert results
    ping_expert = ping_data['ping_expert']['metrics']
    syn_expert = syn_data['syn_expert']['metrics']
    
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    ping_values = [ping_expert['accuracy']*100, ping_expert['precision']*100, 
                   ping_expert['recall']*100, ping_expert['f1_score']*100]
    syn_values = [syn_expert['accuracy']*100, syn_expert['precision']*100, 
                  syn_expert['recall']*100, syn_expert['f1_score']*100]
    
    x = np.arange(len(metrics))
    width = 0.28  # Thinner bars
    
    fig, ax = plt.subplots(figsize=(9, 5))  # More compact size
    bars1 = ax.bar(x - width/2, ping_values, width, label='Ping Flood', 
                   color='#3498db', edgecolor='black', linewidth=1.2, alpha=0.9)
    bars2 = ax.bar(x + width/2, syn_values, width, label='SYN Flood', 
                   color='#e74c3c', edgecolor='black', linewidth=1.2, alpha=0.9)
    
    # Add value labels on bars
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}%',
                    ha='center', va='bottom', fontsize=8, weight='bold')
    
    ax.set_xlabel('Performance Metrics', fontsize=13, weight='bold', labelpad=8)
    ax.set_ylabel('Percentage (%)', fontsize=13, weight='bold', labelpad=8)
    ax.set_title('Expert-Validated Performance Comparison: Ping Flood vs SYN Flood', 
                 fontsize=14, weight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=12)
    ax.legend(fontsize=12, loc='lower right', framealpha=0.95)
    ax.set_ylim([0, 105])
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add horizontal line at 95% for reference
    ax.axhline(y=95, color='gray', linestyle=':', linewidth=1.5, alpha=0.5)
    ax.text(3.7, 96, '95%', fontsize=10, color='gray', style='italic')
    
    plt.tight_layout()
    output_file = os.path.join(output_dir, 'side_by_side_Expert_comparison.png')
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {os.path.basename(output_file)}")


def create_dual_side_by_side_comparison(ping_path, syn_path, output_dir):
    """Create both GT and Expert comparisons in one figure (2x1 grid)"""
    print("Creating dual side-by-side comparison (GT + Expert)...")
    
    with open(ping_path, 'r') as f:
        ping_data = json.load(f)
    with open(syn_path, 'r') as f:
        syn_data = json.load(f)
    
    # Extract results
    ping_gt = ping_data['ping_gt']['metrics']
    syn_gt = syn_data['syn_gt']['metrics']
    ping_expert = ping_data['ping_expert']['metrics']
    syn_expert = syn_data['syn_expert']['metrics']
    
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    
    # Create figure with 2 subplots - more compact
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 8))
    
    x = np.arange(len(metrics))
    width = 0.28  # Thinner bars
    
    # === TOP PLOT: Ground Truth ===
    ping_values_gt = [ping_gt['accuracy']*100, ping_gt['precision']*100, 
                      ping_gt['recall']*100, ping_gt['f1_score']*100]
    syn_values_gt = [syn_gt['accuracy']*100, syn_gt['precision']*100, 
                     syn_gt['recall']*100, syn_gt['f1_score']*100]
    
    bars1 = ax1.bar(x - width/2, ping_values_gt, width, label='Ping Flood', 
                    color='#3498db', edgecolor='black', linewidth=1.2, alpha=0.9)
    bars2 = ax1.bar(x + width/2, syn_values_gt, width, label='SYN Flood', 
                    color='#e74c3c', edgecolor='black', linewidth=1.2, alpha=0.9)
    
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                     f'{height:.1f}%',
                     ha='center', va='bottom', fontsize=8, weight='bold')
    
    ax1.set_ylabel('Percentage (%)', fontsize=13, weight='bold', labelpad=8)
    ax1.set_title('(a) Ground Truth Evaluation', fontsize=14, weight='bold', pad=10)
    ax1.set_xticks(x)
    ax1.set_xticklabels(metrics, fontsize=12)
    ax1.legend(fontsize=12, loc='lower right', framealpha=0.95)
    ax1.set_ylim([0, 105])
    ax1.grid(axis='y', alpha=0.3, linestyle='--')
    ax1.axhline(y=95, color='gray', linestyle=':', linewidth=1.5, alpha=0.5)
    
    # === BOTTOM PLOT: Expert ===
    ping_values_exp = [ping_expert['accuracy']*100, ping_expert['precision']*100, 
                       ping_expert['recall']*100, ping_expert['f1_score']*100]
    syn_values_exp = [syn_expert['accuracy']*100, syn_expert['precision']*100, 
                      syn_expert['recall']*100, syn_expert['f1_score']*100]
    
    bars3 = ax2.bar(x - width/2, ping_values_exp, width, label='Ping Flood', 
                    color='#3498db', edgecolor='black', linewidth=1.2, alpha=0.9)
    bars4 = ax2.bar(x + width/2, syn_values_exp, width, label='SYN Flood', 
                    color='#e74c3c', edgecolor='black', linewidth=1.2, alpha=0.9)
    
    for bars in [bars3, bars4]:
        for bar in bars:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                     f'{height:.1f}%',
                     ha='center', va='bottom', fontsize=8, weight='bold')
    
    ax2.set_xlabel('Performance Metrics', fontsize=13, weight='bold', labelpad=8)
    ax2.set_ylabel('Percentage (%)', fontsize=13, weight='bold', labelpad=8)
    ax2.set_title('(b) Expert-Validated Evaluation', fontsize=14, weight='bold', pad=10)
    ax2.set_xticks(x)
    ax2.set_xticklabels(metrics, fontsize=12)
    ax2.legend(fontsize=12, loc='lower right', framealpha=0.95)
    ax2.set_ylim([0, 105])
    ax2.grid(axis='y', alpha=0.3, linestyle='--')
    ax2.axhline(y=95, color='gray', linestyle=':', linewidth=1.5, alpha=0.5)
    
    plt.suptitle('Performance Comparison: Ping Flood vs SYN Flood', 
                 fontsize=15, weight='bold', y=0.995)
    plt.tight_layout()
    
    output_file = os.path.join(output_dir, 'dual_side_by_side_comparison.png')
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"  ✓ Saved: {os.path.basename(output_file)}")


def main():
    print("="*80)
    print("SIDE-BY-SIDE COMPARISON GENERATOR")
    print("Creating GT and Expert comparison bar charts")
    print("="*80)
    
    base_dir = r'c:\GitHub\llm-traffic'
    output_dir = os.path.join(base_dir, 'results', 'heatmaps', 'final_paper_figures')
    os.makedirs(output_dir, exist_ok=True)
    
    ping_results = os.path.join(base_dir, 'results', 'ping_flood', 'all_results.json')
    syn_results = os.path.join(base_dir, 'results', 'syn_flood', 'all_results.json')
    
    print(f"\n✓ Output directory: {output_dir}\n")
    
    # Generate all three versions
    create_side_by_side_gt_comparison(ping_results, syn_results, output_dir)
    create_side_by_side_expert_comparison(ping_results, syn_results, output_dir)
    create_dual_side_by_side_comparison(ping_results, syn_results, output_dir)
    
    print("\n" + "="*80)
    print("✅ GENERATION COMPLETE")
    print("="*80)
    print(f"\nGenerated 3 side-by-side comparison figures:")
    print("  1. side_by_side_GT_comparison.png       - Ground Truth only")
    print("  2. side_by_side_Expert_comparison.png   - Expert validation only")
    print("  3. dual_side_by_side_comparison.png     - Both GT & Expert (stacked)")
    print("\n" + "="*80)


if __name__ == '__main__':
    main()
