"""
Convenience script to run all baseline comparisons for paper results.
Automates running all baseline methods on all evaluation scenarios.
"""

import os
import sys
import subprocess
from datetime import datetime


def run_comparison(attack_type, log_folder, labels_path, label_type, output_dir, rag_folder=None):
    """Run a single baseline comparison."""
    cmd = [
        sys.executable,
        'src/baselines/run_comparison.py',
        '--attack-type', attack_type,
        '--log-folder', log_folder,
        '--labels', labels_path,
        '--label-type', label_type,
        '--output-dir', output_dir
    ]
    
    if rag_folder:
        cmd.extend(['--rag-folder', rag_folder])
    
    print("\n" + "="*80)
    print(f"Running: {' '.join(cmd)}")
    print("="*80)
    
    subprocess.run(cmd, check=True)


def main():
    """Run all baseline comparisons for the paper."""
    
    print("\n" + "="*80)
    print("COMPREHENSIVE BASELINE COMPARISON FOR PAPER")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80 + "\n")
    
    # Create main results directory
    base_output_dir = './results/baseline_comparison_paper'
    os.makedirs(base_output_dir, exist_ok=True)
    
    # Scenario 1: Ping Flood - Ground Truth Labels
    print("\n>>> SCENARIO 1: Ping Flood Detection (Ground Truth Labels)")
    run_comparison(
        attack_type='ping_flood',
        log_folder='./data/processed/c101split/test1',
        labels_path='./data/processed/c101split/test1/ping_flood_labels.json',
        label_type='json',
        output_dir=os.path.join(base_output_dir, 'ping_flood_gt'),
        rag_folder='./data/processed/rag_outputs_c101split1'
    )
    
    # Scenario 2: Ping Flood - Expert Labels
    print("\n>>> SCENARIO 2: Ping Flood Detection (Expert Labels)")
    run_comparison(
        attack_type='ping_flood',
        log_folder='./data/processed/c101split/test1',
        labels_path='./data/ground_truth/c101_manual_gt_labels.txt',
        label_type='txt',
        output_dir=os.path.join(base_output_dir, 'ping_flood_expert'),
        rag_folder='./data/processed/rag_outputs_c101split1'
    )
    
    # Scenario 3: SYN Flood - Ground Truth Labels (if available)
    syn_gt_labels = './data/processed/syn_flood/syn_flood_labels.json'
    if os.path.exists(syn_gt_labels):
        print("\n>>> SCENARIO 3: SYN Flood Detection (Ground Truth Labels)")
        run_comparison(
            attack_type='syn_flood',
            log_folder='./data/processed/syn_flood',
            labels_path=syn_gt_labels,
            label_type='json',
            output_dir=os.path.join(base_output_dir, 'syn_flood_gt'),
            rag_folder='./data/processed/rag_outputs_syn'
        )
    
    # Scenario 4: SYN Flood - Expert Labels
    syn_expert_labels = './data/ground_truth/syn_flood/expert_labels.txt'
    if os.path.exists(syn_expert_labels):
        print("\n>>> SCENARIO 4: SYN Flood Detection (Expert Labels)")
        run_comparison(
            attack_type='syn_flood',
            log_folder='./data/processed/syn_flood',
            labels_path=syn_expert_labels,
            label_type='txt',
            output_dir=os.path.join(base_output_dir, 'syn_flood_expert'),
            rag_folder='./data/processed/rag_outputs_syn'
        )
    
    print("\n" + "="*80)
    print("ALL BASELINE COMPARISONS COMPLETE!")
    print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Results saved to: {base_output_dir}")
    print("="*80 + "\n")
    
    # Print summary of generated files
    print("\nGenerated Files:")
    print("-" * 80)
    for scenario in os.listdir(base_output_dir):
        scenario_path = os.path.join(base_output_dir, scenario)
        if os.path.isdir(scenario_path):
            print(f"\n{scenario}/")
            summary_file = os.path.join(scenario_path, 'comparison_summary.txt')
            if os.path.exists(summary_file):
                print(f"  ✓ comparison_summary.txt")
                print(f"  ✓ comparison_summary.csv")
                print(f"  ✓ metrics_comparison.png")
                print(f"  ✓ confusion_matrices_comparison.png")
                print(f"  ✓ detailed_results.json")
    
    print("\n" + "="*80)
    print("\nNEXT STEPS:")
    print("1. Review comparison_summary.txt files for each scenario")
    print("2. Include metrics_comparison.png figures in paper")
    print("3. Reference baseline performance in results section")
    print("4. Highlight RAG+LLM's explainability advantage in discussion")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
