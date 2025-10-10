"""
Batch processor for SYN flood RAG analysis
Splits large datasets into manageable chunks to avoid interruptions and API rate limits
"""

import os
import subprocess
import sys
import time
from pathlib import Path

# Configuration
BATCH_SIZE = 500  # Process 500 files per batch
DELAY_BETWEEN_BATCHES = 30  # seconds between batches to avoid rate limits

DATASETS = [
    {
        "name": "Known Training Set",
        "input_folder": "./data/processed/syn_flood/known_train/logs",
        "output_folder": "./data/processed/syn_flood/rag_outputs_known",
        "total_files": 4740
    },
    {
        "name": "Unknown Test Set",
        "input_folder": "./data/processed/syn_flood/unknown_test/logs",
        "output_folder": "./data/processed/syn_flood/rag_outputs_unknown",
        "total_files": 5069
    }
]


def get_log_files(folder):
    """Get all .log files in folder, sorted by name."""
    return sorted([f for f in os.listdir(folder) if f.endswith('.log')])


def get_completed_files(folder):
    """Get all .txt files (already processed) in output folder."""
    if not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)
        return set()
    return set([f.replace('.txt', '.log') for f in os.listdir(folder) if f.endswith('.txt')])


def create_batch_folder(base_folder, batch_num):
    """Create temporary folder for batch processing."""
    batch_folder = os.path.join(base_folder, f"_batch_{batch_num}")
    os.makedirs(batch_folder, exist_ok=True)
    return batch_folder


def run_rag_on_batch(input_folder, output_folder, batch_files):
    """Run RAG analysis on a batch of files."""
    # Create temporary batch folder with symlinks/copies
    temp_batch_folder = create_batch_folder(os.path.dirname(input_folder), "temp")
    
    # Copy/link batch files to temp folder
    for filename in batch_files:
        src = os.path.join(input_folder, filename)
        dst = os.path.join(temp_batch_folder, filename)
        # On Windows, use copy instead of symlink
        import shutil
        shutil.copy2(src, dst)
    
    print(f"  Created temporary batch folder with {len(batch_files)} files")
    
    # Run RAG query script
    cmd = [
        sys.executable,
        "rag_query_syn.py",
        temp_batch_folder,
        output_folder
    ]
    
    print(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False, text=True)
    
    # Clean up temp folder
    import shutil
    shutil.rmtree(temp_batch_folder)
    
    return result.returncode == 0


def process_dataset(dataset):
    """Process a complete dataset in batches."""
    print(f"\n{'='*70}")
    print(f"📊 Processing: {dataset['name']}")
    print(f"{'='*70}")
    
    input_folder = dataset['input_folder']
    output_folder = dataset['output_folder']
    
    # Get all log files and completed files
    all_files = get_log_files(input_folder)
    completed_files = get_completed_files(output_folder)
    
    # Filter out already completed files
    remaining_files = [f for f in all_files if f not in completed_files]
    
    print(f"Total files: {len(all_files)}")
    print(f"Already completed: {len(completed_files)}")
    print(f"Remaining: {len(remaining_files)}")
    
    if not remaining_files:
        print("✅ All files already processed!")
        return True
    
    # Split into batches
    num_batches = (len(remaining_files) + BATCH_SIZE - 1) // BATCH_SIZE
    print(f"\n📦 Processing in {num_batches} batches of {BATCH_SIZE} files each")
    
    for i in range(num_batches):
        batch_num = i + 1
        start_idx = i * BATCH_SIZE
        end_idx = min((i + 1) * BATCH_SIZE, len(remaining_files))
        batch_files = remaining_files[start_idx:end_idx]
        
        print(f"\n{'─'*70}")
        print(f"🔄 Batch {batch_num}/{num_batches}: Processing files {start_idx+1}-{end_idx} of {len(remaining_files)}")
        print(f"{'─'*70}")
        
        success = run_rag_on_batch(input_folder, output_folder, batch_files)
        
        if not success:
            print(f"⚠️  Batch {batch_num} encountered errors. Check logs.")
            response = input("Continue with next batch? (y/n): ")
            if response.lower() != 'y':
                return False
        else:
            print(f"✅ Batch {batch_num} completed successfully!")
        
        # Delay between batches (except for last batch)
        if batch_num < num_batches:
            print(f"⏸️  Waiting {DELAY_BETWEEN_BATCHES} seconds before next batch...")
            time.sleep(DELAY_BETWEEN_BATCHES)
    
    print(f"\n✅ {dataset['name']} - All batches completed!")
    return True


def main():
    print("="*70)
    print("  🚀 SYN FLOOD RAG BATCH PROCESSOR")
    print("="*70)
    print(f"Batch size: {BATCH_SIZE} files")
    print(f"Delay between batches: {DELAY_BETWEEN_BATCHES} seconds")
    
    for dataset in DATASETS:
        success = process_dataset(dataset)
        if not success:
            print(f"\n⚠️  Stopped processing {dataset['name']}")
            break
    
    print("\n" + "="*70)
    print("  🎉 BATCH PROCESSING COMPLETE")
    print("="*70)


if __name__ == "__main__":
    main()
