# Visualization Results

This directory contains the final comparison figures for the ReGAIN network traffic analysis paper.

## Available Figures

Located in `final_paper_figures/`:

1. **`side_by_side_GT_comparison.png`** - Ground Truth performance comparison
   - Side-by-side bar chart comparing Ping Flood vs SYN Flood
   - Shows Accuracy, Precision, Recall, and F1-Score
   - Blue bars: Ping Flood | Red bars: SYN Flood

2. **`side_by_side_Expert_comparison.png`** - Expert validation performance comparison
   - Side-by-side bar chart comparing Ping Flood vs SYN Flood
   - Shows Accuracy, Precision, Recall, and F1-Score
   - Blue bars: Ping Flood | Red bars: SYN Flood

3. **`dual_side_by_side_comparison.png`** - Combined GT + Expert comparison
   - Two subplots stacked vertically
   - Top: Ground Truth evaluation
   - Bottom: Expert validation
   - Consistent color scheme throughout

## How to Regenerate

To regenerate these figures:
```bash
python src/generate_side_by_side_comparisons.py
```

## Figure Specifications
- Format: PNG (300 DPI)
- Color scheme: Blue (#3498db) for Ping Flood, Red (#e74c3c) for SYN Flood
- Size: 12x7 inches (single), 12x12 inches (dual)
- Publication-ready quality
