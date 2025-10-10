"""
Baseline methods for network attack detection comparison.

This package provides baseline implementations to compare against the RAG+LLM approach:
- Rule-based detection (Snort/Suricata-style)
- Traditional ML (SVM, Random Forest)
- Deep Learning (CNN, LSTM)
"""

from .rule_based import RuleBasedDetector
from .traditional_ml import TraditionalMLBaseline
from .deep_learning import DeepLearningBaseline
from .feature_extraction import ZeekFeatureExtractor

__all__ = [
    'RuleBasedDetector',
    'TraditionalMLBaseline',
    'DeepLearningBaseline',
    'ZeekFeatureExtractor'
]

__version__ = '1.0.0'
