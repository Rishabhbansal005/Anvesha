"""
ANVESH ML Inference Module.
Provides standalone, lightweight prediction interfaces for Model 1.
"""

from .predictor import PhishingPredictor, get_phishing_predictor

__all__ = ["PhishingPredictor", "get_phishing_predictor"]
