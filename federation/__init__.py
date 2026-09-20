"""
Federation package for Privacy-Preserving Threat Intelligence.
"""
from .soc_node import SOCNode
from .aggregator import CentralThreatAggregator
from .attacks import PoisoningType, simulate_model_poisoning

__all__ = [
    "SOCNode",
    "CentralThreatAggregator",
    "PoisoningType",
    "simulate_model_poisoning"
]
