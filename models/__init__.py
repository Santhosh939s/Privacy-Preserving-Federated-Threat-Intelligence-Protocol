"""
Models module for Privacy-Preserving Federated Threat Intelligence Protocol.
"""
from .ids_classifier import (
    ThreatDetectionMLP,
    train_local_model,
    evaluate_model,
    export_to_onnx,
    get_flattened_weights,
    set_flattened_weights
)

__all__ = [
    "ThreatDetectionMLP",
    "train_local_model",
    "evaluate_model",
    "export_to_onnx",
    "get_flattened_weights",
    "set_flattened_weights"
]
