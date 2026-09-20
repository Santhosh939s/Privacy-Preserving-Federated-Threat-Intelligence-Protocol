"""
Model Poisoning & Adversarial Attack Simulation for Federated Learning.

Implements attacks used by malicious participants to compromise collaborative defense:
1. Gradient Scaling (Hijack convergence)
2. Noise Injection (Sabotage model utility)
3. Weight Tampering (Violate cryptographic integrity commitments)
"""

from enum import Enum
import numpy as np


class PoisoningType(Enum):
    NONE = "none"
    GRADIENT_SCALING = "gradient_scaling"
    NOISE_INJECTION = "noise_injection"
    WEIGHT_TAMPERING = "weight_tampering"


def simulate_model_poisoning(
    w_initial: np.ndarray,
    w_updated: np.ndarray,
    attack_type: PoisoningType,
    scale_factor: float = 15.0,
    noise_std: float = 2.0
) -> np.ndarray:
    """Applies adversarial manipulation to client weight updates."""
    if attack_type == PoisoningType.NONE:
        return w_updated.copy()

    delta = w_updated - w_initial

    if attack_type == PoisoningType.GRADIENT_SCALING:
        # Multiplies gradient to skew the decision boundary toward attacker
        poisoned_delta = delta * scale_factor
        return w_initial + poisoned_delta

    elif attack_type == PoisoningType.NOISE_INJECTION:
        # Adds high-variance random noise to destroy global feature representations
        noise = np.random.normal(0.0, noise_std, size=w_updated.shape)
        return w_updated + noise

    elif attack_type == PoisoningType.WEIGHT_TAMPERING:
        # Subtle manipulation after proof commitment
        tampered = w_updated.copy()
        tampered[:10] += 5.0
        return tampered

    return w_updated.copy()
