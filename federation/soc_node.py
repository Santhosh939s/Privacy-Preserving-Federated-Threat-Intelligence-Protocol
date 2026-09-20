"""
SOC Node (Federated Client) implementation.

Represents an individual enterprise Security Operations Center (e.g., Financial,
Healthcare, Defense) that trains on proprietary telemetry and generates Zero-Knowledge proofs.
"""

import numpy as np
from models.ids_classifier import (
    ThreatDetectionMLP,
    train_local_model,
    evaluate_model,
    get_flattened_weights,
    set_flattened_weights
)
from data.nsl_kdd_loader import NSLKDDDataset
from zkp.crypto_attestation import CryptographicAttestationEngine, ZKProofPackage
from federation.attacks import PoisoningType, simulate_model_poisoning

try:
    import torch
    from torch.utils.data import DataLoader
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class SOCNode:
    """Enterprise SOC participant in the federated network."""
    def __init__(
        self,
        node_id: str,
        org_name: str,
        x_telemetry: np.ndarray,
        y_labels: np.ndarray,
        attack_type: PoisoningType = PoisoningType.NONE,
        device: str = "cpu"
    ):
        self.node_id = node_id
        self.org_name = org_name
        self.x_telemetry = x_telemetry
        self.y_labels = y_labels
        self.attack_type = attack_type
        self.is_malicious = (attack_type != PoisoningType.NONE)
        self.device = device

        self.dataset = NSLKDDDataset(x_telemetry, y_labels)
        self.model = ThreatDetectionMLP(input_dim=x_telemetry.shape[1])
        self.zkp_engine = CryptographicAttestationEngine(max_norm_bound=3.5)
        
        self.initial_round_weights = None
        self.last_loss = 0.0

    def synchronize_weights(self, global_weights: np.ndarray):
        """Receives and loads the master model parameters from the aggregator."""
        set_flattened_weights(self.model, global_weights)
        self.initial_round_weights = global_weights.copy()

    def train_local_epoch(self, epochs: int = 3, batch_size: int = 64, lr: float = 0.005) -> float:
        """Trains the local IDS model on private network traffic."""
        if TORCH_AVAILABLE and not hasattr(self.model, 'w1'):
            dataloader = DataLoader(self.dataset, batch_size=batch_size, shuffle=True)
            data_source = dataloader
        else:
            data_source = (self.x_telemetry, self.y_labels)

        self.last_loss = train_local_model(
            self.model,
            data_tuple_or_loader=data_source,
            epochs=epochs,
            lr=lr,
            device=self.device
        )
        return self.last_loss

    def generate_submission(self, round_num: int) -> dict:
        """
        Extracts updated model parameters, generates Zero-Knowledge Proof,
        and packages the submission for the central aggregator.
        """
        w_updated_honest = get_flattened_weights(self.model)

        # Apply adversarial poisoning if node is rogue
        if self.is_malicious:
            w_submitted = simulate_model_poisoning(
                w_initial=self.initial_round_weights,
                w_updated=w_updated_honest,
                attack_type=self.attack_type
            )
        else:
            w_submitted = w_updated_honest

        # Generate cryptographic attestation & ZK proof
        proof, is_valid = self.zkp_engine.generate_proof(
            soc_id=self.node_id,
            round_num=round_num,
            w_initial=self.initial_round_weights,
            w_updated=w_submitted,
            telemetry_data=self.x_telemetry,
            loss=self.last_loss,
            simulate_poison=self.is_malicious
        )

        return {
            "node_id": self.node_id,
            "org_name": self.org_name,
            "round_num": round_num,
            "weights": w_submitted,
            "proof": proof,
            "samples_count": len(self.x_telemetry),
            "loss": self.last_loss,
            "is_malicious": self.is_malicious,
            "attack_type": self.attack_type.value
        }

    def evaluate_local(self) -> dict:
        """Evaluates local intrusion detection efficacy."""
        if TORCH_AVAILABLE and not hasattr(self.model, 'w1'):
            data_source = DataLoader(self.dataset, batch_size=64, shuffle=False)
        else:
            data_source = (self.x_telemetry, self.y_labels)
        return evaluate_model(self.model, data_source, device=self.device)
