"""
Central Threat Intelligence Aggregator.

Maintains the global cyber defense AI model, runs cryptographic verification
on ZK proofs from all participating SOCs, quarantines malicious poisoners,
and performs Byzantine-robust Federated Averaging (FedAvg).
"""

import time
import numpy as np
from models.ids_classifier import (
    ThreatDetectionMLP,
    evaluate_model,
    get_flattened_weights,
    set_flattened_weights
)
from data.nsl_kdd_loader import NSLKDDDataset
from zkp.crypto_attestation import CryptographicAttestationEngine, ZKProofPackage

try:
    import torch
    from torch.utils.data import DataLoader
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class CentralThreatAggregator:
    """Central Orchestrator and Verifier for Federated Threat Intelligence."""
    def __init__(
        self,
        input_dim: int = 41,
        test_x: np.ndarray = None,
        test_y: np.ndarray = None,
        device: str = "cpu"
    ):
        self.device = device
        self.input_dim = input_dim
        self.global_model = ThreatDetectionMLP(input_dim=input_dim)
        if hasattr(self.global_model, 'to'):
            self.global_model.to(device)
            
        self.verifier = CryptographicAttestationEngine(max_norm_bound=3.5)

        self.test_data = None
        if test_x is not None and test_y is not None:
            if TORCH_AVAILABLE and not hasattr(self.global_model, 'w1'):
                dataset = NSLKDDDataset(test_x, test_y)
                self.test_data = DataLoader(dataset, batch_size=128, shuffle=False)
            else:
                self.test_data = (test_x, test_y)

        self.round_history = []

    def get_global_weights(self) -> np.ndarray:
        """Returns the current flattened parameters of the global model."""
        return get_flattened_weights(self.global_model)

    def evaluate_global(self) -> dict:
        """Evaluates global model on the hold-out network intrusion test set."""
        if self.test_data is None:
            return {}
        return evaluate_model(self.global_model, self.test_data, device=self.device)

    def process_federation_round(self, round_num: int, submissions: list) -> dict:
        """
        Executes a complete round of Verifiable Federated Learning:
        1. Cryptographic proof verification for each SOC.
        2. Automated quarantine of poisoners / malicious submissions.
        3. FedAvg aggregation of verified honest gradients.
        4. Global model update and telemetry reporting.
        """
        current_weights = self.get_global_weights()
        metrics_before = self.evaluate_global()

        accepted_submissions = []
        quarantine_log = []

        start_time = time.time()
        for sub in submissions:
            node_id = sub["node_id"]
            org_name = sub["org_name"]
            proof: ZKProofPackage = sub["proof"]
            submitted_w = sub["weights"]

            # Cryptographic Zero-Knowledge Verification
            is_valid, reason = self.verifier.verify_proof(
                proof=proof,
                expected_w_initial=current_weights,
                submitted_w_updated=submitted_w
            )

            if is_valid:
                accepted_submissions.append(sub)
            else:
                quarantine_log.append({
                    "node_id": node_id,
                    "org_name": org_name,
                    "reason": reason,
                    "gradient_norm": proof.gradient_norm,
                    "max_allowed": proof.max_norm_bound,
                    "proof_status": proof.zk_snark_status,
                    "action": "QUARANTINED_AND_REJECTED"
                })

        # Federated Averaging (FedAvg) over accepted updates only
        if accepted_submissions:
            total_samples = sum(s["samples_count"] for s in accepted_submissions)
            new_global_weights = np.zeros_like(current_weights)

            for s in accepted_submissions:
                weight_factor = s["samples_count"] / total_samples
                new_global_weights += weight_factor * s["weights"]

            # Update the global neural network
            set_flattened_weights(self.global_model, new_global_weights)
            aggregation_status = "FEDAVG_COMPLETED"
        else:
            new_global_weights = current_weights
            aggregation_status = "NO_VALID_UPDATES"

        metrics_after = self.evaluate_global()
        round_duration = time.time() - start_time

        round_summary = {
            "round_num": round_num,
            "total_submitted": len(submissions),
            "accepted_count": len(accepted_submissions),
            "quarantined_count": len(quarantine_log),
            "accepted_nodes": [s["node_id"] for s in accepted_submissions],
            "quarantine_log": quarantine_log,
            "aggregation_status": aggregation_status,
            "metrics_before": metrics_before,
            "metrics_after": metrics_after,
            "round_duration_sec": round_duration
        }

        self.round_history.append(round_summary)
        return round_summary
