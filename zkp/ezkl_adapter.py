"""
EZKL zkML (Zero-Knowledge Machine Learning) Adapter.

Integrates with EZKL Halo2/KZG proving system to prove neural network
inference and execution traces in zero-knowledge.
"""

import os
import json
import numpy as np
from typing import Tuple, Dict, Any, Optional

try:
    import ezkl
    EZKL_AVAILABLE = True
except ImportError:
    EZKL_AVAILABLE = False


class EZKLProverVerifier:
    """
    EZKL Integration for Verifiable Threat Intelligence.
    Converts ONNX intrusion detection models into arithmetic circuits.
    """
    def __init__(self, work_dir: str = "./ezkl_artifacts"):
        self.work_dir = os.path.abspath(work_dir)
        os.makedirs(self.work_dir, exist_ok=True)
        self.is_available = EZKL_AVAILABLE

    def check_environment(self) -> Dict[str, Any]:
        return {
            "ezkl_installed": self.is_available,
            "work_dir": self.work_dir,
            "version": getattr(ezkl, "__version__", "not installed") if self.is_available else "none"
        }

    def compile_model_circuit(self, onnx_model_path: str) -> Optional[Dict[str, str]]:
        """Compiles ONNX neural network into an EZKL circuit."""
        if not self.is_available:
            return None

        settings_path = os.path.join(self.work_dir, "settings.json")
        compiled_model_path = os.path.join(self.work_dir, "model.ezkl")
        pk_path = os.path.join(self.work_dir, "pk.key")
        vk_path = os.path.join(self.work_dir, "vk.key")

        try:
            # 1. Generate circuit settings
            ezkl.gen_settings(onnx_model_path, settings_path)
            
            # 2. Compile model circuit
            ezkl.compile_circuit(onnx_model_path, compiled_model_path, settings_path)
            
            # 3. Setup proving and verification keys
            ezkl.setup(compiled_model_path, vk_path, pk_path)

            return {
                "settings_path": settings_path,
                "compiled_model_path": compiled_model_path,
                "pk_path": pk_path,
                "vk_path": vk_path
            }
        except Exception as err:
            print(f"[!] EZKL compilation error: {err}")
            return None

    def generate_proof(
        self,
        sample_input: np.ndarray,
        compiled_model_path: str,
        pk_path: str
    ) -> Optional[str]:
        """Generates zk-SNARK proof of honest computation on witness sample."""
        if not self.is_available:
            return None

        input_json_path = os.path.join(self.work_dir, "input.json")
        witness_path = os.path.join(self.work_dir, "witness.json")
        proof_path = os.path.join(self.work_dir, "proof.json")

        try:
            # Export input data as JSON for EZKL witness
            data_payload = {"input_data": [sample_input.flatten().tolist()]}
            with open(input_json_path, 'w') as f:
                json.dump(data_payload, f)

            # Generate witness & proof
            ezkl.gen_witness(input_json_path, compiled_model_path, witness_path)
            ezkl.prove(witness_path, compiled_model_path, pk_path, proof_path, "single")
            return proof_path
        except Exception as err:
            print(f"[!] EZKL prove error: {err}")
            return None

    def verify_proof(self, proof_path: str, settings_path: str, vk_path: str) -> bool:
        """Verifies zk-SNARK proof using verification key."""
        if not self.is_available:
            return False

        try:
            res = ezkl.verify(proof_path, settings_path, vk_path)
            return bool(res)
        except Exception as err:
            print(f"[!] EZKL verification error: {err}")
            return False
