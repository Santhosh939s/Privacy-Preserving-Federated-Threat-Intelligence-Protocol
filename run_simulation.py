"""
End-to-End Simulation Runner for Privacy-Preserving Federated Threat Intelligence.

Executes multi-round federated training across simulated SOCs, tests ZK-Proof
verification against adversarial poisoning, and exports metrics for visualization.
Works seamlessly on both GPU (Colab/Linux) and CPU (local Windows 8GB RAM).
"""

import os
import sys
import json
import time
import numpy as np

from data.nsl_kdd_loader import load_and_partition_nsl_kdd
from federation.soc_node import SOCNode
from federation.aggregator import CentralThreatAggregator
from federation.attacks import PoisoningType

try:
    import torch
    TORCH_AVAILABLE = True
    DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
except ImportError:
    TORCH_AVAILABLE = False
    DEVICE = "cpu (numpy-accelerated)"


def print_banner():
    banner = """
================================================================================
   PRIVACY-PRESERVING FEDERATED THREAT INTELLIGENCE PROTOCOL (PP-FTIP)
   Zero-Knowledge Verifiable Federated Learning for Collaborative Cyber Defense
================================================================================
    """
    print(banner)


def main():
    print_banner()

    print(f"[*] Execution Engine: {DEVICE.upper()} (PyTorch: {'Active' if TORCH_AVAILABLE else 'NumPy-Native Engine'})")
    print("[*] Ingesting NSL-KDD cyber threat telemetry across enterprise SOCs...")

    soc_datasets, (x_test, y_test), input_dim = load_and_partition_nsl_kdd(
        num_socs=3,
        samples_per_soc=1200,
        test_samples=800
    )

    print(f"[+] Ingestion complete: {input_dim} network features. Test set size: {len(x_test)} flows.")

    # 1. Initialize SOC nodes
    soc_nodes = []
    
    # Honest Node 1: Financial SOC
    d1 = soc_datasets["SOC_Financial_FinBank"]
    node1 = SOCNode("SOC-FIN-01", "FinBank Global", d1["x"], d1["y"], PoisoningType.NONE, DEVICE)
    soc_nodes.append(node1)

    # Honest Node 2: Healthcare SOC
    d2 = soc_datasets["SOC_Healthcare_MedNet"]
    node2 = SOCNode("SOC-MED-02", "MedNet Health", d2["x"], d2["y"], PoisoningType.NONE, DEVICE)
    soc_nodes.append(node2)

    # Honest Node 3: Defense SOC
    d3 = soc_datasets["SOC_Defense_AeroCyber"]
    node3 = SOCNode("SOC-DEF-03", "AeroDefense Corp", d3["x"], d3["y"], PoisoningType.NONE, DEVICE)
    soc_nodes.append(node3)

    # Adversarial Node 4: Rogue / Compromised SOC (Attempts Gradient Scaling Poisoning)
    d4_x = np.random.normal(0.5, 0.2, size=(800, input_dim)).astype(np.float32)
    d4_y = np.random.randint(0, 2, size=800).astype(np.int64)
    node4_rogue = SOCNode(
        "SOC-ROGUE-99",
        "Compromised Adversary",
        d4_x,
        d4_y,
        attack_type=PoisoningType.GRADIENT_SCALING,
        device=DEVICE
    )
    soc_nodes.append(node4_rogue)

    print(f"[+] Initialized {len(soc_nodes)} SOC nodes (3 Honest Enterprises, 1 Adversarial Rogue).")

    # 2. Initialize Central Aggregator
    aggregator = CentralThreatAggregator(
        input_dim=input_dim,
        test_x=x_test,
        test_y=y_test,
        device=DEVICE
    )

    initial_eval = aggregator.evaluate_global()
    print(f"\n[+] Global Baseline Model Initial Accuracy: {initial_eval.get('accuracy', 0)*100:.2f}%\n")

    # 3. Multi-round Federated Learning Simulation
    NUM_ROUNDS = 5
    simulation_log = {
        "engine": DEVICE,
        "input_dim": input_dim,
        "test_samples": len(x_test),
        "total_rounds": NUM_ROUNDS,
        "nodes": [
            {"id": n.node_id, "name": n.org_name, "is_malicious": n.is_malicious, "attack": n.attack_type.value}
            for n in soc_nodes
        ],
        "initial_metrics": initial_eval,
        "rounds": []
    }

    for round_idx in range(1, NUM_ROUNDS + 1):
        print(f"\n>>> [ROUND {round_idx}/{NUM_ROUNDS}] Starting Verifiable Federated Learning Cycle <<<")
        global_weights = aggregator.get_global_weights()

        submissions = []
        for node in soc_nodes:
            # 1. Distribute master weights to local SOC
            node.synchronize_weights(global_weights)
            
            # 2. Train local model on private telemetry
            loss = node.train_local_epoch(epochs=3, batch_size=64, lr=0.01)
            
            # 3. Generate weight updates & Zero-Knowledge Proof
            sub = node.generate_submission(round_num=round_idx)
            submissions.append(sub)

            status_tag = "[ROGUE/ATTACK]" if node.is_malicious else "[HONEST SOC]  "
            print(f"  {status_tag} {node.node_id} ({node.org_name:<18}) -> Loss: {loss:.4f} | ZK Status: {sub['proof'].zk_snark_status}")

        # 4. Central Aggregator Verification & FedAvg
        print("  [*] Aggregator running Zero-Knowledge Verification Engine on incoming weights...")
        round_summary = aggregator.process_federation_round(round_num=round_idx, submissions=submissions)

        acc_before = round_summary["metrics_before"].get("accuracy", 0) * 100
        acc_after = round_summary["metrics_after"].get("accuracy", 0) * 100
        prec_after = round_summary["metrics_after"].get("precision", 0) * 100
        rec_after = round_summary["metrics_after"].get("recall", 0) * 100
        far_after = round_summary["metrics_after"].get("false_alarm_rate", 0) * 100

        print(f"  [+] Accepted Updates: {round_summary['accepted_count']}/{round_summary['total_submitted']}")
        print(f"  [!] Quarantined / Rejected: {round_summary['quarantined_count']}")

        for q in round_summary["quarantine_log"]:
            print(f"      -> REJECTED {q['node_id']}: {q['reason']} (Norm: {q['gradient_norm']:.2f} > Max: {q['max_allowed']:.2f})")

        print(f"  [+] Global Model Accuracy: {acc_before:.2f}% -> {acc_after:.2f}% | Recall: {rec_after:.2f}% | FAR: {far_after:.2f}%")

        # Serialized record for dashboard
        cleaned_summary = {
            "round_num": round_summary["round_num"],
            "accepted_count": round_summary["accepted_count"],
            "quarantined_count": round_summary["quarantined_count"],
            "accepted_nodes": round_summary["accepted_nodes"],
            "quarantine_log": round_summary["quarantine_log"],
            "metrics_after": round_summary["metrics_after"],
            "round_duration_sec": round_summary["round_duration_sec"],
            "proof_summaries": [
                {
                    "node_id": s["node_id"],
                    "norm": s["proof"].gradient_norm,
                    "zk_status": s["proof"].zk_snark_status,
                    "sig": s["proof"].proof_signature[:12] + "..."
                }
                for s in submissions
            ]
        }
        simulation_log["rounds"].append(cleaned_summary)

    # 4. Export authentic results
    results_path = os.path.join(os.path.dirname(__file__), "dashboard", "simulation_results.json")
    js_path = os.path.join(os.path.dirname(__file__), "dashboard", "simulation_results.js")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    
    with open(results_path, "w") as f:
        json.dump(simulation_log, f, indent=2)

    with open(js_path, "w") as f:
        f.write("// Authentic simulation results produced by run_simulation.py\n")
        f.write("window.AUTHENTIC_SIMULATION_DATA = " + json.dumps(simulation_log, indent=2) + ";\n")

    print(f"\n[+] Authentic simulation results exported to:\n    - {results_path}\n    - {js_path}")
    final_metrics = aggregator.evaluate_global()
    print("\n" + "="*60)
    print("FINAL GLOBAL MODEL THREAT INTELLIGENCE BENCHMARK:")
    print(f"  - Accuracy:         {final_metrics.get('accuracy', 0)*100:.2f}%")
    print(f"  - Precision:        {final_metrics.get('precision', 0)*100:.2f}%")
    print(f"  - Recall / TPR:     {final_metrics.get('recall', 0)*100:.2f}%")
    print(f"  - False Alarm Rate: {final_metrics.get('false_alarm_rate', 0)*100:.2f}%")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
