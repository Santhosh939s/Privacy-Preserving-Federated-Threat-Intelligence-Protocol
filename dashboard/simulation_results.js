// Authentic simulation results produced by run_simulation.py
window.AUTHENTIC_SIMULATION_DATA = {
  "engine": "cpu (numpy-accelerated)",
  "input_dim": 41,
  "test_samples": 800,
  "total_rounds": 5,
  "nodes": [
    {
      "id": "SOC-FIN-01",
      "name": "FinBank Global",
      "is_malicious": false,
      "attack": "none"
    },
    {
      "id": "SOC-MED-02",
      "name": "MedNet Health",
      "is_malicious": false,
      "attack": "none"
    },
    {
      "id": "SOC-DEF-03",
      "name": "AeroDefense Corp",
      "is_malicious": false,
      "attack": "none"
    },
    {
      "id": "SOC-ROGUE-99",
      "name": "Compromised Adversary",
      "is_malicious": true,
      "attack": "gradient_scaling"
    }
  ],
  "initial_metrics": {
    "accuracy": 0.47875,
    "precision": 0.4698952879581152,
    "recall": 0.967654986522911,
    "f1": 0.6325991189427312,
    "false_alarm_rate": 0.9440559440559441,
    "confusion_matrix": [
      [
        24,
        405
      ],
      [
        12,
        359
      ]
    ]
  },
  "rounds": [
    {
      "round_num": 1,
      "accepted_count": 3,
      "quarantined_count": 1,
      "accepted_nodes": [
        "SOC-FIN-01",
        "SOC-MED-02",
        "SOC-DEF-03"
      ],
      "quarantine_log": [
        {
          "node_id": "SOC-ROGUE-99",
          "org_name": "Compromised Adversary",
          "reason": "Poisoning Detected: Gradient norm 6.127 exceeds threshold 3.500!",
          "gradient_norm": 6.127103328704834,
          "max_allowed": 3.5,
          "proof_status": "VIOLATION_DETECTED",
          "action": "QUARANTINED_AND_REJECTED"
        }
      ],
      "metrics_after": {
        "accuracy": 0.935,
        "precision": 0.9761194029850746,
        "recall": 0.8814016172506739,
        "f1": 0.926345609065156,
        "false_alarm_rate": 0.018648018648018648,
        "confusion_matrix": [
          [
            421,
            8
          ],
          [
            44,
            327
          ]
        ]
      },
      "round_duration_sec": 0.0,
      "proof_summaries": [
        {
          "node_id": "SOC-FIN-01",
          "norm": 0.8942916989326477,
          "zk_status": "PROVEN_VALID",
          "sig": "46108dc749cb..."
        },
        {
          "node_id": "SOC-MED-02",
          "norm": 1.167439579963684,
          "zk_status": "PROVEN_VALID",
          "sig": "2b1fd0bb48c5..."
        },
        {
          "node_id": "SOC-DEF-03",
          "norm": 0.7875375747680664,
          "zk_status": "PROVEN_VALID",
          "sig": "94087b6e4bd1..."
        },
        {
          "node_id": "SOC-ROGUE-99",
          "norm": 6.127103328704834,
          "zk_status": "VIOLATION_DETECTED",
          "sig": "7de69a61dd1d..."
        }
      ]
    },
    {
      "round_num": 2,
      "accepted_count": 3,
      "quarantined_count": 1,
      "accepted_nodes": [
        "SOC-FIN-01",
        "SOC-MED-02",
        "SOC-DEF-03"
      ],
      "quarantine_log": [
        {
          "node_id": "SOC-ROGUE-99",
          "org_name": "Compromised Adversary",
          "reason": "Poisoning Detected: Gradient norm 5.076 exceeds threshold 3.500!",
          "gradient_norm": 5.075753211975098,
          "max_allowed": 3.5,
          "proof_status": "VIOLATION_DETECTED",
          "action": "QUARANTINED_AND_REJECTED"
        }
      ],
      "metrics_after": {
        "accuracy": 0.95,
        "precision": 0.9509536784741145,
        "recall": 0.9407008086253369,
        "f1": 0.94579945799458,
        "false_alarm_rate": 0.04195804195804196,
        "confusion_matrix": [
          [
            411,
            18
          ],
          [
            22,
            349
          ]
        ]
      },
      "round_duration_sec": 0.0009987354278564453,
      "proof_summaries": [
        {
          "node_id": "SOC-FIN-01",
          "norm": 0.45851486921310425,
          "zk_status": "PROVEN_VALID",
          "sig": "992692247be5..."
        },
        {
          "node_id": "SOC-MED-02",
          "norm": 0.6829460263252258,
          "zk_status": "PROVEN_VALID",
          "sig": "f7fdd1873a9b..."
        },
        {
          "node_id": "SOC-DEF-03",
          "norm": 0.6884006261825562,
          "zk_status": "PROVEN_VALID",
          "sig": "a2a20197023a..."
        },
        {
          "node_id": "SOC-ROGUE-99",
          "norm": 5.075753211975098,
          "zk_status": "VIOLATION_DETECTED",
          "sig": "6a464bbffcf7..."
        }
      ]
    },
    {
      "round_num": 3,
      "accepted_count": 3,
      "quarantined_count": 1,
      "accepted_nodes": [
        "SOC-FIN-01",
        "SOC-MED-02",
        "SOC-DEF-03"
      ],
      "quarantine_log": [
        {
          "node_id": "SOC-ROGUE-99",
          "org_name": "Compromised Adversary",
          "reason": "Poisoning Detected: Gradient norm 6.852 exceeds threshold 3.500!",
          "gradient_norm": 6.851891994476318,
          "max_allowed": 3.5,
          "proof_status": "VIOLATION_DETECTED",
          "action": "QUARANTINED_AND_REJECTED"
        }
      ],
      "metrics_after": {
        "accuracy": 0.9525,
        "precision": 0.9463806970509383,
        "recall": 0.9514824797843666,
        "f1": 0.9489247311827957,
        "false_alarm_rate": 0.046620046620046623,
        "confusion_matrix": [
          [
            409,
            20
          ],
          [
            18,
            353
          ]
        ]
      },
      "round_duration_sec": 0.0,
      "proof_summaries": [
        {
          "node_id": "SOC-FIN-01",
          "norm": 0.3644639849662781,
          "zk_status": "PROVEN_VALID",
          "sig": "e974fd8f2df7..."
        },
        {
          "node_id": "SOC-MED-02",
          "norm": 0.471560537815094,
          "zk_status": "PROVEN_VALID",
          "sig": "0de882d5b2e8..."
        },
        {
          "node_id": "SOC-DEF-03",
          "norm": 0.6807808876037598,
          "zk_status": "PROVEN_VALID",
          "sig": "f8a1d7ef8e6f..."
        },
        {
          "node_id": "SOC-ROGUE-99",
          "norm": 6.851891994476318,
          "zk_status": "VIOLATION_DETECTED",
          "sig": "31e868bb99d1..."
        }
      ]
    },
    {
      "round_num": 4,
      "accepted_count": 3,
      "quarantined_count": 1,
      "accepted_nodes": [
        "SOC-FIN-01",
        "SOC-MED-02",
        "SOC-DEF-03"
      ],
      "quarantine_log": [
        {
          "node_id": "SOC-ROGUE-99",
          "org_name": "Compromised Adversary",
          "reason": "Poisoning Detected: Gradient norm 9.441 exceeds threshold 3.500!",
          "gradient_norm": 9.44141674041748,
          "max_allowed": 3.5,
          "proof_status": "VIOLATION_DETECTED",
          "action": "QUARANTINED_AND_REJECTED"
        }
      ],
      "metrics_after": {
        "accuracy": 0.9625,
        "precision": 0.9671232876712329,
        "recall": 0.9514824797843666,
        "f1": 0.9592391304347827,
        "false_alarm_rate": 0.027972027972027972,
        "confusion_matrix": [
          [
            417,
            12
          ],
          [
            18,
            353
          ]
        ]
      },
      "round_duration_sec": 0.0,
      "proof_summaries": [
        {
          "node_id": "SOC-FIN-01",
          "norm": 0.3357381224632263,
          "zk_status": "PROVEN_VALID",
          "sig": "89c18c9d3fd9..."
        },
        {
          "node_id": "SOC-MED-02",
          "norm": 0.372318297624588,
          "zk_status": "PROVEN_VALID",
          "sig": "563e4f057623..."
        },
        {
          "node_id": "SOC-DEF-03",
          "norm": 0.6273846626281738,
          "zk_status": "PROVEN_VALID",
          "sig": "72f571de580a..."
        },
        {
          "node_id": "SOC-ROGUE-99",
          "norm": 9.44141674041748,
          "zk_status": "VIOLATION_DETECTED",
          "sig": "154d133f45bd..."
        }
      ]
    },
    {
      "round_num": 5,
      "accepted_count": 3,
      "quarantined_count": 1,
      "accepted_nodes": [
        "SOC-FIN-01",
        "SOC-MED-02",
        "SOC-DEF-03"
      ],
      "quarantine_log": [
        {
          "node_id": "SOC-ROGUE-99",
          "org_name": "Compromised Adversary",
          "reason": "Poisoning Detected: Gradient norm 11.183 exceeds threshold 3.500!",
          "gradient_norm": 11.182686805725098,
          "max_allowed": 3.5,
          "proof_status": "VIOLATION_DETECTED",
          "action": "QUARANTINED_AND_REJECTED"
        }
      ],
      "metrics_after": {
        "accuracy": 0.96875,
        "precision": 0.9779005524861878,
        "recall": 0.954177897574124,
        "f1": 0.9658935879945428,
        "false_alarm_rate": 0.018648018648018648,
        "confusion_matrix": [
          [
            421,
            8
          ],
          [
            17,
            354
          ]
        ]
      },
      "round_duration_sec": 0.0010042190551757812,
      "proof_summaries": [
        {
          "node_id": "SOC-FIN-01",
          "norm": 0.31398680806159973,
          "zk_status": "PROVEN_VALID",
          "sig": "a21b79516d8f..."
        },
        {
          "node_id": "SOC-MED-02",
          "norm": 0.3529849946498871,
          "zk_status": "PROVEN_VALID",
          "sig": "9f0d8396eb58..."
        },
        {
          "node_id": "SOC-DEF-03",
          "norm": 0.5646771192550659,
          "zk_status": "PROVEN_VALID",
          "sig": "547197acee5b..."
        },
        {
          "node_id": "SOC-ROGUE-99",
          "norm": 11.182686805725098,
          "zk_status": "VIOLATION_DETECTED",
          "sig": "eed4bdbfbe43..."
        }
      ]
    }
  ]
};
