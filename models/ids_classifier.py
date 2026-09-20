"""
Intrusion Detection System (IDS) Neural Network Classifier.

Supports both PyTorch and pure-NumPy execution for cross-platform compatibility:
- Compact architecture to minimize zk-SNARK arithmetic circuit constraints.
- High accuracy on multi-vector network intrusion detection.
- Fast training and evaluation on CPU or GPU.
"""

import os
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


# ==============================================================================
# Pure NumPy Implementation (Runs everywhere without needing 2GB torch install)
# ==============================================================================

class ThreatDetectionMLPNumPy:
    """NumPy-native 3-layer Neural Network with momentum optimizer."""
    def __init__(self, input_dim: int = 41, hidden_dim1: int = 32, hidden_dim2: int = 16, num_classes: int = 2):
        np.random.seed(42)
        # He initialization
        self.w1 = np.random.randn(input_dim, hidden_dim1).astype(np.float32) * np.sqrt(2.0 / input_dim)
        self.b1 = np.zeros(hidden_dim1, dtype=np.float32)
        self.w2 = np.random.randn(hidden_dim1, hidden_dim2).astype(np.float32) * np.sqrt(2.0 / hidden_dim1)
        self.b2 = np.zeros(hidden_dim2, dtype=np.float32)
        self.w3 = np.random.randn(hidden_dim2, num_classes).astype(np.float32) * np.sqrt(2.0 / hidden_dim2)
        self.b3 = np.zeros(num_classes, dtype=np.float32)

        # Momentum velocity buffers
        self.vw1 = np.zeros_like(self.w1)
        self.vb1 = np.zeros_like(self.b1)
        self.vw2 = np.zeros_like(self.w2)
        self.vb2 = np.zeros_like(self.b2)
        self.vw3 = np.zeros_like(self.w3)
        self.vb3 = np.zeros_like(self.b3)

    def forward(self, x: np.ndarray):
        self.z1 = np.dot(x, self.w1) + self.b1
        self.a1 = np.maximum(0.0, self.z1)  # ReLU
        self.z2 = np.dot(self.a1, self.w2) + self.b2
        self.a2 = np.maximum(0.0, self.z2)  # ReLU
        self.z3 = np.dot(self.a2, self.w3) + self.b3
        # Numerically stable Softmax
        exp_z = np.exp(self.z3 - np.max(self.z3, axis=1, keepdims=True))
        self.probs = exp_z / np.sum(exp_z, axis=1, keepdims=True)
        return self.probs

    def backward(self, x: np.ndarray, y: np.ndarray, lr: float = 0.05, momentum: float = 0.85):
        m = len(x)
        y_onehot = np.zeros_like(self.probs)
        y_onehot[np.arange(m), y] = 1.0

        dz3 = (self.probs - y_onehot) / m
        dw3 = np.dot(self.a2.T, dz3)
        db3 = np.sum(dz3, axis=0)

        da2 = np.dot(dz3, self.w3.T)
        dz2 = da2 * (self.z2 > 0)
        dw2 = np.dot(self.a1.T, dz2)
        db2 = np.sum(dz2, axis=0)

        da1 = np.dot(dz2, self.w2.T)
        dz1 = da1 * (self.z1 > 0)
        dw1 = np.dot(x.T, dz1)
        db1 = np.sum(dz1, axis=0)

        # SGD with Momentum
        self.vw1 = momentum * self.vw1 - lr * dw1
        self.vb1 = momentum * self.vb1 - lr * db1
        self.vw2 = momentum * self.vw2 - lr * dw2
        self.vb2 = momentum * self.vb2 - lr * db2
        self.vw3 = momentum * self.vw3 - lr * dw3
        self.vb3 = momentum * self.vb3 - lr * db3

        self.w1 += self.vw1
        self.b1 += self.vb1
        self.w2 += self.vw2
        self.b2 += self.vb2
        self.w3 += self.vw3
        self.b3 += self.vb3

        loss = -np.mean(np.log(np.clip(self.probs[np.arange(m), y], 1e-10, 1.0)))
        return float(loss)


# ==============================================================================
# PyTorch Implementation (For Google Colab / GPU environments)
# ==============================================================================

if TORCH_AVAILABLE:
    class ThreatDetectionMLPTorch(nn.Module):
        def __init__(self, input_dim: int = 41, hidden1: int = 32, hidden2: int = 16, num_classes: int = 2):
            super().__init__()
            self.fc1 = nn.Linear(input_dim, hidden1)
            self.relu1 = nn.ReLU()
            self.fc2 = nn.Linear(hidden1, hidden2)
            self.relu2 = nn.ReLU()
            self.fc3 = nn.Linear(hidden2, num_classes)

        def forward(self, x):
            return self.fc3(self.relu2(self.fc2(self.relu1(self.fc1(x)))))


def ThreatDetectionMLP(input_dim: int = 41, **kwargs):
    """Factory function returning PyTorch or NumPy model depending on environment."""
    if TORCH_AVAILABLE:
        return ThreatDetectionMLPTorch(input_dim=input_dim, **kwargs)
    return ThreatDetectionMLPNumPy(input_dim=input_dim, **kwargs)


# ==============================================================================
# Unified Training, Evaluation, and Weight Serialization
# ==============================================================================

def train_local_model(model, data_tuple_or_loader, epochs: int = 3, lr: float = 0.05, device: str = "cpu") -> float:
    """Trains model on local SOC data using mini-batch gradient descent."""
    if isinstance(model, ThreatDetectionMLPNumPy):
        if hasattr(data_tuple_or_loader, 'dataset'):
            x, y = data_tuple_or_loader.dataset.x, data_tuple_or_loader.dataset.y
        elif isinstance(data_tuple_or_loader, tuple):
            x, y = data_tuple_or_loader
        else:
            x, y = data_tuple_or_loader.x, data_tuple_or_loader.y

        total_loss = 0.0
        batch_size = 64
        n_samples = len(x)
        num_batches = max(1, n_samples // batch_size)

        for _ in range(epochs):
            perm = np.random.permutation(n_samples)
            x_shuf, y_shuf = x[perm], y[perm]
            epoch_loss = 0.0
            for b in range(num_batches):
                start = b * batch_size
                end = min(n_samples, start + batch_size)
                bx, by = x_shuf[start:end], y_shuf[start:end]
                model.forward(bx)
                l = model.backward(bx, by, lr=lr)
                epoch_loss += l
            total_loss += (epoch_loss / num_batches)
        return total_loss / epochs

    # PyTorch branch
    model.to(device)
    model.train()
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)
    total_loss, total_steps = 0.0, 0

    loader = data_tuple_or_loader
    for _ in range(epochs):
        for inputs, targets in loader:
            inputs, targets = inputs.to(device), targets.to(device)
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            total_steps += 1
    return total_loss / max(1, total_steps)


def evaluate_model(model, data_tuple_or_loader, device: str = "cpu") -> dict:
    """Calculates Accuracy, Precision, Recall, F1, and False Alarm Rate."""
    if isinstance(model, ThreatDetectionMLPNumPy):
        if hasattr(data_tuple_or_loader, 'dataset'):
            x, y = data_tuple_or_loader.dataset.x, data_tuple_or_loader.dataset.y
        elif isinstance(data_tuple_or_loader, tuple):
            x, y = data_tuple_or_loader
        else:
            x, y = data_tuple_or_loader.x, data_tuple_or_loader.y

        probs = model.forward(x)
        preds = np.argmax(probs, axis=1)
        targets = y
    else:
        model.to(device)
        model.eval()
        preds, targets = [], []
        with torch.no_grad():
            for bx, by in data_tuple_or_loader:
                bx = bx.to(device)
                p = torch.argmax(model(bx), dim=1).cpu().numpy()
                preds.extend(p)
                targets.extend(by.numpy())
        preds, targets = np.array(preds), np.array(targets)

    # Compute metrics with pure numpy
    tp = int(np.sum((preds == 1) & (targets == 1)))
    tn = int(np.sum((preds == 0) & (targets == 0)))
    fp = int(np.sum((preds == 1) & (targets == 0)))
    fn = int(np.sum((preds == 0) & (targets == 1)))
    total = max(1, len(targets))

    acc = (tp + tn) / total
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * (prec * rec) / max(1e-9, (prec + rec))
    far = fp / max(1, fp + tn)

    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "false_alarm_rate": float(far),
        "confusion_matrix": [[tn, fp], [fn, tp]]
    }


def get_flattened_weights(model) -> np.ndarray:
    """Serializes all model weights into a 1D vector."""
    if isinstance(model, ThreatDetectionMLPNumPy):
        return np.concatenate([
            model.w1.flatten(), model.b1.flatten(),
            model.w2.flatten(), model.b2.flatten(),
            model.w3.flatten(), model.b3.flatten()
        ])
    return np.concatenate([p.detach().cpu().numpy().flatten() for p in model.parameters()])


def set_flattened_weights(model, flat_weights: np.ndarray):
    """Loads weights from 1D vector into model."""
    if isinstance(model, ThreatDetectionMLPNumPy):
        offset = 0
        for attr in ['w1', 'b1', 'w2', 'b2', 'w3', 'b3']:
            param = getattr(model, attr)
            numel = param.size
            setattr(model, attr, flat_weights[offset:offset + numel].reshape(param.shape).copy())
            offset += numel
        return

    offset = 0
    with torch.no_grad():
        for param in model.parameters():
            numel = param.numel()
            slice_w = flat_weights[offset:offset + numel].reshape(param.shape)
            param.copy_(torch.from_numpy(slice_w))
            offset += numel


def export_to_onnx(model, save_path: str, input_dim: int = 41) -> str:
    """Exports to ONNX format for zkML (EZKL) arithmetic circuit compiling."""
    os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
    if TORCH_AVAILABLE and isinstance(model, nn.Module):
        dummy_input = torch.randn(1, input_dim, requires_grad=False)
        torch.onnx.export(
            model,
            dummy_input,
            save_path,
            export_params=True,
            opset_version=14,
            do_constant_folding=True,
            input_names=['input'],
            output_names=['output']
        )
    else:
        # Save weights representation
        weights = get_flattened_weights(model)
        np.save(save_path.replace(".onnx", ".npy"), weights)
    return save_path
