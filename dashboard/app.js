/**
 * PP-FTIP Dashboard Application Logic
 * Interactive telemetry, live round stepping, ZKP inspector, and convergence charts.
 */

// Authentic simulation data produced directly by the training engine
let simulationData = window.AUTHENTIC_SIMULATION_DATA || null;
let currentRoundIndex = simulationData ? simulationData.rounds.length - 1 : 0;
let autoPlayInterval = null;

// Initialize on page load
window.addEventListener("DOMContentLoaded", async () => {
  if (!simulationData) {
    await loadLiveSimulationResults();
  }
  if (simulationData && simulationData.rounds.length > 0) {
    currentRoundIndex = simulationData.rounds.length - 1;
    renderCurrentRound();
    drawConvergenceChart();
    addTerminalLog("success", `Loaded authentic model results from real NSL-KDD dataset (${simulationData.rounds.length} rounds).`);
  } else {
    addTerminalLog("warn", "Awaiting execution: Run 'python run_simulation.py' to generate authentic results.");
  }
});

async function loadLiveSimulationResults() {
  try {
    const res = await fetch("simulation_results.json");
    if (res.ok) {
      const data = await res.json();
      if (data.rounds && data.rounds.length > 0) {
        simulationData = data;
        currentRoundIndex = data.rounds.length - 1;
        renderCurrentRound();
        drawConvergenceChart();
      }
    }
  } catch (err) {
    console.log("Using window.AUTHENTIC_SIMULATION_DATA");
  }
}

function renderCurrentRound() {
  const round = simulationData.rounds[currentRoundIndex];
  if (!round) return;

  // Header display
  document.getElementById("current-round-display").innerText = `Round ${round.round_num} / ${simulationData.rounds.length}`;

  // Stat Cards
  const m = round.metrics_after;
  document.getElementById("metric-accuracy").innerText = `${(m.accuracy * 100).toFixed(1)}%`;
  document.getElementById("metric-recall").innerText = `${(m.recall * 100).toFixed(1)}%`;
  document.getElementById("metric-far").innerText = `${(m.false_alarm_rate * 100).toFixed(1)}%`;
  document.getElementById("metric-quarantine-count").innerText = `${round.quarantined_count} / ${round.quarantined_count + round.accepted_count}`;

  // Confusion Matrix
  if (m.confusion_matrix) {
    const [[tn, fp], [fn, tp]] = m.confusion_matrix;
    document.getElementById("cm-tn").innerText = tn;
    document.getElementById("cm-fp").innerText = fp;
    document.getElementById("cm-fn").innerText = fn;
    document.getElementById("cm-tp").innerText = tp;
  }

  // Render SOC Nodes in Topology
  const nodesList = document.getElementById("soc-nodes-list");
  nodesList.innerHTML = "";

  const nodeProfiles = {
    "SOC-FIN-01": { desc: "Financial Telemetry (DoS / DDoS Defense)", icon: "🏦" },
    "SOC-MED-02": { desc: "Hospital IoT (Portscan & Recon Defense)", icon: "🏥" },
    "SOC-DEF-03": { desc: "Critical Defense (Remote Exploit & U2R)", icon: "🛡️" },
    "SOC-ROGUE-99": { desc: "Poisoning Attack (15x Gradient Scaling)", icon: "⚠️" }
  };

  round.proof_summaries.forEach(ps => {
    const isQuarantined = (ps.zk_status !== "PROVEN_VALID");
    const item = document.createElement("div");
    item.className = `soc-item ${isQuarantined ? "status-quarantined" : "status-verified"}`;

    const prof = nodeProfiles[ps.node_id] || { desc: "Participant SOC", icon: "🏢" };

    item.innerHTML = `
      <div class="soc-info">
        <div class="soc-name">
          <span>${prof.icon}</span>
          <strong>${ps.node_id}</strong>
          <span class="soc-badge-id">Norm: ${ps.norm.toFixed(2)}</span>
        </div>
        <div class="soc-desc">${prof.desc}</div>
      </div>
      <div class="soc-meta">
        <span class="soc-status-badge ${isQuarantined ? 'badge-quarantine' : 'badge-pass'}">
          ${isQuarantined ? 'QUARANTINED' : 'ZK-VERIFIED'}
        </span>
      </div>
    `;
    nodesList.appendChild(item);
  });

  // Render ZKP Invariant Inspector
  const inspector = document.getElementById("zkp-inspector");
  inspector.innerHTML = "";

  round.proof_summaries.forEach(ps => {
    const isOverflow = ps.norm > 3.5;
    const barWidth = Math.min(100, (ps.norm / 15.0) * 100);
    const entry = document.createElement("div");
    entry.className = "zkp-entry";
    entry.innerHTML = `
      <div class="zkp-entry-top">
        <span class="zkp-node-label">${ps.node_id}</span>
        <span class="${isOverflow ? 'text-danger' : 'text-accent'}">${ps.zk_status}</span>
      </div>
      <div class="zkp-hash-row">
        <span>Proof: ${ps.sig}</span>
        <span>Norm: ${ps.norm.toFixed(2)} / Bound: 3.50</span>
      </div>
      <div class="zkp-norm-bar-wrap">
        <div class="zkp-norm-bar">
          <div class="zkp-norm-fill ${isOverflow ? 'overflow' : ''}" style="width: ${barWidth}%"></div>
        </div>
        <span style="font-size:0.68rem; color:${isOverflow ? 'var(--color-danger)' : 'var(--color-text-dim)'}">
          ${isOverflow ? 'VIOLATION' : 'BOUNDED'}
        </span>
      </div>
    `;
    inspector.appendChild(entry);
  });

  // Add terminal entry
  addTerminalLog("info", `Round ${round.round_num}: Verified ${round.accepted_count} honest updates. Quarantined ${round.quarantined_count} adversarial payloads.`);
  if (round.quarantine_log && round.quarantine_log.length > 0) {
    round.quarantine_log.forEach(q => {
      addTerminalLog("danger", `[SECURITY ALERT] Rejected ${q.node_id}: ${q.reason}`);
    });
  }
}

function changeRound(delta) {
  const newIdx = currentRoundIndex + delta;
  if (newIdx >= 0 && newIdx < simulationData.rounds.length) {
    currentRoundIndex = newIdx;
    renderCurrentRound();
  }
}

function toggleAutoPlay() {
  const btn = document.getElementById("btn-play-pause");
  if (autoPlayInterval) {
    clearInterval(autoPlayInterval);
    autoPlayInterval = null;
    btn.innerText = "▶ Auto Play";
    btn.classList.remove("active");
  } else {
    btn.innerText = "⏸ Pause";
    btn.classList.add("active");
    autoPlayInterval = setInterval(() => {
      currentRoundIndex = (currentRoundIndex + 1) % simulationData.rounds.length;
      renderCurrentRound();
    }, 2200);
  }
}

function reloadSimulation() {
  addTerminalLog("info", "Checking for live simulation results update...");
  loadLiveSimulationResults();
}

function addTerminalLog(type, message) {
  const term = document.getElementById("terminal-stream");
  const time = new Date().toLocaleTimeString();
  const line = document.createElement("div");
  line.className = `terminal-line ${type}`;
  line.innerHTML = `<span class="terminal-time">[${time}]</span> ${message}`;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function clearLogs() {
  document.getElementById("terminal-stream").innerHTML = "";
  addTerminalLog("info", "Audit logs cleared.");
}

// Draw HTML5 Canvas Convergence Chart
function drawConvergenceChart() {
  const canvas = document.getElementById("convergenceChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);

  const padding = { top: 20, right: 30, bottom: 30, left: 45 };
  const chartW = w - padding.left - padding.right;
  const chartH = h - padding.top - padding.bottom;

  const rounds = simulationData.rounds;
  const numPts = rounds.length;

  // Draw Grid Lines
  ctx.strokeStyle = "rgba(255, 255, 255, 0.07)";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(w - padding.right, y);
    ctx.stroke();

    // Y Axis labels (80% to 100%)
    const val = 100 - i * 5;
    ctx.fillStyle = "#8892b0";
    ctx.font = "10px 'Fira Code', monospace";
    ctx.textAlign = "right";
    ctx.fillText(`${val}%`, padding.left - 8, y + 3);
  }

  // Draw Lines for Accuracy (green) and Recall (cyan)
  function plotLine(color, field) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    ctx.beginPath();

    rounds.forEach((r, idx) => {
      const x = padding.left + (chartW / (numPts - 1)) * idx;
      const pct = (r.metrics_after[field] || 0.8) * 100;
      // Map 80% -> bottom, 100% -> top
      const normalized = (pct - 80) / 20;
      const y = padding.top + chartH - (normalized * chartH);

      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Draw Points
    rounds.forEach((r, idx) => {
      const x = padding.left + (chartW / (numPts - 1)) * idx;
      const pct = (r.metrics_after[field] || 0.8) * 100;
      const normalized = (pct - 80) / 20;
      const y = padding.top + chartH - (normalized * chartH);

      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fill();

      // X labels
      if (field === "accuracy") {
        ctx.fillStyle = "#8892b0";
        ctx.textAlign = "center";
        ctx.fillText(`R${r.round_num}`, x, h - 10);
      }
    });
  }

  plotLine("#00e676", "accuracy");
  plotLine("#00e5ff", "recall");
}
