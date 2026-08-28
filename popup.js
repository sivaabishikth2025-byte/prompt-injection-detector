const state = { policy: null };

const els = {
  enabledToggle: document.getElementById("enabled-toggle"),
  policyPack: document.getElementById("policy-pack"),
  autoThreshold: document.getElementById("auto-threshold"),
  blockThreshold: document.getElementById("block-threshold"),
  proxyStatusLabel: document.getElementById("proxy-status-label"),
  ledgerIntegrity: document.getElementById("ledger-integrity"),
  events: document.getElementById("events"),
  refreshBtn: document.getElementById("refresh-btn"),
  openOptions: document.getElementById("open-options"),
  clearLedger: document.getElementById("clear-ledger"),
  sparkCanvas: document.getElementById("risk-sparkline"),
  sparkRange: document.getElementById("spark-range"),
};

init().catch(() => renderError("Unable to load extension status."));

els.enabledToggle.addEventListener("change", async () => {
  if (!state.policy) return;
  state.policy.enabled = Boolean(els.enabledToggle.checked);
  await setPolicy(state.policy);
  await refresh();
});

els.refreshBtn.addEventListener("click", () => refresh());
els.openOptions.addEventListener("click", () => chrome.runtime.openOptionsPage());
els.clearLedger.addEventListener("click", async () => {
  if (!confirm("Clear all trust ledger entries?")) return;
  await sendMsg({ type: "LEDGER_CLEAR" });
  await refresh();
});

async function init() {
  await refresh();
}

async function refresh() {
  const [policyResp, ledgerResp, verifyResp] = await Promise.all([
    sendMsg({ type: "POLICY_GET" }),
    sendMsg({ type: "LEDGER_GET", payload: { limit: 40 } }),
    sendMsg({ type: "LEDGER_VERIFY" }),
  ]);

  if (!policyResp?.ok) throw new Error("policy_load_failed");
  state.policy = policyResp.policy;
  renderPolicy(state.policy);

  const ledger = ledgerResp?.ok ? ledgerResp.ledger || [] : [];
  renderEvents(ledger.slice(0, 6));
  renderIntegrity(verifyResp?.ok ? verifyResp : null);
  drawSparkline(ledger);
}

function renderPolicy(policy) {
  els.enabledToggle.checked = Boolean(policy.enabled);
  els.policyPack.textContent = String(policy.policyPack || "custom").toUpperCase();
  els.autoThreshold.textContent = `${policy.riskAutoRedactThreshold}/100`;
  els.blockThreshold.textContent = `${policy.riskBlockThreshold}/100`;

  if (policy.proxyChainEnabled && Array.isArray(policy.proxyChain) && policy.proxyChain.length > 0) {
    els.proxyStatusLabel.textContent = `${policy.proxyChain.length} hop(s) ON`;
    els.proxyStatusLabel.className = "risk-low";
  } else {
    els.proxyStatusLabel.textContent = "Off";
    els.proxyStatusLabel.style.color = "#94a3b8";
  }
}

function renderIntegrity(verifyResp) {
  if (!verifyResp) {
    els.ledgerIntegrity.textContent = "Unknown";
    els.ledgerIntegrity.className = "risk-medium";
    return;
  }

  if (verifyResp.valid) {
    els.ledgerIntegrity.textContent = `OK (${verifyResp.checked})`;
    els.ledgerIntegrity.className = "risk-low";
  } else {
    els.ledgerIntegrity.textContent = `Broken at #${verifyResp.brokenAtIndex}`;
    els.ledgerIntegrity.className = "risk-high";
  }
}

function renderEvents(events) {
  els.events.innerHTML = "";
  if (!Array.isArray(events) || events.length === 0) {
    const li = document.createElement("li");
    li.className = "event-item muted";
    li.textContent = "No ledger events yet.";
    els.events.appendChild(li);
    return;
  }

  for (const event of events) {
    const li = document.createElement("li");
    li.className = "event-item";
    const risk = Number.isFinite(event.risk) ? event.risk : 0;
    const injBadge = event.injectionDetected ? `<span class="injection-badge">INJECT</span>` : "";
    li.innerHTML = `
      <div class="event-top">
        <span class="event-action">${escHtml(event.action || "INFO")}</span>
        <span class="${riskClass(risk)}">${risk}</span>
      </div>
      <div class="event-domain">${escHtml(event.domain || "unknown")}</div>
      <div class="event-meta">${formatTs(event.ts)} • ${escHtml(event.eventType || "event")}</div>
      ${injBadge ? `<div class="badge-row">${injBadge}</div>` : ""}
    `;
    els.events.appendChild(li);
  }
}

// ─────────────────────────────────────────────
//  Risk sparkline (Canvas)
// ─────────────────────────────────────────────
function drawSparkline(ledger) {
  const canvas = els.sparkCanvas;
  if (!canvas) return;

  const dpr = window.devicePixelRatio || 1;
  const W = canvas.offsetWidth || 260;
  const H = 36;

  canvas.width = W * dpr;
  canvas.height = H * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);

  const scanEntries = ledger.filter((e) => e.eventType === "scan" && Number.isFinite(e.risk));
  const points = scanEntries.slice(0, 30).reverse();

  if (points.length === 0) {
    ctx.fillStyle = "#f1f5f9";
    ctx.fillRect(0, 0, W, H);
    ctx.fillStyle = "#94a3b8";
    ctx.font = "10px system-ui";
    ctx.textAlign = "center";
    ctx.fillText("No scan data yet", W / 2, H / 2 + 4);
    els.sparkRange.textContent = "";
    return;
  }

  const risks = points.map((p) => p.risk);
  const maxR = Math.max(...risks, 10);
  const minR = Math.min(...risks);
  const pad = { t: 4, b: 4, l: 4, r: 4 };
  const gW = W - pad.l - pad.r;
  const gH = H - pad.t - pad.b;

  ctx.fillStyle = "#f8fafc";
  ctx.fillRect(0, 0, W, H);

  const xAt = (i) => pad.l + (i / Math.max(1, points.length - 1)) * gW;
  const yAt = (r) => pad.t + gH - (r / Math.max(1, maxR)) * gH;

  const grad = ctx.createLinearGradient(0, pad.t, 0, H - pad.b);
  grad.addColorStop(0, "rgba(17,24,39,0.18)");
  grad.addColorStop(1, "rgba(17,24,39,0.01)");

  ctx.beginPath();
  ctx.moveTo(xAt(0), H - pad.b);
  points.forEach((p, i) => ctx.lineTo(xAt(i), yAt(p.risk)));
  ctx.lineTo(xAt(points.length - 1), H - pad.b);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  ctx.beginPath();
  points.forEach((p, i) => {
    if (i === 0) ctx.moveTo(xAt(i), yAt(p.risk));
    else ctx.lineTo(xAt(i), yAt(p.risk));
  });
  ctx.strokeStyle = "#111827";
  ctx.lineWidth = 1.5;
  ctx.lineJoin = "round";
  ctx.stroke();

  points.forEach((p, i) => {
    ctx.beginPath();
    ctx.arc(xAt(i), yAt(p.risk), 2.5, 0, Math.PI * 2);
    ctx.fillStyle = p.risk >= 70 ? "#dc2626" : p.risk >= 30 ? "#f59e0b" : "#16a34a";
    ctx.fill();
    if (p.injectionDetected) {
      ctx.beginPath();
      ctx.arc(xAt(i), yAt(p.risk), 5, 0, Math.PI * 2);
      ctx.strokeStyle = "#dc2626";
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }
  });

  els.sparkRange.textContent = `${points.length} scan(s) · max ${maxR} · min ${minR}`;
}

function riskClass(risk) {
  if (risk >= 70) return "pill risk-high";
  if (risk >= 30) return "pill risk-medium";
  return "pill risk-low";
}

function formatTs(ts) {
  if (!Number.isFinite(ts)) return "-";
  try {
    return new Date(ts).toLocaleTimeString();
  } catch {
    return "-";
  }
}

async function setPolicy(policy) {
  const resp = await sendMsg({ type: "POLICY_SET", payload: { policy } });
  if (!resp?.ok) throw new Error("policy_save_failed");
  return resp.policy;
}

function renderError(message) {
  els.events.innerHTML = "";
  const li = document.createElement("li");
  li.className = "event-item muted";
  li.textContent = message;
  els.events.appendChild(li);
}

function sendMsg(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
        return;
      }
      resolve(resp || { ok: false, error: "No response." });
    });
  });
}

function escHtml(value) {
  return String(value || "").replace(/[&<>"']/g, (ch) => {
    switch (ch) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#039;";
    }
  });
}

