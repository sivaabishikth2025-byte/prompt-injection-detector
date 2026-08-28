document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "vault") loadVault();
    if (btn.dataset.tab === "audit") loadAudit();
    if (btn.dataset.tab === "enterprise") loadEnterprise();
  });
});

const state = { policy: null, packs: {}, proxyHops: [], enterprise: null, enterpriseSelectedId: null };

const els = {
  policyPack: document.getElementById("policy-pack"),
  enabled: document.getElementById("enabled"),
  autoThreshold: document.getElementById("auto-threshold"),
  blockThreshold: document.getElementById("block-threshold"),
  holdMs: document.getElementById("hold-ms"),
  allowlist: document.getElementById("allowlist"),
  strictDomains: document.getElementById("strict-domains"),
  denyOverrides: document.getElementById("deny-overrides"),
  clipboardProtection: document.getElementById("clipboard-protection"),
  localOnlyMode: document.getElementById("local-only-mode"),
  saveBtn: document.getElementById("save-btn"),
  resetPackBtn: document.getElementById("reset-pack-btn"),
  clearLedgerBtn: document.getElementById("clear-ledger-btn"),
  status: document.getElementById("status"),

  proxyEnabled: document.getElementById("proxy-enabled"),
  proxyHopsList: document.getElementById("proxy-hops-list"),
  addHopBtn: document.getElementById("add-hop-btn"),
  saveProxyBtn: document.getElementById("save-proxy-btn"),
  testProxyBtn: document.getElementById("test-proxy-btn"),
  proxyTestResults: document.getElementById("proxy-test-results"),
  proxyStatus: document.getElementById("proxy-status"),

  vaultList: document.getElementById("vault-list"),
  clearVaultBtn: document.getElementById("clear-vault-btn"),

  auditSummary: document.getElementById("audit-summary"),
  exportJsonBtn: document.getElementById("export-json-btn"),
  exportCsvBtn: document.getElementById("export-csv-btn"),
  refreshAuditBtn: document.getElementById("refresh-audit-btn"),
  auditStatus: document.getElementById("audit-status"),

  enterpriseEnabled: document.getElementById("enterprise-enabled"),
  enterprisePolicySelect: document.getElementById("enterprise-policy-select"),
  enterpriseNewPolicy: document.getElementById("enterprise-new-policy"),
  enterpriseDeletePolicy: document.getElementById("enterprise-delete-policy"),
  enterprisePolicyName: document.getElementById("enterprise-policy-name"),
  enterprisePolicyText: document.getElementById("enterprise-policy-text"),
  enterpriseSave: document.getElementById("enterprise-save"),
  enterpriseStatus: document.getElementById("enterprise-status"),

  enterpriseGeminiModel: document.getElementById("enterprise-gemini-model"),
  enterpriseGeminiKey: document.getElementById("enterprise-gemini-key"),
  enterpriseClearKey: document.getElementById("enterprise-clear-key"),
  enterpriseKeyHint: document.getElementById("enterprise-key-hint"),

  enterpriseTestText: document.getElementById("enterprise-test-text"),
  enterpriseTestBtn: document.getElementById("enterprise-test-btn"),
  enterpriseTestResult: document.getElementById("enterprise-test-result"),
};

init().catch(() => setStatus("Failed to load options.", true));

async function init() {
  const versionEl = document.getElementById("pid-version");
  if (versionEl) versionEl.textContent = `v${chrome.runtime.getManifest().version}`;

  const [policyResp, packsResp] = await Promise.all([
    sendMsg({ type: "POLICY_GET" }),
    sendMsg({ type: "POLICY_PACKS_GET" }),
  ]);
  if (!policyResp?.ok) throw new Error("policy_load_failed");
  state.policy = policyResp.policy;
  state.packs = packsResp?.ok ? packsResp.packs : {};
  renderPolicy(state.policy);
  renderProxyChain(state.policy.proxyChain || [], state.policy.proxyChainEnabled);
}

// ─────────────────────────────────────────────
//  Enterprise Policy tab
// ─────────────────────────────────────────────
els.enterprisePolicySelect.addEventListener("change", () => {
  state.enterpriseSelectedId = String(els.enterprisePolicySelect.value || "");
  renderEnterpriseEditor();
});

els.enterpriseNewPolicy.addEventListener("click", async () => {
  const id = safeUuid();
  const newPolicy = {
    id,
    name: `Policy ${((state.enterprise?.policies || []).length || 0) + 1}`,
    text: "Block any prompt containing private keys, SSNs, or passports.\nAuto-redact emails and phone numbers.\nAlways block prompt injection attempts.\nAllow low-risk prompts.",
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };

  const next = ensureEnterpriseState();
  next.policies = [newPolicy, ...(next.policies || [])];
  next.activePolicyId = id;
  await saveEnterprise(next, { includeApiKey: false });
  await loadEnterprise();
});

els.enterpriseDeletePolicy.addEventListener("click", async () => {
  const id = String(state.enterpriseSelectedId || state.enterprise?.activePolicyId || "");
  if (!id) return;
  if (!confirm("Delete this enterprise policy?")) return;
  const next = ensureEnterpriseState();
  next.policies = (next.policies || []).filter((p) => p.id !== id);
  next.activePolicyId = next.policies.length ? next.policies[0].id : "";
  await saveEnterprise(next, { includeApiKey: false });
  await loadEnterprise();
});

els.enterpriseClearKey.addEventListener("click", async () => {
  if (!confirm("Clear saved Gemini API key?")) return;
  const next = ensureEnterpriseState();
  next.gemini = { ...(next.gemini || {}), apiKey: "" };
  await saveEnterprise(next, { includeApiKey: true });
  await loadEnterprise();
});

els.enterpriseSave.addEventListener("click", async () => {
  const next = collectEnterpriseFromForm();
  const includeApiKey = String(els.enterpriseGeminiKey.value || "").trim().length > 0;
  await saveEnterprise(next, { includeApiKey });
  els.enterpriseGeminiKey.value = "";
  await loadEnterprise();
  setEnterpriseStatus("Enterprise settings saved.");
});

els.enterpriseTestBtn.addEventListener("click", async () => {
  els.enterpriseTestResult.textContent = "Running…";
  const text = String(els.enterpriseTestText.value || "");
  const resp = await sendMsg({
    type: "ENTERPRISE_TEST",
    payload: { text, domain: "test.local" },
  });
  if (!resp?.ok) {
    els.enterpriseTestResult.textContent = `Error: ${resp?.error || "test_failed"}`;
    return;
  }
  els.enterpriseTestResult.textContent = JSON.stringify(resp.result, null, 2);
});

async function loadEnterprise() {
  const resp = await sendMsg({ type: "ENTERPRISE_GET" });
  if (!resp?.ok) {
    setEnterpriseStatus(`Failed to load enterprise settings. ${resp?.error ? `(${resp.error})` : ""}`, true);
    return;
  }
  state.enterprise = resp.enterprise;
  state.enterpriseSelectedId = String(resp.enterprise.activePolicyId || "");
  renderEnterpriseForm();
}

function renderEnterpriseForm() {
  const ent = state.enterprise || {};
  els.enterpriseEnabled.checked = Boolean(ent.enabled);
  els.enterpriseGeminiModel.value = String(ent.gemini?.model || "gemini-1.5-flash");
  els.enterpriseKeyHint.textContent = ent.gemini?.apiKeyPresent ? "API key saved" : "No API key saved";

  const policies = Array.isArray(ent.policies) ? ent.policies : [];
  els.enterprisePolicySelect.innerHTML = "";
  if (policies.length === 0) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "No policies yet";
    els.enterprisePolicySelect.appendChild(opt);
    state.enterpriseSelectedId = "";
  } else {
    for (const p of policies) {
      const opt = document.createElement("option");
      opt.value = p.id;
      opt.textContent = p.name || p.id;
      els.enterprisePolicySelect.appendChild(opt);
    }
    els.enterprisePolicySelect.value = String(state.enterpriseSelectedId || ent.activePolicyId || policies[0].id);
    state.enterpriseSelectedId = String(els.enterprisePolicySelect.value || "");
  }
  renderEnterpriseEditor();
}

function renderEnterpriseEditor() {
  const ent = state.enterprise || {};
  const policies = Array.isArray(ent.policies) ? ent.policies : [];
  const current = policies.find((p) => p.id === state.enterpriseSelectedId) || policies[0] || null;
  els.enterprisePolicyName.value = current ? String(current.name || "") : "";
  els.enterprisePolicyText.value = current ? String(current.text || "") : "";
}

function collectEnterpriseFromForm() {
  const ent = ensureEnterpriseState();
  ent.enabled = Boolean(els.enterpriseEnabled.checked);
  ent.gemini = {
    ...(ent.gemini || {}),
    model: String(els.enterpriseGeminiModel.value || "gemini-1.5-flash").trim(),
  };

  const apiKey = String(els.enterpriseGeminiKey.value || "").trim();
  if (apiKey) ent.gemini.apiKey = apiKey;

  const selectedId = String(state.enterpriseSelectedId || ent.activePolicyId || "");
  const policies = Array.isArray(ent.policies) ? [...ent.policies] : [];
  const idx = policies.findIndex((p) => p.id === selectedId);
  if (idx >= 0) {
    policies[idx] = {
      ...policies[idx],
      name: String(els.enterprisePolicyName.value || "").trim() || policies[idx].name,
      text: String(els.enterprisePolicyText.value || ""),
      updatedAt: Date.now(),
    };
  }
  ent.policies = policies;
  ent.activePolicyId = selectedId;

  return ent;
}

function ensureEnterpriseState() {
  const ent = state.enterprise && typeof state.enterprise === "object" ? { ...state.enterprise } : {};
  ent.enabled = Boolean(ent.enabled);
  ent.activePolicyId = String(ent.activePolicyId || "");
  ent.policies = Array.isArray(ent.policies) ? ent.policies : [];
  ent.gemini = ent.gemini && typeof ent.gemini === "object" ? ent.gemini : {};
  return ent;
}

async function saveEnterprise(enterprise, { includeApiKey }) {
  const payload = { enterprise };
  if (!includeApiKey) {
    // Avoid overwriting saved key with blank.
    if (payload.enterprise?.gemini) {
      payload.enterprise = { ...payload.enterprise, gemini: { ...payload.enterprise.gemini } };
      delete payload.enterprise.gemini.apiKey;
    }
  }
  const resp = await sendMsg({ type: "ENTERPRISE_SET", payload });
  if (!resp?.ok) throw new Error(resp?.error || "enterprise_save_failed");
}

function setEnterpriseStatus(msg, isError = false) {
  els.enterpriseStatus.textContent = msg;
  els.enterpriseStatus.className = `status-text ${isError ? "error" : "ok"}`;
}

function safeUuid() {
  try {
    return crypto.randomUUID();
  } catch {
    return `id_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  }
}

// ─────────────────────────────────────────────
//  Policy tab
// ─────────────────────────────────────────────
els.policyPack.addEventListener("change", () => {
  if (els.policyPack.value !== "custom") applyPackToForm(els.policyPack.value);
});

els.saveBtn.addEventListener("click", async () => {
  const resp = await sendMsg({ type: "POLICY_SET", payload: { policy: collectPolicyFromForm() } });
  if (!resp?.ok) {
    setStatus("Policy save failed.", true);
    return;
  }
  state.policy = resp.policy;
  renderPolicy(resp.policy);
  setStatus("Policy saved.");
});

els.resetPackBtn.addEventListener("click", () => {
  if (els.policyPack.value === "custom") {
    setStatus("Select a named pack first.", true);
    return;
  }
  applyPackToForm(els.policyPack.value);
  setStatus("Pack defaults applied. Click Save to persist.");
});

els.clearLedgerBtn.addEventListener("click", async () => {
  if (!confirm("Clear all ledger entries?")) return;
  const resp = await sendMsg({ type: "LEDGER_CLEAR" });
  if (resp?.ok) setStatus("Ledger cleared.");
  else setStatus("Could not clear ledger.", true);
});

function renderPolicy(policy) {
  els.policyPack.value = ["student", "healthcare", "legal", "corporate", "custom"].includes(policy.policyPack)
    ? policy.policyPack
    : "custom";
  els.enabled.checked = Boolean(policy.enabled);
  els.autoThreshold.value = String(policy.riskAutoRedactThreshold ?? 30);
  els.blockThreshold.value = String(policy.riskBlockThreshold ?? 70);
  els.holdMs.value = String(policy.holdToConfirmMs ?? 2000);
  els.allowlist.value = (policy.allowlistDomains || []).join(", ");
  els.strictDomains.value = (policy.strictModeDomains || []).join(", ");
  els.denyOverrides.checked = Boolean(policy.denyOverridesForSecrets);
  els.clipboardProtection.checked = Boolean(policy.clipboardProtection);
  els.localOnlyMode.checked = Boolean(policy.localOnlyMode);
}

function collectPolicyFromForm() {
  return {
    enabled: els.enabled.checked,
    policyPack: String(els.policyPack.value || "custom"),
    riskAutoRedactThreshold: clamp(Number(els.autoThreshold.value), 1, 100, 30),
    riskBlockThreshold: clamp(Number(els.blockThreshold.value), 1, 100, 70),
    holdToConfirmMs: clamp(Number(els.holdMs.value), 800, 7000, 2000),
    allowlistDomains: parseDomains(els.allowlist.value),
    strictModeDomains: parseDomains(els.strictDomains.value),
    denyOverridesForSecrets: els.denyOverrides.checked,
    clipboardProtection: els.clipboardProtection.checked,
    localOnlyMode: els.localOnlyMode.checked,
    proxyChain: state.proxyHops,
    proxyChainEnabled: els.proxyEnabled.checked,
  };
}

function applyPackToForm(packName) {
  const pack = state.packs[packName];
  if (!pack) return;
  if (pack.riskAutoRedactThreshold) els.autoThreshold.value = String(pack.riskAutoRedactThreshold);
  if (pack.riskBlockThreshold) els.blockThreshold.value = String(pack.riskBlockThreshold);
  els.denyOverrides.checked = Boolean(pack.denyOverridesForSecrets);
  els.clipboardProtection.checked = Boolean(pack.clipboardProtection);
  els.localOnlyMode.checked = Boolean(pack.localOnlyMode);
}

// ─────────────────────────────────────────────
//  Proxy Chain tab
// ─────────────────────────────────────────────
function renderProxyChain(hops, enabled) {
  state.proxyHops = Array.isArray(hops) ? [...hops] : [];
  els.proxyEnabled.checked = Boolean(enabled);
  redrawHops();
}

function redrawHops() {
  els.proxyHopsList.innerHTML = "";
  if (state.proxyHops.length === 0) {
    els.proxyHopsList.innerHTML = '<p class="subtitle" style="margin:0 0 12px;">No hops configured. Add one to build the chain.</p>';
    return;
  }

  state.proxyHops.forEach((hop, i) => {
    const div = document.createElement("div");
    div.className = "proxy-hop";
    div.innerHTML = `
      <div class="proxy-hop-header">
        <span>Hop ${i + 1} — <span id="hop-label-display-${i}">${escHtml(hop.label || `Hop ${i + 1}`)}</span></span>
        <button class="hop-remove" data-index="${i}">Remove</button>
      </div>
      <div class="hop-grid">
        <div class="hop-grid-full">
          <label style="font-size:11px;font-weight:600;display:block;margin-bottom:3px;color:#94a3b8;">Label</label>
          <input type="text" class="hop-field" data-hop="${i}" data-key="label" value="${escHtml(
            hop.label || `Hop ${i + 1}`
          )}" placeholder="Friendly name"/>
        </div>
        <div class="hop-grid-full">
          <label style="font-size:11px;font-weight:600;display:block;margin-bottom:3px;color:#94a3b8;">Endpoint URL</label>
          <input type="url" class="hop-field" data-hop="${i}" data-key="url" value="${escHtml(hop.url || "")}" placeholder="https://your-proxy.example.com/audit"/>
        </div>
        <div>
          <label style="font-size:11px;font-weight:600;display:block;margin-bottom:3px;color:#94a3b8;">Auth Header</label>
          <input type="text" class="hop-field" data-hop="${i}" data-key="authHeader" value="${escHtml(hop.authHeader || "")}" placeholder="Authorization"/>
        </div>
        <div>
          <label style="font-size:11px;font-weight:600;display:block;margin-bottom:3px;color:#94a3b8;">Auth Value</label>
          <input type="text" class="hop-field" data-hop="${i}" data-key="authValue" value="${escHtml(hop.authValue || "")}" placeholder="Bearer ..."/>
        </div>
        <div>
          <label style="font-size:11px;font-weight:600;display:block;margin-bottom:3px;color:#94a3b8;">Transform</label>
          <select class="hop-field" data-hop="${i}" data-key="transform">
            <option value="passthrough" ${hop.transform === "passthrough" ? "selected" : ""}>Passthrough</option>
            <option value="audit" ${hop.transform === "audit" ? "selected" : ""}>Audit Only</option>
            <option value="rewrite" ${hop.transform === "rewrite" ? "selected" : ""}>Rewrite</option>
            <option value="filter" ${hop.transform === "filter" ? "selected" : ""}>Filter</option>
          </select>
        </div>
        <div>
          <label style="font-size:11px;font-weight:600;display:block;margin-bottom:3px;color:#94a3b8;">Timeout (ms)</label>
          <input type="number" class="hop-field" data-hop="${i}" data-key="timeoutMs" value="${hop.timeoutMs || 5000}" min="500" max="15000"/>
        </div>
        <div>
          <label style="font-size:11px;font-weight:600;display:block;margin-bottom:3px;color:#94a3b8;">On Failure</label>
          <select class="hop-field" data-hop="${i}" data-key="failAction">
            <option value="passthrough" ${hop.failAction === "passthrough" ? "selected" : ""}>Continue (passthrough)</option>
            <option value="abort" ${hop.failAction === "abort" ? "selected" : ""}>Abort send</option>
          </select>
        </div>
      </div>
    `;
    els.proxyHopsList.appendChild(div);
  });

  els.proxyHopsList.querySelectorAll(".hop-remove").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.proxyHops.splice(Number(btn.dataset.index), 1);
      redrawHops();
    });
  });

  els.proxyHopsList.querySelectorAll(".hop-field").forEach((input) => {
    input.addEventListener("input", () => {
      const i = Number(input.dataset.hop);
      const k = input.dataset.key;
      state.proxyHops[i][k] = input.type === "number" ? Number(input.value) : input.value;
      if (k === "label") {
        const display = document.getElementById(`hop-label-display-${i}`);
        if (display) display.textContent = input.value || `Hop ${i + 1}`;
      }
    });
  });
}

els.addHopBtn.addEventListener("click", () => {
  state.proxyHops.push({
    url: "",
    label: `Hop ${state.proxyHops.length + 1}`,
    authHeader: "",
    authValue: "",
    transform: "passthrough",
    timeoutMs: 5000,
    failAction: "passthrough",
  });
  redrawHops();
});

els.saveProxyBtn.addEventListener("click", async () => {
  const policy = {
    ...(state.policy || {}),
    proxyChain: state.proxyHops,
    proxyChainEnabled: els.proxyEnabled.checked,
  };
  const resp = await sendMsg({ type: "POLICY_SET", payload: { policy } });
  if (!resp?.ok) {
    setProxyStatus("Save failed.", true);
    return;
  }
  state.policy = resp.policy;
  setProxyStatus("Proxy chain saved.");
});

els.testProxyBtn.addEventListener("click", async () => {
  if (state.proxyHops.length === 0) {
    setProxyStatus("No hops to test.", true);
    return;
  }
  const validHops = state.proxyHops.filter((h) => String(h.url || "").trim());
  if (validHops.length === 0) {
    setProxyStatus("No hops with URLs configured.", true);
    return;
  }
  setProxyStatus("Testing chain…");
  els.proxyTestResults.style.display = "none";

  const resp = await sendMsg({
    type: "PROXY_CHAIN_TEST",
    payload: { hops: validHops, text: "[TEST] Hello from Prompt Injection Detector proxy chain test." },
  });
  if (!resp?.ok) {
    setProxyStatus(`Test request failed: ${resp?.error || "unknown"}`, true);
    return;
  }

  els.proxyTestResults.style.display = "block";
  const hops = resp.hops || [];
  const aborted = resp.aborted ? `<div style="color:#fecaca;font-weight:600;margin-bottom:8px;">Chain aborted at hop ${resp.abortedAt}</div>` : "";
  els.proxyTestResults.innerHTML = `
    <div style="font-weight:600;margin-bottom:8px;">Test Results</div>
    ${aborted}
    ${hops
      .map(
        (h, i) => `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;padding:6px 8px;background:rgba(15, 23, 42, 0.45);border:1px solid rgba(148, 163, 184, 0.25);border-radius:6px;">
        <span><b>Hop ${i + 1}</b> — ${escHtml(h.url || "(no url)")} ${h.transform ? `(${h.transform})` : ""}</span>
        <span>
          ${
            h.skipped
              ? `<span class="hop-status hop-pend">Skipped</span>`
              : h.success
                ? `<span class="hop-status hop-ok">✓ ${h.latencyMs}ms</span>`
                : `<span class="hop-status hop-fail">✗ ${escHtml(h.error || "error")}</span>`
          }
        </span>
      </div>
    `
      )
      .join("")}
    <div style="margin-top:8px;color:#e5e7eb;"><b>Final output:</b> ${escHtml((resp.finalText || "").slice(0, 200))}${
      (resp.finalText || "").length > 200 ? "…" : ""
    }</div>
  `;
  const fails = hops.filter((h) => !h.skipped && !h.success).length;
  setProxyStatus(`Test complete. ${hops.length} hop(s), ${fails} failure(s).`, fails > 0);
});

// ─────────────────────────────────────────────
//  Vault tab
// ─────────────────────────────────────────────
async function loadVault() {
  els.vaultList.innerHTML = '<div class="muted" style="font-size:12px;">Loading…</div>';
  const resp = await sendMsg({ type: "VAULT_GET" });
  const items = resp?.ok ? resp.vault || [] : [];
  if (items.length === 0) {
    els.vaultList.innerHTML = '<div class="muted" style="font-size:12px;">No vault entries yet.</div>';
    return;
  }
  const grouped = {};
  for (const item of items) {
    if (!grouped[item.category]) grouped[item.category] = [];
    grouped[item.category].push(item);
  }
  els.vaultList.innerHTML = Object.entries(grouped)
    .map(
      ([cat, entries]) => `
    <div style="margin-bottom:14px;">
      <div style="font-weight:600;font-size:12px;margin-bottom:6px;">${escHtml(cat)} (${entries.length})</div>
      ${entries
        .map(
          (e) => `
        <div class="vault-item">
          <span style="font-family:ui-monospace,monospace;">${escHtml(e.placeholder)}</span>
          <span style="color:#94a3b8;font-size:11px;">${formatTs(e.ts)}</span>
        </div>
      `
        )
        .join("")}
    </div>
  `
    )
    .join("");
}

els.clearVaultBtn.addEventListener("click", async () => {
  if (!confirm("Clear all vault entries?")) return;
  await sendMsg({ type: "VAULT_CLEAR" });
  loadVault();
});

// ─────────────────────────────────────────────
//  Audit & Export tab
// ─────────────────────────────────────────────
async function loadAudit() {
  els.auditSummary.innerHTML = "Loading…";
  const resp = await sendMsg({ type: "AUDIT_EXPORT" });
  if (!resp?.ok) {
    els.auditSummary.innerHTML = "Failed to load audit data.";
    return;
  }
  const r = resp.report;
  const s = r.summary;
  const integrityColor = r.ledgerIntegrity?.valid ? "#86efac" : "#fecaca";
  const integrityText = r.ledgerIntegrity?.valid
    ? `✓ Intact (${r.ledgerIntegrity.checked} entries)`
    : `⚠ Broken at #${r.ledgerIntegrity.brokenAtIndex}`;

  els.auditSummary.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:14px;">
      <div style="background:rgba(15, 23, 42, 0.45);border:1px solid rgba(148, 163, 184, 0.25);border-radius:10px;padding:10px;">
        <div style="font-size:11px;color:#94a3b8;margin-bottom:2px;">Total Events</div>
        <div style="font-size:22px;font-weight:700;">${s.totalEvents}</div>
      </div>
      <div style="background:rgba(15, 23, 42, 0.45);border:1px solid rgba(148, 163, 184, 0.25);border-radius:10px;padding:10px;">
        <div style="font-size:11px;color:#94a3b8;margin-bottom:2px;">Avg Risk</div>
        <div style="font-size:22px;font-weight:700;">${s.avgRisk}/100</div>
        <div class="risk-bar-wrap"><div class="risk-bar" style="width:${s.avgRisk}%;background:${
          s.avgRisk > 70 ? "#dc2626" : s.avgRisk > 30 ? "#f59e0b" : "#16a34a"
        };"></div></div>
      </div>
      <div style="background:rgba(15, 23, 42, 0.45);border:1px solid rgba(148, 163, 184, 0.25);border-radius:10px;padding:10px;">
        <div style="font-size:11px;color:#94a3b8;margin-bottom:2px;">Injection Alerts</div>
        <div style="font-size:22px;font-weight:700;color:${s.injectionAttemptsDetected > 0 ? "#fecaca" : "#e5e7eb"}">${
          s.injectionAttemptsDetected
        }</div>
      </div>
    </div>
    <div style="font-size:12px;margin-bottom:6px;"><b>Ledger integrity:</b> <span style="color:${integrityColor}">${integrityText}</span></div>
    <div style="font-size:12px;margin-bottom:6px;"><b>Policy pack:</b> ${escHtml(r.policy.pack)} | Auto-redact: ${
      r.policy.autoRedactThreshold
    } | Block: ${r.policy.blockThreshold}</div>
    <div style="font-size:12px;margin-bottom:6px;"><b>Proxy chain:</b> ${
      r.policy.proxyChainEnabled ? `Enabled (${r.policy.proxyHops} hop(s))` : "Disabled"
    }</div>
    <div style="font-size:12px;margin-bottom:10px;"><b>Actions:</b> ${Object.entries(s.actionBreakdown || {})
      .map(([a, c]) => `${a}: ${c}`)
      .join(" • ")}</div>
    <div style="font-size:12px;"><b>Top categories:</b> ${(s.topCategories || []).slice(0, 6).map((c) => `${c.category} (${c.count})`).join(", ")}</div>
    <div style="font-size:11px;color:#94a3b8;margin-top:8px;">Generated: ${escHtml(r.generatedAt)}</div>
  `;

  window._pidAuditReport = r;
}

els.refreshAuditBtn.addEventListener("click", loadAudit);

els.exportJsonBtn.addEventListener("click", () => {
  if (!window._pidAuditReport) {
    setAuditStatus("Load report first.", true);
    return;
  }
  const blob = new Blob([JSON.stringify(window._pidAuditReport, null, 2)], { type: "application/json" });
  downloadBlob(blob, `prompt-injection-detector-audit-${dateTag()}.json`);
  setAuditStatus("JSON exported.");
});

els.exportCsvBtn.addEventListener("click", () => {
  if (!window._pidAuditReport) {
    setAuditStatus("Load report first.", true);
    return;
  }
  const entries = window._pidAuditReport.entries || [];
  const rows = [
    ["id", "ts", "domain", "action", "risk", "categories", "injectionDetected", "injectionSignals", "eventType", "note"],
    ...entries.map((e) => [
      e.id,
      new Date(e.ts).toISOString(),
      e.domain,
      e.action,
      e.risk,
      (e.categories || []).join("|"),
      e.injectionDetected ? "true" : "false",
      (e.injectionSignals || []).map((s) => s.signal).join("|"),
      e.eventType,
      JSON.stringify(e.note || ""),
    ]),
  ];
  const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\r\n");
  const blob = new Blob([csv], { type: "text/csv" });
  downloadBlob(blob, `prompt-injection-detector-audit-${dateTag()}.csv`);
  setAuditStatus("CSV exported.");
});

// ─────────────────────────────────────────────
//  Shared utils
// ─────────────────────────────────────────────
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function dateTag() {
  return new Date().toISOString().slice(0, 10);
}

function parseDomains(raw) {
  return Array.from(
    new Set(
      String(raw || "")
        .split(/[\n,]/g)
        .map((d) => d.trim().toLowerCase())
        .filter(Boolean)
        .map((d) => d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").split(":")[0])
    )
  );
}

function clamp(v, min, max, fallback) {
  if (!Number.isFinite(v)) return fallback;
  return Math.max(min, Math.min(max, Math.round(v)));
}

function setStatus(msg, isError = false) {
  els.status.textContent = msg;
  els.status.className = `status-text ${isError ? "error" : "ok"}`;
}
function setProxyStatus(msg, isError = false) {
  els.proxyStatus.textContent = msg;
  els.proxyStatus.className = `status-text ${isError ? "error" : "ok"}`;
}
function setAuditStatus(msg, isError = false) {
  els.auditStatus.textContent = msg;
  els.auditStatus.className = `status-text ${isError ? "error" : "ok"}`;
}

function formatTs(ts) {
  if (!Number.isFinite(ts)) return "-";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return "-";
  }
}

function escHtml(v) {
  return String(v || "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[c]));
}

function sendMsg(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
        return;
      }
      resolve(resp || { ok: false });
    });
  });
}

