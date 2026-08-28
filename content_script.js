const PF_STATE = {
  lastFocusedEditable: null,
  bypassUntil: 0,
  inFlight: false,
  // Behavioral signals (for invisible CAPTCHA)
  lastPasteAt: 0,
  pasteBurst: [],
  lastSendAt: 0,
  sendBurst: [],
  lastSendHash: "",
  repeatSendCount: 0,
  humanVerifiedUntil: 0,
  // Session-only safe substitution mapping
  substitutionCache: new Map(),
  substitutionSerial: {},
};

const EDITABLE_SELECTOR = 'textarea, [contenteditable="true"], [contenteditable="plaintext-only"]';
const CHAT_HOST_HINTS = ["chatgpt.com", "chat.openai.com", "gemini.google.com", "claude.ai", "perplexity.ai"];
const CHAT_INPUT_HINTS = ["prompt", "message", "chat", "ask", "assistant"];

// Mark page for quick debugging (visible from DevTools console).
try {
  document.documentElement.dataset.pfActive = "1";
  const v = globalThis?.chrome?.runtime?.getManifest?.()?.version || "";
  document.documentElement.dataset.pfVersion = String(v);
} catch {
  // no-op
}

document.addEventListener(
  "focusin",
  (e) => {
    const el = getEditableFromTarget(e.target);
    if (el) PF_STATE.lastFocusedEditable = el;
  },
  true
);

document.addEventListener(
  "keydown",
  (e) => {
    if (!shouldHandle(e)) return;
    if (e.key !== "Enter" || e.shiftKey || e.altKey || e.ctrlKey || e.metaKey) return;
    if (e.isComposing) return;
    const el = getEditableFromTarget(e.target);
    if (!el || !isLikelyChatInput(el)) return;
    const text = getText(el);
    if (!text.trim()) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    void handleSend({ editable: el, originalText: text, triggerMeta: { type: "enter" } });
  },
  true
);

document.addEventListener(
  "click",
  (e) => {
    if (!shouldHandle(e)) return;
    const btn = getSendButton(e.target);
    if (!btn) return;
    const el = locateBestEditable(btn);
    if (!el || !isLikelyChatInput(el)) return;
    const text = getText(el);
    if (!text.trim()) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    void handleSend({ editable: el, originalText: text, triggerMeta: { type: "button", button: btn } });
  },
  true
);

document.addEventListener(
  "submit",
  (e) => {
    if (!shouldHandle(e)) return;
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    const el = form.querySelector(EDITABLE_SELECTOR) || locateBestEditable(form);
    if (!el || !isLikelyChatInput(el)) return;
    const text = getText(el);
    if (!text.trim()) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    void handleSend({ editable: el, originalText: text, triggerMeta: { type: "form", form } });
  },
  true
);

document.addEventListener(
  "paste",
  (e) => {
    if (!shouldHandle(e)) return;
    const el = getEditableFromTarget(e.target);
    if (!el || !isLikelyChatInput(el) || !e.clipboardData) return;
    const pasted = e.clipboardData.getData("text/plain");
    if (!pasted) return;
    void handlePaste(e, el, pasted);
  },
  true
);

function shouldHandle(e) {
  return e.isTrusted && !PF_STATE.inFlight && Date.now() >= PF_STATE.bypassUntil;
}

// ─────────────────────────────────────────────
//  Core send handler
// ─────────────────────────────────────────────
async function handleSend({ editable, originalText, triggerMeta }) {
  PF_STATE.inFlight = true;
  try {
    // Invisible CAPTCHA: micro-challenge when automation-like behavior is detected.
    const captchaOk = await maybeRequireHumanVerification(originalText);
    if (!captchaOk) {
      toast("Send canceled.");
      await appendResolution({
        action: "CAPTCHA_FAILED",
        risk: 0,
        categories: [],
        counts: {},
        note: "Invisible CAPTCHA challenge not completed.",
      });
      return;
    }

    const resp = await sendMsg({
      type: "CLASSIFY_AND_REDACT",
      payload: { text: originalText, url: location.href, trigger: triggerMeta.type },
    });

    if (!resp?.ok) {
      toast("Prompt Injection Detector: scan failed, sending original.");
      await executeSend(editable, originalText, triggerMeta);
    return;
    }

    const { analysis, decision, redactedText, redactions, policy, injectionResult } = resp;

    // ── Proxy chain ─────────────────────────────────────────────────────
    let textToSend = originalText;
    let proxyHops = null;

    if (policy?.proxyChainEnabled && Array.isArray(policy.proxyChain) && policy.proxyChain.length > 0) {
      // Always send the already-redacted text through hops (may equal original when no findings)
      const proxyInput = redactedText;
      const proxyResp = await sendMsg({
        type: "PROXY_CHAIN_EXECUTE",
        payload: { text: proxyInput, domain: location.hostname },
      });
      if (proxyResp?.ok && !proxyResp.skipped) {
        textToSend = proxyResp.finalText;
        proxyHops = proxyResp.hops;
        const failedHops = proxyResp.hops.filter((h) => !h.skipped && !h.success);
        if (failedHops.length > 0) toast(`${failedHops.length} proxy hop(s) failed — using fallback text.`);
        if (proxyResp.aborted) {
          toast("Proxy chain aborted — send cancelled.");
          return;
        }
      }
    }

    // ── Show injection warning banner if detected ───────────────────────
    if (injectionResult?.detected) {
      showInjectionBanner(injectionResult);
    }

    // ── Dispatch by decision ────────────────────────────────────────────
    if (decision.action === "ALLOW") {
      const finalText = proxyHops ? textToSend : originalText;
      await executeSend(editable, finalText, triggerMeta);
      if (proxyHops) showProxyToast(proxyHops);
      return;
    }

    if (decision.action === "AUTO_REDACT") {
      const finalText = proxyHops ? textToSend : redactedText;
      toast(`Sensitive data redacted (risk ${analysis.risk}/100).`);
      await executeSend(editable, finalText, triggerMeta);
      await storeVaultEntries(redactions);
      await appendResolution({
        action: "AUTO_REDACT_SENT",
        risk: analysis.risk,
        categories: analysis.categories,
        counts: analysis.counts,
        note: "Auto-redacted and sent.",
      });
      if (proxyHops) showProxyToast(proxyHops);
      return;
    }

    // BLOCK ── show modal
    const choice = await showBlockModal({
      analysis,
      redactedText,
      redactions,
      canOverride: decision.canOverride,
      holdMs: policy?.holdToConfirmMs || 2000,
      stepUp: decision.stepUp || null,
      injectionResult,
      proxyHops,
    });

    if (choice === "SEND_REDACTED") {
      const finalText = proxyHops ? textToSend : redactedText;
      await executeSend(editable, finalText, triggerMeta);
      await storeVaultEntries(redactions);
      await appendResolution({
        action: "SEND_REDACTED",
        risk: analysis.risk,
        categories: analysis.categories,
        counts: analysis.counts,
        note: "User chose redacted send.",
      });
      if (proxyHops) showProxyToast(proxyHops);
      return;
    }

    if (choice === "SEND_SAFE_SUBSTITUTED") {
      const substituted = buildSafeSubstitutedText(originalText, redactions || []);
      const finalText = proxyHops ? textToSend : substituted;
      await executeSend(editable, finalText, triggerMeta);
      await storeVaultEntries(redactions);
      await appendResolution({
        action: "SEND_SAFE_SUBSTITUTED",
        risk: analysis.risk,
        categories: analysis.categories,
        counts: analysis.counts,
        note: "User chose safe substitution send.",
      });
      if (proxyHops) showProxyToast(proxyHops);
      return;
    }

    if (choice === "SEND_REWRITE") {
      const rewrite = await sendMsg({ type: "SAFE_REWRITE", payload: { redactedText, categories: analysis.categories || [] } });
      const output = rewrite?.ok && rewrite.rewrittenText ? rewrite.rewrittenText : redactedText;
      const finalText = proxyHops ? textToSend : output;
      await executeSend(editable, finalText, triggerMeta);
      await storeVaultEntries(redactions);
      await appendResolution({
        action: "SEND_REWRITE",
        risk: analysis.risk,
        categories: analysis.categories,
        counts: analysis.counts,
        note: "User chose redacted + safe rewrite.",
      });
      return;
    }

    if (choice === "OVERRIDE_ORIGINAL") {
      if (!decision.canOverride) {
        toast("Override denied by policy for secret-class data.");
        await appendResolution({
          action: "OVERRIDE_DENIED",
          risk: analysis.risk,
          categories: analysis.categories,
          counts: analysis.counts,
          note: "Policy denied secret override.",
        });
        return;
      }
      await executeSend(editable, originalText, triggerMeta);
      await appendResolution({
        action: "OVERRIDE_ORIGINAL",
        risk: analysis.risk,
        categories: analysis.categories,
        counts: analysis.counts,
        note: "User completed step-up and sent original.",
      });
      return;
    }

    toast("Send canceled.");
    await appendResolution({
      action: "CANCELLED",
      risk: analysis.risk,
      categories: analysis.categories,
      counts: analysis.counts,
      note: "User canceled blocked send.",
    });
  } catch {
    toast("Prompt Injection Detector: fallback send.");
    await executeSend(editable, originalText, triggerMeta);
  } finally {
    PF_STATE.inFlight = false;
  }
}

async function handlePaste(event, editable, pastedText) {
  PF_STATE.lastPasteAt = Date.now();
  PF_STATE.pasteBurst = pruneWindow([...PF_STATE.pasteBurst, PF_STATE.lastPasteAt], 1200);

  const resp = await sendMsg({
    type: "CLASSIFY_AND_REDACT",
    payload: { text: pastedText, url: location.href, trigger: "paste" },
  });
  if (!resp?.ok || !resp.policy?.clipboardProtection || resp.decision.action === "ALLOW") return;
  event.preventDefault();
  insertAtCursor(editable, resp.redactedText || pastedText);
  toast(`Paste sanitized (${resp.analysis?.risk || 0}/100).`);
  await storeVaultEntries(resp.redactions || []);
  await appendResolution({
    action: "PASTE_REDACTED",
    risk: resp.analysis?.risk || 0,
    categories: resp.analysis?.categories || [],
    counts: resp.analysis?.counts || {},
    note: "Clipboard protection sanitized paste.",
  });
}

// ─────────────────────────────────────────────
//  Data Vault helper
// ─────────────────────────────────────────────
async function storeVaultEntries(redactions) {
  if (!Array.isArray(redactions) || redactions.length === 0) return;
  const entries = redactions.map((r) => ({ placeholder: r.replacement, category: r.category }));
  await sendMsg({ type: "VAULT_STORE", payload: { entries } });
}

// ─────────────────────────────────────────────
//  Injection warning banner
// ─────────────────────────────────────────────
function showInjectionBanner(injectionResult) {
  const existing = document.getElementById("pf-injection-banner");
  if (existing) existing.remove();

  const signals = (injectionResult.signals || []).map((s) => s.signal.replace(/_/g, " ")).join(", ");
  const banner = document.createElement("div");
  banner.id = "pf-injection-banner";
  banner.style.cssText = [
    "position:fixed",
    "top:0",
    "left:0",
    "right:0",
    "z-index:2147483647",
    "background:#7c2d12",
    "color:#fff",
    "padding:10px 16px",
    "font:13px/1.4 system-ui,sans-serif",
    "display:flex",
    "align-items:center",
    "justify-content:space-between",
    "gap:12px",
    "box-shadow:0 2px 12px rgba(0,0,0,0.4)",
  ].join(";");
  banner.innerHTML = `
    <span><b>Prompt Injection Detected</b> — Signals: ${escHtml(signals)} (score: ${injectionResult.score}/100)</span>
    <button id="pf-banner-close" style="border:0;background:rgba(255,255,255,0.2);color:#fff;padding:4px 10px;border-radius:6px;cursor:pointer;font-weight:600;">Dismiss</button>
  `;
  document.body.appendChild(banner);
  banner.querySelector("#pf-banner-close").addEventListener("click", () => banner.remove());
  setTimeout(() => banner.remove(), 8000);
}

function showProxyToast(hops) {
  const ok = hops.filter((h) => h.success).length;
  const fail = hops.filter((h) => !h.skipped && !h.success).length;
  toast(`Proxy chain: ${ok} hop(s) OK${fail ? `, ${fail} failed (passthrough)` : ""}.`);
}

// ─────────────────────────────────────────────
//  Block modal (extended)
// ─────────────────────────────────────────────
function showBlockModal({ analysis, redactedText, redactions, canOverride, holdMs, stepUp, injectionResult, proxyHops }) {
  return new Promise((resolve) => {
    let timer = null;
    let start = 0;
    let verifyTimer = null;
    let verifyStart = 0;
    let verified = false;

    const step = stepUp && typeof stepUp === "object" && stepUp.required ? stepUp : null;
    const hasRedactions = Array.isArray(redactions) && redactions.length > 0;
    const otpCode = step?.level === 2 ? generateOtpCode() : "";

    const overlay = mk("div", [
      "position:fixed",
      "inset:0",
      "z-index:2147483647",
      "background:rgba(15,23,42,0.65)",
      "display:flex",
      "align-items:center",
      "justify-content:center",
      "padding:20px",
    ]);

    const card = mk("div", [
      "width:min(740px,96vw)",
      "max-height:92vh",
      "overflow:auto",
      "background:#ffffff",
      "color:#111827",
      "border-radius:16px",
      "padding:18px",
      "box-shadow:0 20px 48px rgba(15,23,42,0.35)",
      "font:13px/1.45 system-ui,sans-serif",
    ]);

    const categoryText = (analysis.categories || []).join(", ") || "Unknown";
    const redactionSummary = summarizeRedactions(redactions || []);
    const injectionHtml = injectionResult?.detected
      ? `<div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:10px;padding:8px 10px;margin-bottom:10px;">
           <b style="color:#991b1b;">Prompt Injection:</b>
           <span style="color:#7f1d1d;">${escHtml(
             (injectionResult.signals || []).map((s) => s.signal.replace(/_/g, " ")).join(", ")
           )} (score ${injectionResult.score}/100)</span>
         </div>`
      : "";

    const proxyHtml =
      proxyHops && proxyHops.length > 0
        ? `<div style="background:#f0fdf4;border:1px solid #86efac;border-radius:10px;padding:8px 10px;margin-bottom:10px;font-size:11px;">
           <b style="color:#166534;">Proxy chain:</b> ${proxyHops
             .map(
               (h) =>
                 `<span style="margin-right:6px;padding:1px 6px;border-radius:4px;background:${
                   h.success ? "#bbf7d0" : "#fecaca"
                 };color:${h.success ? "#14532d" : "#7f1d1d"};">
               ${escHtml(h.label || `Hop ${h.index + 1}`)} ${h.latencyMs ? `(${h.latencyMs}ms)` : ""} ${
                   h.success ? "✓" : `✗ ${escHtml(h.error || "")}`
                 }
             </span>`
             )
             .join("")}
         </div>`
        : "";

    const verifyHtml = step
      ? (() => {
          if (step.level === 2) {
            return `<div id="pf-verify-zone" style="margin-bottom:10px;border:1px solid #93c5fd;background:#eff6ff;border-radius:12px;padding:10px;">
              <div style="font-weight:700;font-size:12px;color:#1e3a8a;margin-bottom:6px;">Step-Up L2 verification</div>
              <div style="font-size:12px;color:#1e40af;margin-bottom:8px;">Enter the one-time code to unlock sending:</div>
              <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                <span style="font-family:ui-monospace,monospace;font-weight:800;letter-spacing:0.08em;background:#dbeafe;color:#1e3a8a;padding:6px 10px;border-radius:10px;">${escHtml(
                  otpCode
                )}</span>
                <input id="pf-otp-input" inputmode="numeric" autocomplete="one-time-code" placeholder="Enter code" style="padding:8px 10px;border:1px solid #93c5fd;border-radius:10px;min-width:180px;"/>
                <span id="pf-verify-status" style="font-size:12px;color:#1e3a8a;"></span>
              </div>
            </div>`;
          }
          // L1
          return `<div id="pf-verify-zone" style="margin-bottom:10px;border:1px solid #fcd34d;background:#fffbeb;border-radius:12px;padding:10px;">
            <div style="font-weight:700;font-size:12px;color:#92400e;margin-bottom:6px;">Step-Up L1 verification</div>
            <div style="font-size:12px;color:#78350f;margin-bottom:8px;">Hold for 1.5s or type <b>ALLOW</b> to unlock sending.</div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
              <div style="flex:1;min-width:220px;">
                <div style="height:8px;border-radius:999px;background:#fde68a;overflow:hidden;margin-bottom:8px;">
                  <div id="pf-verify-hold-progress" style="width:0%;height:100%;background:#f59e0b;transition:width 0.05s linear;"></div>
                </div>
                <button id="pf-verify-hold-btn" style="padding:8px 10px;border:0;border-radius:10px;background:#92400e;color:#fff;font-weight:700;cursor:pointer;">Hold to unlock</button>
              </div>
              <div style="display:flex;gap:8px;align-items:center;">
                <input id="pf-verify-input" placeholder="Type ALLOW" style="padding:8px 10px;border:1px solid #fcd34d;border-radius:10px;min-width:180px;"/>
                <span id="pf-verify-status" style="font-size:12px;color:#92400e;"></span>
              </div>
            </div>
          </div>`;
        })()
      : "";

    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:8px;">
        <div style="font-weight:700;font-size:15px;">Prompt Injection Detector blocked this send</div>
        <div style="font-size:12px;background:#111827;color:#fff;padding:4px 8px;border-radius:999px;">Risk ${escHtml(
          String(analysis.risk || 0)
        )}/100</div>
      </div>
      <div style="font-size:12px;color:#4b5563;margin-bottom:10px;">Detected: <b>${escHtml(categoryText)}</b></div>
      ${injectionHtml}
      ${proxyHtml}
      ${verifyHtml}
      <div style="display:grid;gap:10px;margin-bottom:10px;">
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:10px;">
          <div style="font-size:12px;font-weight:600;margin-bottom:6px;">Redaction summary</div>
          <div style="font-size:12px;color:#334155">${escHtml(redactionSummary || "No redactions.")}</div>
        </div>
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:10px;">
          <div style="font-size:12px;font-weight:600;margin-bottom:6px;">Redacted preview</div>
          <pre style="margin:0;white-space:pre-wrap;word-break:break-word;font:12px/1.35 ui-monospace,monospace;color:#0f172a;max-height:200px;overflow:auto;">${escHtml(
            redactedText || ""
          )}</pre>
        </div>
      </div>
      <div id="pf-override-zone" style="display:none;margin-bottom:10px;border:1px solid #f59e0b;background:#fffbeb;border-radius:12px;padding:10px;">
        <div style="font-weight:600;font-size:12px;color:#92400e;margin-bottom:6px;">Step-up required</div>
        <div style="font-size:12px;color:#78350f;margin-bottom:8px;">Hold confirm for ${
          Math.round(holdMs / 100) / 10
        }s to send original.</div>
        <div style="height:8px;border-radius:999px;background:#fde68a;overflow:hidden;margin-bottom:8px;">
          <div id="pf-hold-progress" style="width:0%;height:100%;background:#f59e0b;transition:width 0.05s linear;"></div>
        </div>
        <button id="pf-hold-btn" style="padding:8px 10px;border:0;border-radius:10px;background:#92400e;color:#fff;font-weight:600;cursor:pointer;">Hold to confirm override</button>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end;">
        <button id="pf-cancel" style="padding:8px 10px;border:1px solid #cbd5e1;background:#fff;border-radius:10px;cursor:pointer;">Cancel</button>
        <button id="pf-send-redacted" ${step ? "disabled" : ""} style="padding:8px 10px;border:0;background:#111827;color:#fff;border-radius:10px;cursor:pointer;${step ? "opacity:0.55;cursor:not-allowed;" : ""}">Send redacted</button>
        ${
          hasRedactions
            ? `<button id="pf-send-safe-sub" ${step ? "disabled" : ""} style="padding:8px 10px;border:0;background:#065f46;color:#fff;border-radius:10px;cursor:pointer;${step ? "opacity:0.55;cursor:not-allowed;" : ""}">Send safe substituted</button>`
            : ""
        }
        <button id="pf-send-rewrite" ${step ? "disabled" : ""} style="padding:8px 10px;border:0;background:#1d4ed8;color:#fff;border-radius:10px;cursor:pointer;${step ? "opacity:0.55;cursor:not-allowed;" : ""}">Send + safe rewrite</button>
        ${
          canOverride
            ? `<button id="pf-request-override" ${step ? "disabled" : ""} style="padding:8px 10px;border:1px solid #f59e0b;background:#fffbeb;color:#92400e;border-radius:10px;cursor:pointer;${step ? "opacity:0.55;cursor:not-allowed;" : ""}">Send original (step-up)</button>`
            : '<button disabled style="padding:8px 10px;border:1px solid #e2e8f0;background:#f8fafc;color:#94a3b8;border-radius:10px;">Override disabled</button>'
        }
      </div>
    `;

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    const cleanup = () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      if (verifyTimer) {
        clearInterval(verifyTimer);
        verifyTimer = null;
      }
      window.removeEventListener("keydown", onEsc, true);
      overlay.remove();
    };
    const done = (choice) => {
      cleanup();
      resolve(choice);
    };
    const onEsc = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        done("CANCEL");
      }
    };

    window.addEventListener("keydown", onEsc, true);
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) done("CANCEL");
    });
    card.querySelector("#pf-cancel")?.addEventListener("click", () => done("CANCEL"));
    card.querySelector("#pf-send-redacted")?.addEventListener("click", () => (step && !verified ? null : done("SEND_REDACTED")));
    card.querySelector("#pf-send-safe-sub")?.addEventListener("click", () => (step && !verified ? null : done("SEND_SAFE_SUBSTITUTED")));
    card.querySelector("#pf-send-rewrite")?.addEventListener("click", () => (step && !verified ? null : done("SEND_REWRITE")));

    const overrideBtn = card.querySelector("#pf-request-override");
    const zone = card.querySelector("#pf-override-zone");
    const holdBtn = card.querySelector("#pf-hold-btn");
    const progress = card.querySelector("#pf-hold-progress");

    const sendBtns = [
      card.querySelector("#pf-send-redacted"),
      card.querySelector("#pf-send-safe-sub"),
      card.querySelector("#pf-send-rewrite"),
      overrideBtn,
    ].filter(Boolean);

    const setVerified = () => {
      verified = true;
      const status = card.querySelector("#pf-verify-status");
      if (status) status.textContent = "Unlocked ✓";
      for (const b of sendBtns) {
        b.disabled = false;
        b.style.opacity = "";
        b.style.cursor = "";
      }
      const v = card.querySelector("#pf-verify-zone");
      if (v) v.style.display = "none";
    };

    // Step-up verification handlers
    if (step) {
      if (step.level === 2) {
        const input = card.querySelector("#pf-otp-input");
        const status = card.querySelector("#pf-verify-status");
        if (input) {
          input.addEventListener("input", () => {
            const v = String(input.value || "").replace(/\s+/g, "");
            if (v.length >= 6) {
              if (v === otpCode) setVerified();
              else if (status) status.textContent = "Incorrect code";
            }
          });
        }
      } else {
        const vInput = card.querySelector("#pf-verify-input");
        const vHoldBtn = card.querySelector("#pf-verify-hold-btn");
        const vProgress = card.querySelector("#pf-verify-hold-progress");
        const vStatus = card.querySelector("#pf-verify-status");

        const resetVerifyHold = () => {
          if (verifyTimer) {
            clearInterval(verifyTimer);
            verifyTimer = null;
          }
          verifyStart = 0;
          if (vProgress) vProgress.style.width = "0%";
        };
        const startVerifyHold = () => {
          if (!vHoldBtn || !vProgress) return;
          resetVerifyHold();
          verifyStart = Date.now();
          const unlockMs = 1500;
          verifyTimer = setInterval(() => {
            const pct = Math.min(1, (Date.now() - verifyStart) / unlockMs);
            vProgress.style.width = `${Math.round(pct * 100)}%`;
            if (pct >= 1) {
              resetVerifyHold();
              setVerified();
            }
          }, 24);
        };

        if (vHoldBtn) {
          vHoldBtn.addEventListener("mousedown", startVerifyHold);
          vHoldBtn.addEventListener("touchstart", startVerifyHold, { passive: true });
          vHoldBtn.addEventListener("mouseup", resetVerifyHold);
          vHoldBtn.addEventListener("mouseleave", resetVerifyHold);
          vHoldBtn.addEventListener("touchend", resetVerifyHold);
          vHoldBtn.addEventListener("touchcancel", resetVerifyHold);
        }

        if (vInput) {
          vInput.addEventListener("input", () => {
            const v = String(vInput.value || "").trim().toUpperCase();
            if (v === "ALLOW") setVerified();
            else if (v.length >= 5 && vStatus) vStatus.textContent = "Type ALLOW";
          });
        }
      }
    }

    const resetHold = () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      start = 0;
      if (progress) progress.style.width = "0%";
    };
    const startHold = () => {
      if (!holdBtn || !progress) return;
      resetHold();
      start = Date.now();
      timer = setInterval(() => {
        const pct = Math.min(1, (Date.now() - start) / holdMs);
        progress.style.width = `${Math.round(pct * 100)}%`;
        if (pct >= 1) {
          resetHold();
          done("OVERRIDE_ORIGINAL");
        }
      }, 24);
    };

    if (overrideBtn && zone) {
      overrideBtn.addEventListener("click", () => {
        if (step && !verified) return;
        zone.style.display = "block";
      });
    }
    if (holdBtn) {
      holdBtn.addEventListener("mousedown", startHold);
      holdBtn.addEventListener("touchstart", startHold, { passive: true });
      holdBtn.addEventListener("mouseup", resetHold);
      holdBtn.addEventListener("mouseleave", resetHold);
      holdBtn.addEventListener("touchend", resetHold);
      holdBtn.addEventListener("touchcancel", resetHold);
    }
  });
}

// ─────────────────────────────────────────────
//  DOM helpers
// ─────────────────────────────────────────────
function mk(tag, styles) {
  const el = document.createElement(tag);
  el.style.cssText = Array.isArray(styles) ? styles.join(";") : styles;
  return el;
}

function getEditableFromTarget(target) {
  if (!(target instanceof Element)) return null;
  if (isEditable(target)) return target;
  return target.closest(EDITABLE_SELECTOR);
}

function isEditable(el) {
  if (!(el instanceof Element)) return false;
  if (el.matches("textarea")) return !el.hasAttribute("disabled") && !el.hasAttribute("readonly");
  return el.getAttribute("contenteditable") === "true" || el.getAttribute("contenteditable") === "plaintext-only";
}

function isLikelyChatInput(el) {
  if (!isEditable(el)) return false;
  const host = location.hostname.toLowerCase();
  if (CHAT_HOST_HINTS.some((h) => host === h || host.endsWith(`.${h}`))) return true;
  const attrs = [el.id, el.getAttribute("name"), el.getAttribute("aria-label"), el.getAttribute("placeholder")]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (CHAT_INPUT_HINTS.some((h) => attrs.includes(h))) return true;
  const nearby = (el.closest("form, section, main, div")?.textContent || "").slice(0, 500).toLowerCase();
  return CHAT_INPUT_HINTS.some((h) => nearby.includes(h));
}

function getText(el) {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) return el.value || "";
  return (el.innerText || "").replace(/\u00a0/g, " ");
}

function setText(el, text) {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
    el.value = text;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    return;
  }
  el.textContent = text;
  el.dispatchEvent(new Event("input", { bubbles: true }));
}

function getSendButton(target) {
  if (!(target instanceof Element)) return null;
  const btn = target.closest('button, [role="button"], input[type="submit"]');
  if (!btn || !looksLikeSend(btn)) return null;
  return btn;
}

function looksLikeSend(btn) {
  if (btn.matches('[data-testid="send-button"]')) return true;
  const text = [
    btn.getAttribute("aria-label"),
    btn.getAttribute("title"),
    btn.textContent,
    btn.getAttribute("data-testid"),
    btn.getAttribute("name"),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return /(send|submit|run|ask|arrow up|paper airplane|upward)/.test(text);
}

function locateBestEditable(anchor) {
  if (PF_STATE.lastFocusedEditable && document.contains(PF_STATE.lastFocusedEditable)) return PF_STATE.lastFocusedEditable;
  if (anchor instanceof Element) {
    const form = anchor.closest("form");
    if (form) {
      const el = form.querySelector(EDITABLE_SELECTOR);
      if (el) return el;
    }
    const container = anchor.closest("section, main, article, div");
    if (container) {
      const el = container.querySelector(EDITABLE_SELECTOR);
      if (el) return el;
    }
  }
  return document.querySelector(EDITABLE_SELECTOR);
}

function insertAtCursor(el, text) {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
    const s = el.selectionStart ?? el.value.length;
    const e = el.selectionEnd ?? el.value.length;
    el.value = el.value.slice(0, s) + text + el.value.slice(e);
    el.selectionStart = el.selectionEnd = s + text.length;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    return;
  }
  el.focus();
  if (!document.execCommand("insertText", false, text)) setText(el, getText(el) + text);
}

async function executeSend(editable, text, triggerMeta) {
  setText(editable, text);
  await new Promise((r) => setTimeout(r, 16));
  PF_STATE.bypassUntil = Date.now() + 700;

  if (triggerMeta.type === "button" && triggerMeta.button?.isConnected) {
    triggerMeta.button.click();
    return;
  }
  if (triggerMeta.type === "form" && triggerMeta.form?.isConnected) {
    triggerMeta.form.requestSubmit();
    return;
  }
  if (clickKnownSend()) return;

  for (const type of ["keydown", "keyup"]) {
    editable.dispatchEvent(new KeyboardEvent(type, { key: "Enter", code: "Enter", bubbles: true, cancelable: true }));
  }
  const form = editable.closest("form");
  if (form) form.requestSubmit();
}

function clickKnownSend() {
  const selectors = [
    'button[data-testid="send-button"]',
    'button[aria-label*="Send" i]',
    'button[aria-label*="Submit" i]',
    'button[title*="Send" i]',
    'button[aria-label*="Run" i]',
    'button[type="submit"]',
  ];
  for (const sel of selectors) {
    const candidates = Array.from(document.querySelectorAll(sel));
    const target = candidates.find((el) => {
      if (!(el instanceof HTMLElement)) return false;
      if ((el instanceof HTMLButtonElement || el instanceof HTMLInputElement) && el.disabled) return false;
      const r = el.getBoundingClientRect();
      if (r.width < 6 || r.height < 6) return false;
      const s = getComputedStyle(el);
      return s.visibility !== "hidden" && s.display !== "none" && s.pointerEvents !== "none";
    });
    if (target) {
      target.click();
      return true;
    }
  }
  return false;
}

// ─────────────────────────────────────────────
//  Messaging / utils
// ─────────────────────────────────────────────
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

async function appendResolution(payload) {
  await sendMsg({
    type: "LEDGER_APPEND",
    payload: { ...payload, domain: location.hostname, trigger: "content_resolution", eventType: "user_resolution" },
  });
}

function toast(message, durationMs = 2800) {
  const node = document.createElement("div");
  node.textContent = message;
  node.style.cssText = [
    "position:fixed",
    "right:16px",
    "bottom:16px",
    "z-index:2147483647",
    "padding:10px 14px",
    "border-radius:10px",
    "font:12px/1.3 system-ui,sans-serif",
    "background:#111827",
    "color:#f9fafb",
    "box-shadow:0 8px 20px rgba(0,0,0,0.3)",
    "opacity:0.98",
    "max-width:380px",
    "word-wrap:break-word",
  ].join(";");
  document.body.appendChild(node);
  setTimeout(() => node.remove(), durationMs);
}

function summarizeRedactions(redactions) {
  if (!Array.isArray(redactions) || redactions.length === 0) return "";
  const counts = {};
  for (const r of redactions) counts[r.category] = (counts[r.category] || 0) + 1;
  return Object.entries(counts)
    .map(([k, v]) => `${k}: ${v}`)
    .join(" • ");
}

// ─────────────────────────────────────────────
//  Invisible CAPTCHA (behavioral micro-challenge)
// ─────────────────────────────────────────────
function pruneWindow(timestamps, windowMs) {
  const now = Date.now();
  return (Array.isArray(timestamps) ? timestamps : []).filter((t) => Number.isFinite(t) && now - t <= windowMs);
}

function fnv1a32(str) {
  let h = 0x811c9dc5;
  const s = String(str || "");
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function generateCaptchaCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  let x = buf[0] >>> 0;
  let out = "";
  for (let i = 0; i < 4; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out += alphabet[(x >>> 0) % alphabet.length];
  }
  return out;
}

async function maybeRequireHumanVerification(text) {
  const now = Date.now();

  PF_STATE.sendBurst = pruneWindow([...PF_STATE.sendBurst, now], 2500);
  const h = String(fnv1a32(String(text || "").trim().slice(0, 2500)));
  if (h === PF_STATE.lastSendHash && now - PF_STATE.lastSendAt < 1500) PF_STATE.repeatSendCount++;
  else PF_STATE.repeatSendCount = 0;
  PF_STATE.lastSendHash = h;
  PF_STATE.lastSendAt = now;

  if (now < PF_STATE.humanVerifiedUntil) return true;

  const fastAfterPaste = PF_STATE.lastPasteAt > 0 && now - PF_STATE.lastPasteAt < 300;
  const burstSends = PF_STATE.sendBurst.length >= 5;
  const repeats = PF_STATE.repeatSendCount >= 3;
  const suspicious = burstSends || repeats || fastAfterPaste;
  if (!suspicious) return true;

  const reason = burstSends
    ? "rapid sends"
    : repeats
      ? "repeated prompt pattern"
      : fastAfterPaste
        ? "paste-to-send too fast"
        : "behavioral signal";

  const ok = await showMicroChallengeModal({ reason });
  if (ok) {
    PF_STATE.humanVerifiedUntil = Date.now() + 60_000;
    toast("Human verification passed.");
    await appendResolution({
      action: "CAPTCHA_PASSED",
      risk: 0,
      categories: [],
      counts: {},
      note: `Invisible CAPTCHA passed (${reason}).`,
    });
  }
  return ok;
}

function showMicroChallengeModal({ reason }) {
  return new Promise((resolve) => {
    let timer = null;
    let start = 0;
    const code = generateCaptchaCode();

    const overlay = mk("div", [
      "position:fixed",
      "inset:0",
      "z-index:2147483647",
      "background:rgba(15,23,42,0.65)",
      "display:flex",
      "align-items:center",
      "justify-content:center",
      "padding:20px",
    ]);

    const card = mk("div", [
      "width:min(520px,96vw)",
      "background:#ffffff",
      "color:#111827",
      "border-radius:16px",
      "padding:16px",
      "box-shadow:0 20px 48px rgba(15,23,42,0.35)",
      "font:13px/1.45 system-ui,sans-serif",
    ]);

    card.innerHTML = `
      <div style="font-weight:800;font-size:14px;margin-bottom:6px;">Human verification</div>
      <div style="font-size:12px;color:#475569;margin-bottom:10px;">Triggered by: <b>${escHtml(reason || "behavior")}</b></div>
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:10px;margin-bottom:10px;">
        <div style="font-size:12px;font-weight:700;margin-bottom:6px;">Micro-challenge</div>
        <div style="font-size:12px;color:#334155;margin-bottom:8px;">Hold for <b>1.5s</b> or type this code:</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <div style="flex:1;min-width:220px;">
            <div style="height:8px;border-radius:999px;background:#e2e8f0;overflow:hidden;margin-bottom:8px;">
              <div id="pf-mc-progress" style="width:0%;height:100%;background:#111827;transition:width 0.05s linear;"></div>
      </div>
            <button id="pf-mc-hold" style="padding:8px 10px;border:0;border-radius:10px;background:#111827;color:#fff;font-weight:700;cursor:pointer;">Hold to verify</button>
        </div>
          <span style="font-family:ui-monospace,monospace;font-weight:900;background:#e2e8f0;color:#111827;padding:6px 10px;border-radius:10px;letter-spacing:0.08em;">${escHtml(
            code
          )}</span>
          <input id="pf-mc-input" placeholder="Type code" style="padding:8px 10px;border:1px solid #cbd5e1;border-radius:10px;min-width:160px;"/>
        </div>
        <div id="pf-mc-status" style="margin-top:8px;font-size:12px;color:#475569;"></div>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;">
        <button id="pf-mc-cancel" style="padding:8px 10px;border:1px solid #cbd5e1;background:#fff;border-radius:10px;cursor:pointer;">Cancel</button>
      </div>
    `;

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    const cleanup = () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      window.removeEventListener("keydown", onEsc, true);
      overlay.remove();
    };

    const done = (ok) => {
      cleanup();
      resolve(Boolean(ok));
    };

    const onEsc = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        done(false);
      }
    };

    window.addEventListener("keydown", onEsc, true);
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) done(false);
    });
    card.querySelector("#pf-mc-cancel")?.addEventListener("click", () => done(false));

    const progress = card.querySelector("#pf-mc-progress");
    const holdBtn = card.querySelector("#pf-mc-hold");
    const input = card.querySelector("#pf-mc-input");
    const status = card.querySelector("#pf-mc-status");

    const resetHold = () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
      start = 0;
      if (progress) progress.style.width = "0%";
    };
    const startHold = () => {
      if (!holdBtn || !progress) return;
      resetHold();
      start = Date.now();
      const holdMs = 1500;
      timer = setInterval(() => {
        const pct = Math.min(1, (Date.now() - start) / holdMs);
        progress.style.width = `${Math.round(pct * 100)}%`;
        if (pct >= 1) {
          resetHold();
          done(true);
        }
      }, 24);
    };

    if (holdBtn) {
      holdBtn.addEventListener("mousedown", startHold);
      holdBtn.addEventListener("touchstart", startHold, { passive: true });
      holdBtn.addEventListener("mouseup", resetHold);
      holdBtn.addEventListener("mouseleave", resetHold);
      holdBtn.addEventListener("touchend", resetHold);
      holdBtn.addEventListener("touchcancel", resetHold);
    }

    if (input) {
      input.addEventListener("input", () => {
        const v = String(input.value || "").trim().toUpperCase();
        if (v.length >= 4) {
          if (v === code) done(true);
          else if (status) status.textContent = "Incorrect code";
        }
      });
    }
  });
}

// ─────────────────────────────────────────────
//  Safe substitution (format-preserving redaction)
// ─────────────────────────────────────────────
function seededChars(seed, alphabet, len) {
  let x = (seed >>> 0) || 1;
  let out = "";
  const a = String(alphabet || "abcdefghijklmnopqrstuvwxyz0123456789");
  for (let i = 0; i < len; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out += a[(x >>> 0) % a.length];
  }
  return out;
}

function generateOtpCode() {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  const n = (buf[0] >>> 0) % 1_000_000;
  return String(n).padStart(6, "0");
}

function buildSafeSubstitutedText(originalText, redactions) {
  const list = Array.isArray(redactions) ? [...redactions] : [];
  if (list.length === 0) return String(originalText || "");
  list.sort((a, b) => (a.start || 0) - (b.start || 0));

  const text = String(originalText || "");
  let cursor = 0;
  let out = "";

  for (const r of list) {
    const start = Number.isFinite(r.start) ? r.start : -1;
    const end = Number.isFinite(r.end) ? r.end : -1;
    if (start < 0 || end <= start || start > text.length) continue;
    out += text.slice(cursor, start);
    const raw = text.slice(start, Math.min(end, text.length));
    out += getSafeSubstitution(String(r.category || "UNKNOWN"), raw);
    cursor = Math.min(end, text.length);
  }
  out += text.slice(cursor);
  return out;
}

function getSafeSubstitution(category, raw) {
  const cat = String(category || "UNKNOWN").toUpperCase();
  const seed = fnv1a32(raw);
  const key = `${cat}:${seed}`;
  if (PF_STATE.substitutionCache.has(key)) return PF_STATE.substitutionCache.get(key);

  PF_STATE.substitutionSerial[cat] = (PF_STATE.substitutionSerial[cat] || 0) + 1;
  const idx = PF_STATE.substitutionSerial[cat];
  const value = generateFakeForCategory(cat, raw, idx, seed);
  PF_STATE.substitutionCache.set(key, value);
  return value;
}

function generateFakeForCategory(category, raw, idx, seed) {
  const s = String(raw || "");

  if (category === "EMAIL") {
    const at = s.indexOf("@");
    const tld = at >= 0 ? (s.slice(at + 1).split(".").pop() || "com") : "com";
    return `user_${idx}@company.${tld.replace(/[^a-z]/gi, "") || "com"}`.toLowerCase();
  }

  if (category === "PHONE") {
    const digits = s.replace(/\D/g, "");
    const want = Math.max(10, Math.min(15, digits.length || 10));
    const tail = String(1000 + (idx % 9000)).padStart(4, "0");
    const replacementDigits = (`555000${tail}` + seededChars(seed ^ idx, "0123456789", want)).slice(0, want);
    let j = 0;
    return s.replace(/\d/g, () => replacementDigits[j++] ?? "0");
  }

  if (category === "SSN") {
    return `123-45-${String(6700 + (idx % 999)).padStart(4, "0")}`;
  }

  if (category === "FINANCIAL") {
    const digits = s.replace(/\D/g, "");
    const len = Math.max(13, Math.min(19, digits.length || 16));
    const card = generateLuhnNumber(len, seed ^ (idx * 97));
    return applyDigitMask(s, card);
  }

  if (category === "IP_ADDRESS") {
    return `192.0.2.${(idx % 250) + 1}`;
  }

  if (category === "PASSPORT") {
    const letters = (s.match(/^[A-Z]{1,2}/) || ["P"])[0];
    const digitsLen = Math.max(6, Math.min(9, s.replace(/[^0-9]/g, "").length || 7));
    const digits = seededChars(seed ^ idx, "0123456789", digitsLen);
    return `${letters}${digits}`;
  }

  if (category === "DATE_OF_BIRTH") {
    // Preserve delimiter style if possible.
    const delim = s.includes("-") ? "-" : "/";
    return `DOB: 01${delim}01${delim}1990`;
  }

  if (category === "ADDRESS") {
    return `123 Example St`;
  }

  if (category === "JWT") {
    const parts = s.split(".");
    if (parts.length === 3) {
      const a = seededChars(seed ^ 1, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", Math.max(10, parts[0].length));
      const b = seededChars(seed ^ 2, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", Math.max(10, parts[1].length));
      const c = seededChars(seed ^ 3, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", Math.max(16, parts[2].length));
      // Keep typical JWT header prefix to preserve shape.
      const header = a.startsWith("eyJ") ? a : `eyJ${a.slice(3)}`;
      return `${header}.${b}.${c}`;
    }
    const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const payload = seededChars(seed ^ idx, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 48);
    const sig = seededChars(seed ^ (idx * 13), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", 43);
    return `${header}.${payload}.${sig}`;
  }

  if (category === "PRIVATE_KEY") {
    const lines = s.split(/\r?\n/);
    const beginIdx = lines.findIndex((l) => /-----BEGIN .*PRIVATE KEY-----/.test(l));
    const endIdx = lines.findIndex((l) => /-----END .*PRIVATE KEY-----/.test(l));
    const begin = beginIdx >= 0 ? lines[beginIdx] : "-----BEGIN PRIVATE KEY-----";
    const end = endIdx >= 0 ? lines[endIdx] : "-----END PRIVATE KEY-----";
    const bodyLines = Math.max(6, Math.min(18, endIdx > beginIdx ? endIdx - beginIdx - 1 : 10));
    const body = Array.from({ length: bodyLines }, (_v, i) =>
      seededChars(seed ^ (idx * 31) ^ i, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 64)
    );
    return [begin, ...body, end].join("\n");
  }

  if (category === "SECRET") {
    if (/^AKIA[0-9A-Z]{16}$/.test(s)) {
      return `AKIA${seededChars(seed ^ idx, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 16)}`;
    }
    if (/^AIza[0-9A-Za-z\-_]{35}$/.test(s)) {
      return `AIza${seededChars(seed ^ idx, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_", 35)}`;
    }
    if (/^(sk|rk)_(live|test)_[A-Za-z0-9]{16,}$/.test(s)) {
      const prefix = s.split("_").slice(0, 3).join("_");
      const restLen = Math.max(16, s.length - (prefix.length + 1));
      return `${prefix}_${seededChars(seed ^ idx, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", restLen)}`;
    }
    // Generic token: preserve length + rough prefix/suffix.
    if (s.length >= 12) {
      const head = s.slice(0, 4);
      const tail = s.slice(-4);
      const mid = seededChars(seed ^ idx, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_", Math.max(0, s.length - 8));
      return `${head}${mid}${tail}`;
    }
    return `SAFE_SECRET_${idx}`;
  }

  // Fallback: preserve length-ish for unknown categories
  if (s.length >= 6) {
    return seededChars(seed ^ idx, "abcdefghijklmnopqrstuvwxyz0123456789", s.length);
  }
  return `safe_${category.toLowerCase()}_${idx}`;
}

function applyDigitMask(template, digits) {
  const src = String(digits || "").replace(/\D/g, "");
  let j = 0;
  const t = String(template || "");
  if (!t) return src;
  return t.replace(/\d/g, () => src[j++] ?? "0");
}

function generateLuhnNumber(len, seed) {
  const n = Math.max(13, Math.min(19, Number(len) || 16));
  const bodyLen = n - 1;
  const body = seededChars(seed, "0123456789", bodyLen);
  const check = luhnCheckDigit(body);
  return `${body}${check}`;
}

function luhnCheckDigit(bodyDigits) {
  const s = String(bodyDigits || "").replace(/\D/g, "");
  let sum = 0;
  let alternate = true; // because check digit is appended
  for (let i = s.length - 1; i >= 0; i--) {
    let n = s.charCodeAt(i) - 48;
    if (n < 0 || n > 9) n = 0;
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return (10 - (sum % 10)) % 10;
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

