import { DEFAULT_POLICY } from "./defaultPolicy.js";

/**
 * Policy Breaker: DEFAULT_POLICY + managed baseline + user local => effective policy.
 *
 * @returns {Promise<{effectivePolicy: any, managedPresent: boolean, lockedKeys: string[], managedBaseline: any}>}
 */
export async function getEffectivePolicy() {
  ensureCacheHooks();
  if (_cacheValue) return _cacheValue;
  if (_cachePromise) return _cachePromise;
  _cachePromise = computeEffectivePolicy()
    .then((v) => {
      _cacheValue = v;
      _cachePromise = null;
      return v;
    })
    .catch(() => {
      _cachePromise = null;
      const fallback = {
        effectivePolicy: { ...DEFAULT_POLICY },
        managedPresent: false,
        lockedKeys: [],
        managedBaseline: {},
      };
      _cacheValue = fallback;
      return fallback;
    });
  return _cachePromise;
}

export function runMergeTests() {
  const base = structuredCloneSafe(DEFAULT_POLICY);
  const managed = {
    denyDomains: ["blocked.example.com"],
    requiredDetectors: ["JWT"],
    maxThresholds: { riskBlockThreshold: 50 },
    overrideMode: "ALLOW_STRICTER_ONLY",
  };
  const local = {
    allowlistDomains: ["blocked.example.com"],
    riskBlockThreshold: 95,
    enabledDetectors: ["EMAIL"],
  };

  const merged = mergePolicy(base, managed, local);
  console.assert(
    merged.effectivePolicy.denyDomains.includes("blocked.example.com"),
    "managed denyDomains cannot be removed"
  );
  console.assert(merged.effectivePolicy.riskBlockThreshold <= 50, "thresholds are clamped to max");
  console.assert(
    merged.effectivePolicy.enabledDetectors.includes("JWT"),
    "requiredDetectors always included"
  );
}

const DEBUG = false;
if (DEBUG) runMergeTests();

let _cacheValue = null;
let _cachePromise = null;
let _hooksInstalled = false;

function ensureCacheHooks() {
  if (_hooksInstalled) return;
  _hooksInstalled = true;

  if (chrome?.storage?.onChanged?.addListener) {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "managed") {
        invalidateCache();
        return;
      }
      if (area === "local" && (changes.policy || changes.enterprise)) {
        invalidateCache();
      }
    });
  }
}

function invalidateCache() {
  _cacheValue = null;
  _cachePromise = null;
}

async function computeEffectivePolicy() {
  const [managedBaseline, localPolicy] = await Promise.all([readManaged(), readLocalPolicy()]);
  const managedPresent = hasManagedBaseline(managedBaseline);
  const lockedKeys = normalizeStringArray(managedBaseline.lockedKeys);
  const merged = mergePolicy(structuredCloneSafe(DEFAULT_POLICY), managedBaseline, localPolicy);

  return {
    effectivePolicy: merged.effectivePolicy,
    managedPresent,
    lockedKeys,
    managedBaseline: managedBaseline || {},
  };
}

async function readManaged() {
  try {
    if (!chrome?.storage?.managed?.get) return {};
    return await chrome.storage.managed.get(null);
  } catch {
    return {};
  }
}

async function readLocalPolicy() {
  try {
    const { policy } = await chrome.storage.local.get("policy");
    return policy && typeof policy === "object" ? policy : {};
  } catch {
    return {};
  }
}

function hasManagedBaseline(managed) {
  if (!managed || typeof managed !== "object") return false;
  const keys = [
    "tenantId",
    "policyVersion",
    "lockedKeys",
    "overrideMode",
    "requiredDetectors",
    "denyDomains",
    "allowlistDomains",
    "enforceOnlyOnDomains",
    "minThresholds",
    "maxThresholds",
    "telemetryMode",
  ];
  return keys.some((k) => managed[k] !== undefined && managed[k] !== null && `${managed[k]}` !== "");
}

function mergePolicy(defaultPolicy, managedBaseline, localPolicy) {
  const managed = managedBaseline && typeof managedBaseline === "object" ? managedBaseline : {};
  const local = localPolicy && typeof localPolicy === "object" ? localPolicy : {};

  const overrideMode = String(managed.overrideMode || "ALLOW_STRICTER_ONLY").toUpperCase();
  const lockedKeys = new Set(normalizeStringArray(managed.lockedKeys));

  // Start from default, then apply local (user UI still edits this), then enforce org constraints.
  const effective = { ...defaultPolicy, ...local };

  // Domains: union (deny always wins in enforcement; locking applied later)
  effective.denyDomains = unionDomains(managed.denyDomains, local.denyDomains);
  effective.allowlistDomains = unionDomains(managed.allowlistDomains, local.allowlistDomains);

  // enforceOnlyOnDomains: managed-only gate
  effective.enforceOnlyOnDomains = normalizeDomainList(managed.enforceOnlyOnDomains);

  // Detectors: union required + user extras (does not disable implicit/hardcoded detectors)
  const required = normalizeStringArray(managed.requiredDetectors);
  const userExtras = normalizeStringArray(local.enabledDetectors || local.userExtraDetectors);
  effective.enabledDetectors = unionStrings(required, userExtras);

  // Threshold bounds
  const minT = managed.minThresholds && typeof managed.minThresholds === "object" ? managed.minThresholds : {};
  const maxT = managed.maxThresholds && typeof managed.maxThresholds === "object" ? managed.maxThresholds : {};

  effective.riskBlockThreshold = mergeThreshold({
    key: "riskBlockThreshold",
    defaultValue: defaultPolicy.riskBlockThreshold,
    userValue: local.riskBlockThreshold,
    managedMin: minT.riskBlockThreshold,
    managedMax: maxT.riskBlockThreshold,
    overrideMode,
  });

  effective.riskAutoRedactThreshold = mergeThreshold({
    key: "riskAutoRedactThreshold",
    defaultValue: defaultPolicy.riskAutoRedactThreshold,
    userValue: local.riskAutoRedactThreshold,
    managedMin: minT.riskAutoRedactThreshold,
    managedMax: maxT.riskAutoRedactThreshold,
    overrideMode,
    // Auto-redact must be < block threshold
    upperCap: Math.max(1, effective.riskBlockThreshold - 1),
  });

  effective.holdToConfirmMs = mergeThreshold({
    key: "holdToConfirmMs",
    defaultValue: defaultPolicy.holdToConfirmMs,
    userValue: local.holdToConfirmMs,
    managedMin: minT.holdToConfirmMs,
    managedMax: maxT.holdToConfirmMs,
    overrideMode,
    minFallback: 800,
    maxFallback: 7000,
  });

  // Partial key locking: managed value overrides local
  for (const key of lockedKeys) {
    if (managed[key] === undefined) continue;
    effective[key] = managed[key];
  }

  // Managed denies always win: if allowlist overlaps deny, deny is kept (enforcement must check deny first).
  effective.allowlistDomains = normalizeDomainList(effective.allowlistDomains);
  effective.denyDomains = normalizeDomainList(effective.denyDomains);

  return {
    effectivePolicy: effective,
    managedPresent: hasManagedBaseline(managed),
    lockedKeys: Array.from(lockedKeys),
    managedBaseline: managed,
  };
}

function mergeThreshold({
  key,
  defaultValue,
  userValue,
  managedMin,
  managedMax,
  overrideMode,
  upperCap,
  minFallback = 1,
  maxFallback = 100,
}) {
  const base = clampNumber(defaultValue, minFallback, maxFallback, defaultValue);
  const user = Number.isFinite(Number(userValue)) ? Number(userValue) : base;

  const minB = Number.isFinite(Number(managedMin)) ? Number(managedMin) : minFallback;
  const maxBFromManaged = Number.isFinite(Number(managedMax)) ? Number(managedMax) : undefined;

  let maxB = maxBFromManaged ?? maxFallback;
  if (String(overrideMode) === "ALLOW_STRICTER_ONLY") {
    // Security-first: without an org max, do not allow user to weaken beyond default.
    maxB = Math.min(maxB, maxBFromManaged ?? base);
  }

  let out = clampNumber(user, minB, maxB, base);
  if (Number.isFinite(Number(upperCap))) out = Math.min(out, Number(upperCap));
  return Math.round(out);
}

function unionDomains(a, b) {
  return unionStrings(normalizeDomainList(a), normalizeDomainList(b));
}

function unionStrings(a, b) {
  return Array.from(new Set([...(Array.isArray(a) ? a : []), ...(Array.isArray(b) ? b : [])].filter(Boolean)));
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) return [];
  return Array.from(
    new Set(
      value
        .map((v) => String(v || "").trim())
        .filter(Boolean)
    )
  );
}

function normalizeDomainList(value) {
  if (!Array.isArray(value)) return [];
  const out = new Set();
  for (const item of value) {
    const d = String(item || "").trim().toLowerCase();
    if (!d) continue;
    out.add(stripPort(stripSchemeAndPath(d)));
  }
  return Array.from(out);
}

function stripSchemeAndPath(value) {
  return String(value || "")
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "");
}

function stripPort(domain) {
  return String(domain || "").split(":")[0];
}

function clampNumber(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function structuredCloneSafe(obj) {
  try {
    return structuredClone(obj);
  } catch {
    return JSON.parse(JSON.stringify(obj));
  }
}

