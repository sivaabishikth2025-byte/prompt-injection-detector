/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Policy Breaker (TypeScript reference)
 *
 * Note: this repo runs plain JS in MV3 service worker.
 * The runtime implementation lives in `effectivePolicy.js`.
 */

export type EffectivePolicyResult = {
  effectivePolicy: any;
  managedPresent: boolean;
  lockedKeys: string[];
  managedBaseline: any;
};

export async function getEffectivePolicy(): Promise<EffectivePolicyResult> {
  throw new Error("Use runtime module effectivePolicy.js");
}

export function runMergeTests(): void {
  // implemented in effectivePolicy.js
}

