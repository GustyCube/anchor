export type VerificationDecision = "AUTHORIZED" | "REJECTED";
export type ReplayStatus = "UNKNOWN" | "FRESH" | "REPLAY";
export type ReasonCode =
  | "ERR_REFERENCE_TIME_MISSING"
  | "ERR_ISSUER_MISMATCH"
  | "ERR_CAPABILITY_INVALID"
  | "ERR_CAPABILITY_SIGNATURE_INVALID"
  | "ERR_CAPABILITY_NOT_YET_VALID"
  | "ERR_CAPABILITY_EXPIRED"
  | "ERR_CAPABILITY_REVOKED"
  | "ERR_AGENT_MISMATCH"
  | "ERR_ACTION_INVALID"
  | "ERR_ACTION_SIGNATURE_INVALID"
  | "ERR_CAPABILITY_BINDING_MISMATCH"
  | "ERR_ACTION_NOT_ALLOWED"
  | "ERR_AUDIENCE_MISMATCH"
  | "ERR_DELEGATION_DEPTH_EXCEEDED"
  | "ERR_POLICY_HASH_MISMATCH"
  | "ERR_POLICY_HOOK_REJECTED"
  | "ERR_CONSTRAINT_VIOLATION"
  | "ERR_CHALLENGE_REQUIRED"
  | "ERR_REPLAY_DETECTED"
  | "ERR_TRUST_BUNDLE_EXPIRED"
  | "ERR_TRUST_BUNDLE_SIGNATURE_INVALID"
  | "ERR_ISSUER_KEY_OUT_OF_WINDOW"
  | "ERR_TRANSPARENCY_INVALID"
  | "ERR_ISSUER_KEY_MISSING";

export interface Delegation {
  parent_capability_id: string;
  depth: number;
  max_depth: number;
}

export interface ConstraintSet {
  resource_limits: Record<string, number>;
  spend_limits: Record<string, number>;
  api_scopes: string[];
  rate_limits: Record<string, number>;
  environment_constraints: string[];
}

export interface ConstraintEvidence {
  resource_usage: Record<string, number>;
  spend_usage: Record<string, number>;
  rate_usage: Record<string, number>;
  environment: string;
  api_scope: string;
}

export interface Capability {
  capability_id: string;
  issuer_id: string;
  issuer_kid: string;
  agent_id: string;
  audience: string;
  allowed_actions: string[];
  constraints: ConstraintSet;
  delegation: Delegation;
  policy_hash: string;
  transparency_ref: string;
  issued_at: string;
  expires_at: string;
  signature: string;
}

export interface ActionEnvelope {
  action_id: string;
  agent_id: string;
  capability_id: string;
  audience: string;
  action_type: string;
  constraint_evidence: ConstraintEvidence;
  challenge_nonce?: string;
  timestamp: string;
  agent_signature: string;
}

export interface VerificationResult {
  decision: VerificationDecision;
  reason_codes: ReasonCode[];
  reasons: string[];
  replay_status: ReplayStatus;
  policy_hash_seen: string;
}

export interface RevocationChecker {
  isRevoked(capabilityId: string): boolean;
}

export interface ReplayCache {
  markAndCheck(actionId: string): boolean;
}

export interface WindowedReplayCache extends ReplayCache {
  markAndCheckWithinWindow(actionId: string, actionTimestamp: Date, referenceTime: Date, windowMs: number): boolean;
}

export interface KeyResolutionResult {
  publicKey?: string;
  errorCode?: ReasonCode;
}

export interface IssuerKeyResolver {
  resolve(issuerId: string, issuerKID: string, at: Date): KeyResolutionResult;
}

export interface ChallengePolicy {
  requiresChallenge(actionType: string): boolean;
}

export interface PolicyEvaluator {
  evaluate(capability: Capability, action: ActionEnvelope): Array<{ code: ReasonCode; reason: string }>;
}

export interface TransparencyVerifier {
  verify(transparencyRef: string, capabilityId: string): string | null;
}

export interface CryptoProvider {
  deriveIDFromPublicKey(publicKey: string): string;
  verifyCapabilitySignature(capability: Capability, issuerPublicKey: string): boolean;
  verifyActionSignature(action: ActionEnvelope, agentPublicKey: string): boolean;
}

export interface VerifyRequest {
  capability: Capability;
  action: ActionEnvelope;
  agentPublicKey: string;
  referenceTime: Date;
  expectedAudience?: string;
  expectedPolicyHash?: string;
  revocationList?: RevocationChecker;
  replayCache?: ReplayCache;
  replayWindowMs?: number;
  challengePolicy?: ChallengePolicy;
  policyEvaluator?: PolicyEvaluator;
  transparency?: TransparencyVerifier;
  issuerPublicKey?: string;
  keyResolver?: IssuerKeyResolver;
  crypto: CryptoProvider;
}

export class AnchorOfflineVerifier {
  verify(req: VerifyRequest): VerificationResult {
    const result: VerificationResult = {
      decision: "AUTHORIZED",
      reason_codes: [],
      reasons: [],
      replay_status: "UNKNOWN",
      policy_hash_seen: req.capability.policy_hash,
    };
    const addReason = (code: ReasonCode, reason: string): void => {
      result.decision = "REJECTED";
      result.reason_codes.push(code);
      result.reasons.push(reason);
    };

    if (!req.referenceTime || Number.isNaN(req.referenceTime.getTime())) {
      addReason("ERR_REFERENCE_TIME_MISSING", "reference_time is required");
      return result;
    }

    const issuerResolution = this.resolveIssuerKey(req);
    if (issuerResolution.errorCode) {
      addReason(issuerResolution.errorCode, "issuer key resolution failed");
      return result;
    }
    if (!issuerResolution.publicKey) {
      addReason("ERR_ISSUER_KEY_MISSING", "issuer key not found for issuer_id+issuer_kid");
      return result;
    }

    if (req.issuerPublicKey) {
      try {
        const derivedIssuerID = req.crypto.deriveIDFromPublicKey(issuerResolution.publicKey);
        if (derivedIssuerID !== req.capability.issuer_id) {
          addReason("ERR_ISSUER_MISMATCH", "issuer_id does not match issuer public key");
        }
      } catch (err) {
        addReason("ERR_CAPABILITY_INVALID", `invalid issuer public key: ${String(err)}`);
      }
    }

    if (!req.crypto.verifyCapabilitySignature(req.capability, issuerResolution.publicKey)) {
      addReason("ERR_CAPABILITY_SIGNATURE_INVALID", "capability signature invalid");
    }

    const ref = req.referenceTime.getTime();
    if (ref < parseTime(req.capability.issued_at)) {
      addReason("ERR_CAPABILITY_NOT_YET_VALID", "capability is not valid yet");
    }
    if (ref > parseTime(req.capability.expires_at)) {
      addReason("ERR_CAPABILITY_EXPIRED", "capability is expired");
    }
    if (req.revocationList && req.revocationList.isRevoked(req.capability.capability_id)) {
      addReason("ERR_CAPABILITY_REVOKED", "capability is revoked");
    }

    let agentID = "";
    try {
      agentID = req.crypto.deriveIDFromPublicKey(req.agentPublicKey);
      if (req.capability.agent_id !== agentID) {
        addReason("ERR_AGENT_MISMATCH", "capability agent_id does not match agent public key");
      }
      if (req.action.agent_id !== agentID) {
        addReason("ERR_AGENT_MISMATCH", "action agent_id does not match agent public key");
      }
    } catch (err) {
      addReason("ERR_ACTION_INVALID", `invalid agent public key: ${String(err)}`);
    }

    if (!req.crypto.verifyActionSignature(req.action, req.agentPublicKey)) {
      addReason("ERR_ACTION_SIGNATURE_INVALID", "action signature invalid");
    }

    if (req.action.capability_id !== req.capability.capability_id) {
      addReason("ERR_CAPABILITY_BINDING_MISMATCH", "action capability_id does not match capability");
    }
    if (req.action.audience !== req.capability.audience) {
      addReason("ERR_AUDIENCE_MISMATCH", "action audience does not match capability audience");
    }
    if (req.expectedAudience && req.action.audience !== req.expectedAudience) {
      addReason("ERR_AUDIENCE_MISMATCH", "action audience does not match expected audience");
    }
    if (req.expectedPolicyHash && req.capability.policy_hash !== req.expectedPolicyHash) {
      addReason("ERR_POLICY_HASH_MISMATCH", "capability policy_hash does not match expected policy_hash");
    }
    if (req.transparency && req.capability.transparency_ref) {
      const transparencyError = req.transparency.verify(req.capability.transparency_ref, req.capability.capability_id);
      if (transparencyError) {
        addReason("ERR_TRANSPARENCY_INVALID", `transparency linkage verification failed: ${transparencyError}`);
      }
    }
    if (req.capability.delegation.depth > req.capability.delegation.max_depth) {
      addReason("ERR_DELEGATION_DEPTH_EXCEEDED", "delegation depth exceeds max_depth");
    }
    if (!contains(req.capability.allowed_actions, req.action.action_type)) {
      addReason("ERR_ACTION_NOT_ALLOWED", "action_type not allowed by capability");
    }

    for (const reason of verifyConstraints(req.capability.constraints, req.action.constraint_evidence)) {
      addReason("ERR_CONSTRAINT_VIOLATION", reason);
    }

    if (
      req.challengePolicy &&
      req.challengePolicy.requiresChallenge(req.action.action_type) &&
      !req.action.challenge_nonce
    ) {
      addReason("ERR_CHALLENGE_REQUIRED", "challenge_nonce required for high-risk action");
    }
    if (req.policyEvaluator) {
      for (const entry of req.policyEvaluator.evaluate(req.capability, req.action)) {
        addReason(entry.code, entry.reason);
      }
    }
    if (req.replayCache) {
      let replayDetected = false;
      const maybeWindowed = req.replayCache as WindowedReplayCache;
      if (typeof maybeWindowed.markAndCheckWithinWindow === "function") {
        const windowMs = req.replayWindowMs && req.replayWindowMs > 0 ? req.replayWindowMs : 5 * 60 * 1000;
        replayDetected = maybeWindowed.markAndCheckWithinWindow(
          req.action.action_id,
          new Date(req.action.timestamp),
          req.referenceTime,
          windowMs,
        );
      } else {
        replayDetected = req.replayCache.markAndCheck(req.action.action_id);
      }
      if (replayDetected) {
        result.replay_status = "REPLAY";
        addReason("ERR_REPLAY_DETECTED", "replay detected for action_id");
      } else {
        result.replay_status = "FRESH";
      }
    }

    return result;
  }

  private resolveIssuerKey(req: VerifyRequest): KeyResolutionResult {
    if (req.issuerPublicKey) {
      return { publicKey: req.issuerPublicKey };
    }
    if (!req.keyResolver) {
      return {};
    }
    const resolved = req.keyResolver.resolve(req.capability.issuer_id, req.capability.issuer_kid, req.referenceTime);
    return resolved ?? {};
  }
}

function parseTime(raw: string): number {
  const value = Date.parse(raw);
  if (Number.isNaN(value)) {
    return 0;
  }
  return value;
}

function contains(values: string[], needle: string): boolean {
  return values.includes(needle);
}

function sortedKeys(values: Record<string, number>): string[] {
  return Object.keys(values).sort();
}

function verifyConstraints(constraints: ConstraintSet, evidence: ConstraintEvidence): string[] {
  const reasons: string[] = [];
  if (constraints.api_scopes.length > 0 && !contains(constraints.api_scopes, evidence.api_scope)) {
    reasons.push("api_scope is not allowed by capability constraints");
  }
  if (
    constraints.environment_constraints.length > 0 &&
    !contains(constraints.environment_constraints, evidence.environment)
  ) {
    reasons.push("environment is not allowed by capability constraints");
  }
  for (const key of sortedKeys(evidence.resource_usage)) {
    const limit = constraints.resource_limits[key];
    if (limit === undefined) {
      reasons.push(`resource usage for ${key} is not permitted`);
      continue;
    }
    if (evidence.resource_usage[key] > limit) {
      reasons.push(`resource usage for ${key} exceeds limit`);
    }
  }
  for (const key of sortedKeys(evidence.spend_usage)) {
    const limit = constraints.spend_limits[key];
    if (limit === undefined) {
      reasons.push(`spend usage for ${key} is not permitted`);
      continue;
    }
    if (evidence.spend_usage[key] > limit) {
      reasons.push(`spend usage for ${key} exceeds limit`);
    }
  }
  for (const key of sortedKeys(evidence.rate_usage)) {
    const limit = constraints.rate_limits[key];
    if (limit === undefined) {
      reasons.push(`rate usage for ${key} is not permitted`);
      continue;
    }
    if (evidence.rate_usage[key] > limit) {
      reasons.push(`rate usage for ${key} exceeds limit`);
    }
  }
  return reasons;
}
