import { AnchorOfflineVerifier } from "./verifier.ts";
import type {
  ActionEnvelope,
  Capability,
  ChallengePolicy,
  ConstraintEvidence,
  ConstraintSet,
  CryptoProvider,
  IssuerKeyResolver,
  KeyResolutionResult,
  ReplayCache,
  VerificationResult,
  VerifyRequest,
} from "./verifier.ts";

class MemoryReplayCache implements ReplayCache {
  private readonly seen = new Set<string>();

  markAndCheck(actionId: string): boolean {
    if (this.seen.has(actionId)) {
      return true;
    }
    this.seen.add(actionId);
    return false;
  }
}

class StaticKeyResolver implements IssuerKeyResolver {
  resolve(issuerId: string, issuerKID: string): KeyResolutionResult {
    if (issuerId == "issuer-001" && issuerKID == "kid-001") {
      return { publicKey: "issuer-public-key" };
    }
    return { errorCode: "ERR_ISSUER_KEY_MISSING" };
  }
}

class StaticChallengePolicy implements ChallengePolicy {
  requiresChallenge(actionType: string): boolean {
    return actionType == "bank:TransferFunds";
  }
}

class StaticCrypto implements CryptoProvider {
  deriveIDFromPublicKey(publicKey: string): string {
    if (publicKey == "issuer-public-key") {
      return "issuer-001";
    }
    if (publicKey == "agent-public-key") {
      return "agent-001";
    }
    throw new Error("unknown public key");
  }

  verifyCapabilitySignature(capability: Capability): boolean {
    return capability.signature == "capability-signature-valid";
  }

  verifyActionSignature(action: ActionEnvelope): boolean {
    return action.agent_signature == "action-signature-valid";
  }
}

function baseConstraints(): ConstraintSet {
  return {
    resource_limits: { "bank:transfers": 5 },
    spend_limits: { usd_cents: 10000 },
    api_scopes: ["bank:payments"],
    rate_limits: { requests_per_minute: 5 },
    environment_constraints: ["prod"],
  };
}

function baseEvidence(): ConstraintEvidence {
  return {
    resource_usage: { "bank:transfers": 1 },
    spend_usage: { usd_cents: 500 },
    rate_usage: { requests_per_minute: 1 },
    environment: "prod",
    api_scope: "bank:payments",
  };
}

function baseCapability(): Capability {
  return {
    capability_id: "cap-001",
    issuer_id: "issuer-001",
    issuer_kid: "kid-001",
    agent_id: "agent-001",
    audience: "bank:prod:payments",
    allowed_actions: ["bank:TransferFunds"],
    constraints: baseConstraints(),
    delegation: {
      parent_capability_id: "",
      depth: 0,
      max_depth: 1,
    },
    policy_hash: "policy-hash-v2",
    transparency_ref: "",
    issued_at: "2026-02-13T12:00:00Z",
    expires_at: "2026-02-13T13:00:00Z",
    signature: "capability-signature-valid",
  };
}

function baseAction(): ActionEnvelope {
  return {
    action_id: "act-001",
    agent_id: "agent-001",
    capability_id: "cap-001",
    audience: "bank:prod:payments",
    action_type: "bank:TransferFunds",
    constraint_evidence: baseEvidence(),
    challenge_nonce: "challenge-001",
    timestamp: "2026-02-13T12:05:00Z",
    agent_signature: "action-signature-valid",
  };
}

function parseScenarioArg(): string {
  if (process.argv.length < 3 || process.argv[2].trim().length == 0) {
    throw new Error("scenario argument is required");
  }
  return process.argv[2].trim();
}

function runScenario(name: string): VerificationResult {
  const verifier = new AnchorOfflineVerifier();
  const capability = baseCapability();
  const action = baseAction();
  const replayCache = new MemoryReplayCache();

  const request: VerifyRequest = {
    capability,
    action,
    agentPublicKey: "agent-public-key",
    referenceTime: new Date("2026-02-13T12:05:00Z"),
    expectedAudience: "bank:prod:payments",
    expectedPolicyHash: "policy-hash-v2",
    replayCache,
    challengePolicy: new StaticChallengePolicy(),
    keyResolver: new StaticKeyResolver(),
    crypto: new StaticCrypto(),
  };

  switch (name) {
    case "authorized":
      return verifier.verify(request);
    case "audience_mismatch":
      request.action.audience = "bank:prod:treasury";
      return verifier.verify(request);
    case "challenge_required":
      request.action.challenge_nonce = "";
      return verifier.verify(request);
    case "policy_hash_mismatch":
      request.expectedPolicyHash = "policy-hash-mismatch";
      return verifier.verify(request);
    case "replay_detected":
      verifier.verify(request);
      return verifier.verify(request);
    default:
      throw new Error(`unsupported scenario: ${name}`);
  }
}

function toOutput(result: VerificationResult): string {
  return JSON.stringify({
    decision: result.decision,
    reason_codes: result.reason_codes,
    replay_status: result.replay_status,
    policy_hash_seen: result.policy_hash_seen,
  });
}

function main(): void {
  const scenario = parseScenarioArg();
  const result = runScenario(scenario);
  process.stdout.write(toOutput(result));
}

main();
