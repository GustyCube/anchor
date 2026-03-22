import com.gustycube.anchor.sdk.AnchorLocalVerifier;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.ActionEnvelope;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.Capability;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.ChallengePolicy;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.ConstraintEvidence;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.ConstraintSet;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.CryptoProvider;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.Delegation;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.IssuerKeyResolver;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.KeyResolutionResult;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.ReplayCache;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.VerificationResult;
import com.gustycube.anchor.sdk.AnchorLocalVerifier.VerifyRequest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class ConformanceRunner {
    private ConformanceRunner() {}

    public static void main(String[] args) {
        if (args.length != 1 || args[0].trim().isEmpty()) {
            throw new IllegalArgumentException("scenario argument is required");
        }

        VerificationResult result = runScenario(args[0].trim());
        System.out.print(toJSON(result));
    }

    private static VerificationResult runScenario(String scenario) {
        AnchorLocalVerifier verifier = new AnchorLocalVerifier();
        VerifyRequest request = new VerifyRequest();
        request.capability = baseCapability();
        request.action = baseAction();
        request.agentPublicKey = "agent-public-key";
        request.referenceTime = Instant.parse("2026-02-13T12:05:00Z");
        request.expectedAudience = "bank:prod:payments";
        request.expectedPolicyHash = "policy-hash-v2";
        request.replayCache = new MemoryReplayCache();
        request.challengePolicy = new StaticChallengePolicy();
        request.keyResolver = new StaticKeyResolver();
        request.cryptoProvider = new StaticCrypto();

        switch (scenario) {
            case "authorized":
                return verifier.verify(request);
            case "audience_mismatch":
                request.action.audience = "bank:prod:treasury";
                return verifier.verify(request);
            case "challenge_required":
                request.action.challengeNonce = "";
                return verifier.verify(request);
            case "policy_hash_mismatch":
                request.expectedPolicyHash = "policy-hash-mismatch";
                return verifier.verify(request);
            case "replay_detected":
                verifier.verify(request);
                return verifier.verify(request);
            default:
                throw new IllegalArgumentException("unsupported scenario: " + scenario);
        }
    }

    private static Capability baseCapability() {
        Capability capability = new Capability();
        capability.capabilityId = "cap-001";
        capability.issuerId = "issuer-001";
        capability.issuerKid = "kid-001";
        capability.agentId = "agent-001";
        capability.audience = "bank:prod:payments";
        capability.allowedActions = List.of("bank:TransferFunds");

        ConstraintSet constraints = new ConstraintSet();
        constraints.resourceLimits = Map.of("bank:transfers", 5L);
        constraints.spendLimits = Map.of("usd_cents", 10_000L);
        constraints.apiScopes = List.of("bank:payments");
        constraints.rateLimits = Map.of("requests_per_minute", 5L);
        constraints.environmentConstraints = List.of("prod");
        capability.constraints = constraints;

        Delegation delegation = new Delegation();
        delegation.depth = 0;
        delegation.maxDepth = 1;
        capability.delegation = delegation;

        capability.policyHash = "policy-hash-v2";
        capability.transparencyRef = "";
        capability.issuedAt = "2026-02-13T12:00:00Z";
        capability.expiresAt = "2026-02-13T13:00:00Z";
        capability.signature = "capability-signature-valid";
        return capability;
    }

    private static ActionEnvelope baseAction() {
        ActionEnvelope action = new ActionEnvelope();
        action.actionId = "act-001";
        action.agentId = "agent-001";
        action.capabilityId = "cap-001";
        action.audience = "bank:prod:payments";
        action.actionType = "bank:TransferFunds";
        action.challengeNonce = "challenge-001";
        action.timestamp = "2026-02-13T12:05:00Z";
        action.agentSignature = "action-signature-valid";

        ConstraintEvidence evidence = new ConstraintEvidence();
        evidence.resourceUsage = Map.of("bank:transfers", 1L);
        evidence.spendUsage = Map.of("usd_cents", 500L);
        evidence.rateUsage = Map.of("requests_per_minute", 1L);
        evidence.environment = "prod";
        evidence.apiScope = "bank:payments";
        action.constraintEvidence = evidence;

        return action;
    }

    private static String toJSON(VerificationResult result) {
        String reasonCodes = result.reasonCodes.stream()
            .map(code -> quote(code))
            .collect(Collectors.joining(","));

        return "{" +
            "\"decision\":" + quote(result.decision) + "," +
            "\"reason_codes\":[" + reasonCodes + "]," +
            "\"replay_status\":" + quote(result.replayStatus) + "," +
            "\"policy_hash_seen\":" + quote(result.policyHashSeen) +
            "}";
    }

    private static String quote(String value) {
        if (value == null) {
            return "\"\"";
        }
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static final class MemoryReplayCache implements ReplayCache {
        private final Map<String, Boolean> seen = new HashMap<>();

        @Override
        public boolean markAndCheck(String actionId) {
            if (seen.containsKey(actionId)) {
                return true;
            }
            seen.put(actionId, true);
            return false;
        }
    }

    private static final class StaticKeyResolver implements IssuerKeyResolver {
        @Override
        public KeyResolutionResult resolve(String issuerId, String issuerKid, Instant at) {
            KeyResolutionResult result = new KeyResolutionResult();
            if ("issuer-001".equals(issuerId) && "kid-001".equals(issuerKid)) {
                result.publicKey = "issuer-public-key";
                return result;
            }
            result.errorCode = "ERR_ISSUER_KEY_MISSING";
            return result;
        }
    }

    private static final class StaticChallengePolicy implements ChallengePolicy {
        @Override
        public boolean requiresChallenge(String actionType) {
            return "bank:TransferFunds".equals(actionType);
        }
    }

    private static final class StaticCrypto implements CryptoProvider {
        @Override
        public String deriveIDFromPublicKey(String publicKey) throws Exception {
            if ("issuer-public-key".equals(publicKey)) {
                return "issuer-001";
            }
            if ("agent-public-key".equals(publicKey)) {
                return "agent-001";
            }
            throw new Exception("unknown public key");
        }

        @Override
        public boolean verifyCapabilitySignature(Capability capability, String issuerPublicKey) {
            return "capability-signature-valid".equals(capability.signature);
        }

        @Override
        public boolean verifyActionSignature(ActionEnvelope action, String agentPublicKey) {
            return "action-signature-valid".equals(action.agentSignature);
        }
    }
}
