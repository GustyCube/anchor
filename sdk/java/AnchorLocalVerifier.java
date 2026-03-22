package com.gustycube.anchor.sdk;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public final class AnchorLocalVerifier {
    public static final class ReasonCodes {
        public static final String REFERENCE_TIME_MISSING = "ERR_REFERENCE_TIME_MISSING";
        public static final String ISSUER_MISMATCH = "ERR_ISSUER_MISMATCH";
        public static final String CAPABILITY_INVALID = "ERR_CAPABILITY_INVALID";
        public static final String CAPABILITY_SIGNATURE_INVALID = "ERR_CAPABILITY_SIGNATURE_INVALID";
        public static final String CAPABILITY_NOT_YET_VALID = "ERR_CAPABILITY_NOT_YET_VALID";
        public static final String CAPABILITY_EXPIRED = "ERR_CAPABILITY_EXPIRED";
        public static final String CAPABILITY_REVOKED = "ERR_CAPABILITY_REVOKED";
        public static final String AGENT_MISMATCH = "ERR_AGENT_MISMATCH";
        public static final String ACTION_INVALID = "ERR_ACTION_INVALID";
        public static final String ACTION_SIGNATURE_INVALID = "ERR_ACTION_SIGNATURE_INVALID";
        public static final String CAPABILITY_BINDING_MISMATCH = "ERR_CAPABILITY_BINDING_MISMATCH";
        public static final String ACTION_NOT_ALLOWED = "ERR_ACTION_NOT_ALLOWED";
        public static final String AUDIENCE_MISMATCH = "ERR_AUDIENCE_MISMATCH";
        public static final String DELEGATION_DEPTH_EXCEEDED = "ERR_DELEGATION_DEPTH_EXCEEDED";
        public static final String POLICY_HASH_MISMATCH = "ERR_POLICY_HASH_MISMATCH";
        public static final String POLICY_HOOK_REJECTED = "ERR_POLICY_HOOK_REJECTED";
        public static final String CONSTRAINT_VIOLATION = "ERR_CONSTRAINT_VIOLATION";
        public static final String CHALLENGE_REQUIRED = "ERR_CHALLENGE_REQUIRED";
        public static final String REPLAY_DETECTED = "ERR_REPLAY_DETECTED";
        public static final String TRUST_BUNDLE_EXPIRED = "ERR_TRUST_BUNDLE_EXPIRED";
        public static final String TRUST_BUNDLE_SIGNATURE_INVALID = "ERR_TRUST_BUNDLE_SIGNATURE_INVALID";
        public static final String ISSUER_KEY_OUT_OF_WINDOW = "ERR_ISSUER_KEY_OUT_OF_WINDOW";
        public static final String TRANSPARENCY_INVALID = "ERR_TRANSPARENCY_INVALID";
        public static final String ISSUER_KEY_MISSING = "ERR_ISSUER_KEY_MISSING";

        private ReasonCodes() {}
    }

    public static final class ConstraintSet {
        public Map<String, Long> resourceLimits;
        public Map<String, Long> spendLimits;
        public List<String> apiScopes;
        public Map<String, Long> rateLimits;
        public List<String> environmentConstraints;
    }

    public static final class Delegation {
        public int depth;
        public int maxDepth;
    }

    public static final class ConstraintEvidence {
        public Map<String, Long> resourceUsage;
        public Map<String, Long> spendUsage;
        public Map<String, Long> rateUsage;
        public String environment;
        public String apiScope;
    }

    public static final class Capability {
        public String capabilityId;
        public String issuerId;
        public String issuerKid;
        public String agentId;
        public String audience;
        public List<String> allowedActions;
        public ConstraintSet constraints;
        public Delegation delegation;
        public String policyHash;
        public String transparencyRef;
        public String issuedAt;
        public String expiresAt;
        public String signature;
    }

    public static final class ActionEnvelope {
        public String actionId;
        public String agentId;
        public String capabilityId;
        public String audience;
        public String actionType;
        public ConstraintEvidence constraintEvidence;
        public String challengeNonce;
        public String timestamp;
        public String agentSignature;
    }

    public static final class VerificationResult {
        public String decision = "AUTHORIZED";
        public final List<String> reasonCodes = new ArrayList<>();
        public final List<String> reasons = new ArrayList<>();
        public String replayStatus = "UNKNOWN";
        public String policyHashSeen = "";
    }

    public interface RevocationChecker {
        boolean isRevoked(String capabilityId);
    }

    public interface ReplayCache {
        boolean markAndCheck(String actionId);
    }

    public interface WindowedReplayCache extends ReplayCache {
        boolean markAndCheckWithinWindow(String actionId, Instant actionTimestamp, Instant referenceTime, Duration window);
    }

    public static final class KeyResolutionResult {
        public String publicKey = "";
        public String errorCode = "";
    }

    public interface IssuerKeyResolver {
        KeyResolutionResult resolve(String issuerId, String issuerKid, Instant at);
    }

    public interface ChallengePolicy {
        boolean requiresChallenge(String actionType);
    }

    public static final class PolicyDecision {
        public String code;
        public String reason;
    }

    public interface PolicyEvaluator {
        List<PolicyDecision> evaluate(Capability capability, ActionEnvelope action);
    }

    public interface TransparencyVerifier {
        String verify(String transparencyRef, String capabilityId);
    }

    public interface CryptoProvider {
        String deriveIDFromPublicKey(String publicKey) throws Exception;
        boolean verifyCapabilitySignature(Capability capability, String issuerPublicKey);
        boolean verifyActionSignature(ActionEnvelope action, String agentPublicKey);
    }

    public static final class VerifyRequest {
        public Capability capability;
        public ActionEnvelope action;
        public String agentPublicKey;
        public Instant referenceTime;
        public String expectedAudience = "";
        public String expectedPolicyHash = "";
        public RevocationChecker revocationList;
        public ReplayCache replayCache;
        public Duration replayWindow = Duration.ofMinutes(5);
        public ChallengePolicy challengePolicy;
        public PolicyEvaluator policyEvaluator;
        public TransparencyVerifier transparencyVerifier;
        public String issuerPublicKey = "";
        public IssuerKeyResolver keyResolver;
        public CryptoProvider cryptoProvider;
    }

    public VerificationResult verify(VerifyRequest req) {
        VerificationResult result = new VerificationResult();
        result.policyHashSeen = req.capability.policyHash;

        if (req.referenceTime == null) {
            addReason(result, ReasonCodes.REFERENCE_TIME_MISSING, "reference_time is required");
            return result;
        }

        KeyResolutionResult issuerResolution = resolveIssuerKey(req);
        if (issuerResolution.errorCode != null && !issuerResolution.errorCode.isEmpty()) {
            addReason(result, issuerResolution.errorCode, "issuer key resolution failed");
            return result;
        }
        if (issuerResolution.publicKey == null || issuerResolution.publicKey.isEmpty()) {
            addReason(result, ReasonCodes.ISSUER_KEY_MISSING, "issuer key not found for issuer_id+issuer_kid");
            return result;
        }

        if (req.issuerPublicKey != null && !req.issuerPublicKey.isEmpty()) {
            try {
                String derivedIssuerID = req.cryptoProvider.deriveIDFromPublicKey(issuerResolution.publicKey);
                if (!req.capability.issuerId.equals(derivedIssuerID)) {
                    addReason(result, ReasonCodes.ISSUER_MISMATCH, "issuer_id does not match issuer public key");
                }
            } catch (Exception ex) {
                addReason(result, ReasonCodes.CAPABILITY_INVALID, "invalid issuer public key: " + ex.getMessage());
            }
        }

        if (!req.cryptoProvider.verifyCapabilitySignature(req.capability, issuerResolution.publicKey)) {
            addReason(result, ReasonCodes.CAPABILITY_SIGNATURE_INVALID, "capability signature invalid");
        }

        Instant issuedAt = parseInstant(req.capability.issuedAt);
        Instant expiresAt = parseInstant(req.capability.expiresAt);
        if (issuedAt != null && req.referenceTime.isBefore(issuedAt)) {
            addReason(result, ReasonCodes.CAPABILITY_NOT_YET_VALID, "capability is not valid yet");
        }
        if (expiresAt != null && req.referenceTime.isAfter(expiresAt)) {
            addReason(result, ReasonCodes.CAPABILITY_EXPIRED, "capability is expired");
        }
        if (req.revocationList != null && req.revocationList.isRevoked(req.capability.capabilityId)) {
            addReason(result, ReasonCodes.CAPABILITY_REVOKED, "capability is revoked");
        }

        try {
            String agentID = req.cryptoProvider.deriveIDFromPublicKey(req.agentPublicKey);
            if (!req.capability.agentId.equals(agentID)) {
                addReason(result, ReasonCodes.AGENT_MISMATCH, "capability agent_id does not match agent public key");
            }
            if (!req.action.agentId.equals(agentID)) {
                addReason(result, ReasonCodes.AGENT_MISMATCH, "action agent_id does not match agent public key");
            }
        } catch (Exception ex) {
            addReason(result, ReasonCodes.ACTION_INVALID, "invalid agent public key: " + ex.getMessage());
        }

        if (!req.cryptoProvider.verifyActionSignature(req.action, req.agentPublicKey)) {
            addReason(result, ReasonCodes.ACTION_SIGNATURE_INVALID, "action signature invalid");
        }

        if (!req.action.capabilityId.equals(req.capability.capabilityId)) {
            addReason(result, ReasonCodes.CAPABILITY_BINDING_MISMATCH, "action capability_id does not match capability");
        }
        if (!req.action.audience.equals(req.capability.audience)) {
            addReason(result, ReasonCodes.AUDIENCE_MISMATCH, "action audience does not match capability audience");
        }
        if (req.expectedAudience != null && !req.expectedAudience.isEmpty() && !req.expectedAudience.equals(req.action.audience)) {
            addReason(result, ReasonCodes.AUDIENCE_MISMATCH, "action audience does not match expected audience");
        }
        if (req.expectedPolicyHash != null && !req.expectedPolicyHash.isEmpty()
            && !req.expectedPolicyHash.equals(req.capability.policyHash)) {
            addReason(result, ReasonCodes.POLICY_HASH_MISMATCH, "capability policy_hash does not match expected policy_hash");
        }
        if (req.transparencyVerifier != null && req.capability.transparencyRef != null && !req.capability.transparencyRef.isEmpty()) {
            String transparencyErr = req.transparencyVerifier.verify(req.capability.transparencyRef, req.capability.capabilityId);
            if (transparencyErr != null && !transparencyErr.isEmpty()) {
                addReason(result, ReasonCodes.TRANSPARENCY_INVALID, "transparency linkage verification failed: " + transparencyErr);
            }
        }
        if (req.capability.delegation.depth > req.capability.delegation.maxDepth) {
            addReason(result, ReasonCodes.DELEGATION_DEPTH_EXCEEDED, "delegation depth exceeds max_depth");
        }
        if (req.capability.allowedActions == null || !req.capability.allowedActions.contains(req.action.actionType)) {
            addReason(result, ReasonCodes.ACTION_NOT_ALLOWED, "action_type not allowed by capability");
        }

        for (String reason : verifyConstraints(req.capability.constraints, req.action.constraintEvidence)) {
            addReason(result, ReasonCodes.CONSTRAINT_VIOLATION, reason);
        }

        if (req.challengePolicy != null && req.challengePolicy.requiresChallenge(req.action.actionType)) {
            if (req.action.challengeNonce == null || req.action.challengeNonce.isEmpty()) {
                addReason(result, ReasonCodes.CHALLENGE_REQUIRED, "challenge_nonce required for high-risk action");
            }
        }
        if (req.policyEvaluator != null) {
            List<PolicyDecision> decisions = req.policyEvaluator.evaluate(req.capability, req.action);
            if (decisions != null) {
                for (PolicyDecision decision : decisions) {
                    if (decision != null && decision.code != null && decision.reason != null) {
                        addReason(result, decision.code, decision.reason);
                    }
                }
            }
        }

        if (req.replayCache != null) {
            boolean replayDetected;
            if (req.replayCache instanceof WindowedReplayCache) {
                Duration window = req.replayWindow == null || req.replayWindow.isZero() || req.replayWindow.isNegative()
                    ? Duration.ofMinutes(5)
                    : req.replayWindow;
                Instant actionTimestamp = parseInstant(req.action.timestamp);
                if (actionTimestamp == null) {
                    replayDetected = req.replayCache.markAndCheck(req.action.actionId);
                } else {
                    replayDetected = ((WindowedReplayCache) req.replayCache)
                        .markAndCheckWithinWindow(req.action.actionId, actionTimestamp, req.referenceTime, window);
                }
            } else {
                replayDetected = req.replayCache.markAndCheck(req.action.actionId);
            }
            if (replayDetected) {
                result.replayStatus = "REPLAY";
                addReason(result, ReasonCodes.REPLAY_DETECTED, "replay detected for action_id");
            } else {
                result.replayStatus = "FRESH";
            }
        }

        return result;
    }

    private static void addReason(VerificationResult result, String code, String reason) {
        result.decision = "REJECTED";
        result.reasonCodes.add(code);
        result.reasons.add(reason);
    }

    private static KeyResolutionResult resolveIssuerKey(VerifyRequest req) {
        if (req.issuerPublicKey != null && !req.issuerPublicKey.isEmpty()) {
            KeyResolutionResult result = new KeyResolutionResult();
            result.publicKey = req.issuerPublicKey;
            return result;
        }
        if (req.keyResolver == null) {
            return new KeyResolutionResult();
        }
        KeyResolutionResult resolved = req.keyResolver.resolve(req.capability.issuerId, req.capability.issuerKid, req.referenceTime);
        return resolved == null ? new KeyResolutionResult() : resolved;
    }

    private static Instant parseInstant(String raw) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(raw);
        } catch (Exception ex) {
            return null;
        }
    }

    private static List<String> sortedKeys(Map<String, Long> values) {
        if (values == null || values.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> keys = new ArrayList<>(values.keySet());
        keys.sort(Comparator.naturalOrder());
        return keys;
    }

    private static List<String> verifyConstraints(ConstraintSet constraints, ConstraintEvidence evidence) {
        List<String> reasons = new ArrayList<>();
        if (constraints == null || evidence == null) {
            reasons.add("constraint evidence is required");
            return reasons;
        }

        if (constraints.apiScopes != null && !constraints.apiScopes.isEmpty()
            && (evidence.apiScope == null || !constraints.apiScopes.contains(evidence.apiScope))) {
            reasons.add("api_scope is not allowed by capability constraints");
        }
        if (constraints.environmentConstraints != null && !constraints.environmentConstraints.isEmpty()
            && (evidence.environment == null || !constraints.environmentConstraints.contains(evidence.environment))) {
            reasons.add("environment is not allowed by capability constraints");
        }
        for (String key : sortedKeys(evidence.resourceUsage)) {
            Long limit = constraints.resourceLimits == null ? null : constraints.resourceLimits.get(key);
            if (limit == null) {
                reasons.add("resource usage for " + key + " is not permitted");
                continue;
            }
            if (evidence.resourceUsage.get(key) > limit) {
                reasons.add("resource usage for " + key + " exceeds limit");
            }
        }
        for (String key : sortedKeys(evidence.spendUsage)) {
            Long limit = constraints.spendLimits == null ? null : constraints.spendLimits.get(key);
            if (limit == null) {
                reasons.add("spend usage for " + key + " is not permitted");
                continue;
            }
            if (evidence.spendUsage.get(key) > limit) {
                reasons.add("spend usage for " + key + " exceeds limit");
            }
        }
        for (String key : sortedKeys(evidence.rateUsage)) {
            Long limit = constraints.rateLimits == null ? null : constraints.rateLimits.get(key);
            if (limit == null) {
                reasons.add("rate usage for " + key + " is not permitted");
                continue;
            }
            if (evidence.rateUsage.get(key) > limit) {
                reasons.add("rate usage for " + key + " exceeds limit");
            }
        }
        return reasons;
    }
}
