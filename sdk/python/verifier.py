from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Protocol, Tuple


ReasonCode = str
Decision = str
ReplayStatus = str

REASON_CODES: List[str] = [
    "ERR_REFERENCE_TIME_MISSING",
    "ERR_ISSUER_MISMATCH",
    "ERR_CAPABILITY_INVALID",
    "ERR_CAPABILITY_SIGNATURE_INVALID",
    "ERR_CAPABILITY_NOT_YET_VALID",
    "ERR_CAPABILITY_EXPIRED",
    "ERR_CAPABILITY_REVOKED",
    "ERR_AGENT_MISMATCH",
    "ERR_ACTION_INVALID",
    "ERR_ACTION_SIGNATURE_INVALID",
    "ERR_CAPABILITY_BINDING_MISMATCH",
    "ERR_ACTION_NOT_ALLOWED",
    "ERR_AUDIENCE_MISMATCH",
    "ERR_DELEGATION_DEPTH_EXCEEDED",
    "ERR_POLICY_HASH_MISMATCH",
    "ERR_POLICY_HOOK_REJECTED",
    "ERR_CONSTRAINT_VIOLATION",
    "ERR_CHALLENGE_REQUIRED",
    "ERR_REPLAY_DETECTED",
    "ERR_TRUST_BUNDLE_EXPIRED",
    "ERR_TRUST_BUNDLE_SIGNATURE_INVALID",
    "ERR_ISSUER_KEY_OUT_OF_WINDOW",
    "ERR_TRANSPARENCY_INVALID",
    "ERR_ISSUER_KEY_MISSING",
]


@dataclass(frozen=True)
class Delegation:
    parent_capability_id: str
    depth: int
    max_depth: int


@dataclass(frozen=True)
class ConstraintSet:
    resource_limits: Dict[str, int]
    spend_limits: Dict[str, int]
    api_scopes: List[str]
    rate_limits: Dict[str, int]
    environment_constraints: List[str]


@dataclass(frozen=True)
class ConstraintEvidence:
    resource_usage: Dict[str, int]
    spend_usage: Dict[str, int]
    rate_usage: Dict[str, int]
    environment: str
    api_scope: str


@dataclass(frozen=True)
class Capability:
    capability_id: str
    issuer_id: str
    issuer_kid: str
    agent_id: str
    audience: str
    allowed_actions: List[str]
    constraints: ConstraintSet
    delegation: Delegation
    policy_hash: str
    transparency_ref: str
    issued_at: str
    expires_at: str
    signature: str


@dataclass(frozen=True)
class ActionEnvelope:
    action_id: str
    agent_id: str
    capability_id: str
    audience: str
    action_type: str
    constraint_evidence: ConstraintEvidence
    timestamp: str
    agent_signature: str
    challenge_nonce: str = ""


@dataclass
class VerificationResult:
    decision: Decision = "AUTHORIZED"
    reason_codes: List[ReasonCode] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    replay_status: ReplayStatus = "UNKNOWN"
    policy_hash_seen: str = ""


class RevocationChecker(Protocol):
    def is_revoked(self, capability_id: str) -> bool: ...


class ReplayCache(Protocol):
    def mark_and_check(self, action_id: str) -> bool: ...


class WindowedReplayCache(ReplayCache, Protocol):
    def mark_and_check_within_window(
        self, action_id: str, action_timestamp: datetime, reference_time: datetime, window_seconds: int
    ) -> bool: ...


@dataclass(frozen=True)
class KeyResolutionResult:
    public_key: str = ""
    error_code: str = ""


class IssuerKeyResolver(Protocol):
    def resolve(self, issuer_id: str, issuer_kid: str, at: datetime) -> KeyResolutionResult: ...


class ChallengePolicy(Protocol):
    def requires_challenge(self, action_type: str) -> bool: ...


class PolicyEvaluator(Protocol):
    def evaluate(self, capability: Capability, action: ActionEnvelope) -> List[Tuple[ReasonCode, str]]: ...


class TransparencyVerifier(Protocol):
    def verify(self, transparency_ref: str, capability_id: str) -> Optional[str]: ...


class CryptoProvider(Protocol):
    def derive_id_from_public_key(self, public_key: str) -> str: ...
    def verify_capability_signature(self, capability: Capability, issuer_public_key: str) -> bool: ...
    def verify_action_signature(self, action: ActionEnvelope, agent_public_key: str) -> bool: ...


@dataclass(frozen=True)
class VerifyRequest:
    capability: Capability
    action: ActionEnvelope
    agent_public_key: str
    reference_time: datetime
    crypto: CryptoProvider
    expected_audience: str = ""
    expected_policy_hash: str = ""
    revocation_list: Optional[RevocationChecker] = None
    replay_cache: Optional[ReplayCache] = None
    replay_window_seconds: int = 300
    challenge_policy: Optional[ChallengePolicy] = None
    policy_evaluator: Optional[PolicyEvaluator] = None
    transparency: Optional[TransparencyVerifier] = None
    issuer_public_key: str = ""
    key_resolver: Optional[IssuerKeyResolver] = None


class AnchorOfflineVerifier:
    def verify(self, req: VerifyRequest) -> VerificationResult:
        result = VerificationResult(policy_hash_seen=req.capability.policy_hash)

        def add_reason(code: ReasonCode, reason: str) -> None:
            result.decision = "REJECTED"
            result.reason_codes.append(code)
            result.reasons.append(reason)

        if req.reference_time.tzinfo is None:
            add_reason("ERR_REFERENCE_TIME_MISSING", "reference_time is required")
            return result

        issuer_key, issuer_error = self._resolve_issuer_key(req)
        if issuer_error:
            add_reason(issuer_error, "issuer key resolution failed")
            return result
        if not issuer_key:
            add_reason("ERR_ISSUER_KEY_MISSING", "issuer key not found for issuer_id+issuer_kid")
            return result

        if req.issuer_public_key:
            try:
                derived_issuer_id = req.crypto.derive_id_from_public_key(issuer_key)
                if derived_issuer_id != req.capability.issuer_id:
                    add_reason("ERR_ISSUER_MISMATCH", "issuer_id does not match issuer public key")
            except Exception as err:  # noqa: BLE001
                add_reason("ERR_CAPABILITY_INVALID", f"invalid issuer public key: {err}")

        if not req.crypto.verify_capability_signature(req.capability, issuer_key):
            add_reason("ERR_CAPABILITY_SIGNATURE_INVALID", "capability signature invalid")

        issued_at = _parse_timestamp(req.capability.issued_at)
        expires_at = _parse_timestamp(req.capability.expires_at)
        ref_time = req.reference_time.astimezone(timezone.utc)
        if issued_at is not None and ref_time < issued_at:
            add_reason("ERR_CAPABILITY_NOT_YET_VALID", "capability is not valid yet")
        if expires_at is not None and ref_time > expires_at:
            add_reason("ERR_CAPABILITY_EXPIRED", "capability is expired")
        if req.revocation_list and req.revocation_list.is_revoked(req.capability.capability_id):
            add_reason("ERR_CAPABILITY_REVOKED", "capability is revoked")

        try:
            agent_id = req.crypto.derive_id_from_public_key(req.agent_public_key)
            if req.capability.agent_id != agent_id:
                add_reason("ERR_AGENT_MISMATCH", "capability agent_id does not match agent public key")
            if req.action.agent_id != agent_id:
                add_reason("ERR_AGENT_MISMATCH", "action agent_id does not match agent public key")
        except Exception as err:  # noqa: BLE001
            add_reason("ERR_ACTION_INVALID", f"invalid agent public key: {err}")

        if not req.crypto.verify_action_signature(req.action, req.agent_public_key):
            add_reason("ERR_ACTION_SIGNATURE_INVALID", "action signature invalid")

        if req.action.capability_id != req.capability.capability_id:
            add_reason("ERR_CAPABILITY_BINDING_MISMATCH", "action capability_id does not match capability")
        if req.action.audience != req.capability.audience:
            add_reason("ERR_AUDIENCE_MISMATCH", "action audience does not match capability audience")
        if req.expected_audience and req.action.audience != req.expected_audience:
            add_reason("ERR_AUDIENCE_MISMATCH", "action audience does not match expected audience")
        if req.expected_policy_hash and req.capability.policy_hash != req.expected_policy_hash:
            add_reason("ERR_POLICY_HASH_MISMATCH", "capability policy_hash does not match expected policy_hash")
        if req.transparency and req.capability.transparency_ref:
            transparency_error = req.transparency.verify(req.capability.transparency_ref, req.capability.capability_id)
            if transparency_error:
                add_reason("ERR_TRANSPARENCY_INVALID", f"transparency linkage verification failed: {transparency_error}")
        if req.capability.delegation.depth > req.capability.delegation.max_depth:
            add_reason("ERR_DELEGATION_DEPTH_EXCEEDED", "delegation depth exceeds max_depth")
        if req.action.action_type not in req.capability.allowed_actions:
            add_reason("ERR_ACTION_NOT_ALLOWED", "action_type not allowed by capability")

        for reason in _verify_constraints(req.capability.constraints, req.action.constraint_evidence):
            add_reason("ERR_CONSTRAINT_VIOLATION", reason)

        if req.challenge_policy and req.challenge_policy.requires_challenge(req.action.action_type):
            if not req.action.challenge_nonce:
                add_reason("ERR_CHALLENGE_REQUIRED", "challenge_nonce required for high-risk action")
        if req.policy_evaluator:
            for code, reason in req.policy_evaluator.evaluate(req.capability, req.action):
                add_reason(code, reason)

        if req.replay_cache:
            replay_detected = False
            action_ts = _parse_timestamp(req.action.timestamp)
            if action_ts is not None and hasattr(req.replay_cache, "mark_and_check_within_window"):
                replay_detected = getattr(req.replay_cache, "mark_and_check_within_window")(
                    req.action.action_id, action_ts, ref_time, max(req.replay_window_seconds, 1)
                )
            else:
                replay_detected = req.replay_cache.mark_and_check(req.action.action_id)
            if replay_detected:
                result.replay_status = "REPLAY"
                add_reason("ERR_REPLAY_DETECTED", "replay detected for action_id")
            else:
                result.replay_status = "FRESH"

        return result

    def _resolve_issuer_key(self, req: VerifyRequest) -> Tuple[str, str]:
        if req.issuer_public_key:
            return req.issuer_public_key, ""
        if req.key_resolver is None:
            return "", ""
        resolved = req.key_resolver.resolve(req.capability.issuer_id, req.capability.issuer_kid, req.reference_time)
        return resolved.public_key, resolved.error_code


def _parse_timestamp(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    except ValueError:
        return None


def _verify_constraints(constraints: ConstraintSet, evidence: ConstraintEvidence) -> List[str]:
    reasons: List[str] = []
    if constraints.api_scopes and evidence.api_scope not in constraints.api_scopes:
        reasons.append("api_scope is not allowed by capability constraints")
    if constraints.environment_constraints and evidence.environment not in constraints.environment_constraints:
        reasons.append("environment is not allowed by capability constraints")

    for key in sorted(evidence.resource_usage):
        if key not in constraints.resource_limits:
            reasons.append(f"resource usage for {key} is not permitted")
            continue
        if evidence.resource_usage[key] > constraints.resource_limits[key]:
            reasons.append(f"resource usage for {key} exceeds limit")
    for key in sorted(evidence.spend_usage):
        if key not in constraints.spend_limits:
            reasons.append(f"spend usage for {key} is not permitted")
            continue
        if evidence.spend_usage[key] > constraints.spend_limits[key]:
            reasons.append(f"spend usage for {key} exceeds limit")
    for key in sorted(evidence.rate_usage):
        if key not in constraints.rate_limits:
            reasons.append(f"rate usage for {key} is not permitted")
            continue
        if evidence.rate_usage[key] > constraints.rate_limits[key]:
            reasons.append(f"rate usage for {key} exceeds limit")
    return reasons
