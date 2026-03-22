from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Dict

from verifier import (
    ActionEnvelope,
    Capability,
    ChallengePolicy,
    ConstraintEvidence,
    ConstraintSet,
    CryptoProvider,
    Delegation,
    AnchorOfflineVerifier,
    IssuerKeyResolver,
    KeyResolutionResult,
    ReplayCache,
    VerifyRequest,
)


class MemoryReplayCache(ReplayCache):
    def __init__(self) -> None:
        self._seen: Dict[str, bool] = {}

    def mark_and_check(self, action_id: str) -> bool:
        if action_id in self._seen:
            return True
        self._seen[action_id] = True
        return False


class StaticKeyResolver(IssuerKeyResolver):
    def resolve(self, issuer_id: str, issuer_kid: str, at: datetime) -> KeyResolutionResult:
        if issuer_id == "issuer-001" and issuer_kid == "kid-001":
            return KeyResolutionResult(public_key="issuer-public-key")
        return KeyResolutionResult(error_code="ERR_ISSUER_KEY_MISSING")


class StaticChallengePolicy(ChallengePolicy):
    def requires_challenge(self, action_type: str) -> bool:
        return action_type == "bank:TransferFunds"


class StaticCrypto(CryptoProvider):
    def derive_id_from_public_key(self, public_key: str) -> str:
        if public_key == "issuer-public-key":
            return "issuer-001"
        if public_key == "agent-public-key":
            return "agent-001"
        raise ValueError("unknown public key")

    def verify_capability_signature(self, capability: Capability, issuer_public_key: str) -> bool:
        return capability.signature == "capability-signature-valid"

    def verify_action_signature(self, action: ActionEnvelope, agent_public_key: str) -> bool:
        return action.agent_signature == "action-signature-valid"


def _base_constraints() -> ConstraintSet:
    return ConstraintSet(
        resource_limits={"bank:transfers": 5},
        spend_limits={"usd_cents": 10000},
        api_scopes=["bank:payments"],
        rate_limits={"requests_per_minute": 5},
        environment_constraints=["prod"],
    )


def _base_evidence() -> ConstraintEvidence:
    return ConstraintEvidence(
        resource_usage={"bank:transfers": 1},
        spend_usage={"usd_cents": 500},
        rate_usage={"requests_per_minute": 1},
        environment="prod",
        api_scope="bank:payments",
    )


def _base_capability() -> Capability:
    return Capability(
        capability_id="cap-001",
        issuer_id="issuer-001",
        issuer_kid="kid-001",
        agent_id="agent-001",
        audience="bank:prod:payments",
        allowed_actions=["bank:TransferFunds"],
        constraints=_base_constraints(),
        delegation=Delegation(parent_capability_id="", depth=0, max_depth=1),
        policy_hash="policy-hash-v2",
        transparency_ref="",
        issued_at="2026-02-13T12:00:00Z",
        expires_at="2026-02-13T13:00:00Z",
        signature="capability-signature-valid",
    )


def _base_action() -> ActionEnvelope:
    return ActionEnvelope(
        action_id="act-001",
        agent_id="agent-001",
        capability_id="cap-001",
        audience="bank:prod:payments",
        action_type="bank:TransferFunds",
        constraint_evidence=_base_evidence(),
        challenge_nonce="challenge-001",
        timestamp="2026-02-13T12:05:00Z",
        agent_signature="action-signature-valid",
    )


def _run_scenario(name: str) -> dict[str, object]:
    verifier = AnchorOfflineVerifier()
    request = VerifyRequest(
        capability=_base_capability(),
        action=_base_action(),
        agent_public_key="agent-public-key",
        reference_time=datetime(2026, 2, 13, 12, 5, tzinfo=timezone.utc),
        expected_audience="bank:prod:payments",
        expected_policy_hash="policy-hash-v2",
        replay_cache=MemoryReplayCache(),
        challenge_policy=StaticChallengePolicy(),
        key_resolver=StaticKeyResolver(),
        crypto=StaticCrypto(),
    )

    if name == "authorized":
        result = verifier.verify(request)
    elif name == "audience_mismatch":
        action = ActionEnvelope(
            action_id=request.action.action_id,
            agent_id=request.action.agent_id,
            capability_id=request.action.capability_id,
            audience="bank:prod:treasury",
            action_type=request.action.action_type,
            constraint_evidence=request.action.constraint_evidence,
            challenge_nonce=request.action.challenge_nonce,
            timestamp=request.action.timestamp,
            agent_signature=request.action.agent_signature,
        )
        result = verifier.verify(
            VerifyRequest(
                capability=request.capability,
                action=action,
                agent_public_key=request.agent_public_key,
                reference_time=request.reference_time,
                expected_audience=request.expected_audience,
                expected_policy_hash=request.expected_policy_hash,
                replay_cache=request.replay_cache,
                challenge_policy=request.challenge_policy,
                key_resolver=request.key_resolver,
                crypto=request.crypto,
            )
        )
    elif name == "challenge_required":
        action = ActionEnvelope(
            action_id=request.action.action_id,
            agent_id=request.action.agent_id,
            capability_id=request.action.capability_id,
            audience=request.action.audience,
            action_type=request.action.action_type,
            constraint_evidence=request.action.constraint_evidence,
            challenge_nonce="",
            timestamp=request.action.timestamp,
            agent_signature=request.action.agent_signature,
        )
        result = verifier.verify(
            VerifyRequest(
                capability=request.capability,
                action=action,
                agent_public_key=request.agent_public_key,
                reference_time=request.reference_time,
                expected_audience=request.expected_audience,
                expected_policy_hash=request.expected_policy_hash,
                replay_cache=request.replay_cache,
                challenge_policy=request.challenge_policy,
                key_resolver=request.key_resolver,
                crypto=request.crypto,
            )
        )
    elif name == "policy_hash_mismatch":
        request = VerifyRequest(
            capability=request.capability,
            action=request.action,
            agent_public_key=request.agent_public_key,
            reference_time=request.reference_time,
            expected_audience=request.expected_audience,
            expected_policy_hash="policy-hash-mismatch",
            replay_cache=request.replay_cache,
            challenge_policy=request.challenge_policy,
            key_resolver=request.key_resolver,
            crypto=request.crypto,
        )
        result = verifier.verify(request)
    elif name == "replay_detected":
        verifier.verify(request)
        result = verifier.verify(request)
    else:
        raise ValueError(f"unsupported scenario: {name}")

    return {
        "decision": result.decision,
        "reason_codes": result.reason_codes,
        "replay_status": result.replay_status,
        "policy_hash_seen": result.policy_hash_seen,
    }


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        raise ValueError("scenario argument is required")

    payload = _run_scenario(sys.argv[1].strip())
    sys.stdout.write(json.dumps(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
