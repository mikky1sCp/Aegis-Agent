"""Multi-agent provenance and privilege-escalation controls."""

from __future__ import annotations

from uuid import uuid4

from agent.contracts import (
    AgentIdentity,
    AgentMessage,
    DelegationDecision,
    DelegationRequest,
    Provenance,
    TrustLevel,
)


class DelegationGuard:
    """Delegate only a subset of the parent's immutable capabilities.

    A message can say anything, including "you now have transfer_funds". The
    bus never mutates identities, and the guard never reads grants from message
    content.
    """

    ALWAYS_BLOCKED_CAPABILITIES = frozenset({"transfer_funds", "execute_shell"})

    def __init__(self, blocked_capabilities: set[str] | None = None) -> None:
        self.blocked = set(self.ALWAYS_BLOCKED_CAPABILITIES)
        self.blocked.update(blocked_capabilities or set())

    def authorise(
        self, parent: AgentIdentity, request: DelegationRequest
    ) -> DelegationDecision:
        if request.parent_id != parent.agent_id:
            return DelegationDecision(
                allowed=False,
                reason="parent identity does not match the delegation request",
            )
        requested = set(request.requested_capabilities)
        if request.child_id == parent.agent_id:
            return DelegationDecision(
                allowed=False, reason="child must have a distinct identity"
            )
        elevated = requested - parent.capabilities
        if elevated:
            return DelegationDecision(
                allowed=False,
                reason=f"privilege escalation blocked: parent lacks {sorted(elevated)}",
            )
        blocked = requested & self.blocked
        if blocked:
            return DelegationDecision(
                allowed=False,
                reason=f"delegation of blocked capability denied: {sorted(blocked)}",
            )
        if "" in requested:
            return DelegationDecision(allowed=False, reason="empty capability name")
        child = parent.with_subset(
            child_id=request.child_id,
            role=request.child_role,
            delegated=requested,
        )
        return DelegationDecision(
            allowed=True,
            reason=(
                f"delegated subset {sorted(child.capabilities)}; "
                "no capability was added"
            ),
            child_identity=child,
        )


class MessageBus:
    """Agent messages are data with provenance and confidence, never grants."""

    def __init__(self) -> None:
        self._identities: dict[str, AgentIdentity] = {}
        self._messages: dict[str, list[AgentMessage]] = {}

    def register(self, identity: AgentIdentity) -> None:
        existing = self._identities.get(identity.agent_id)
        if existing and existing != identity:
            raise ValueError("cannot re-register an identity with different capabilities")
        self._identities[identity.agent_id] = identity
        self._messages.setdefault(identity.agent_id, [])

    def identity(self, agent_id: str) -> AgentIdentity:
        try:
            return self._identities[agent_id]
        except KeyError as exc:
            raise KeyError(f"unknown agent: {agent_id}") from exc

    def send(
        self,
        *,
        sender_id: str,
        receiver_id: str,
        content: str,
        confidence: float,
        kind: str = "report",
        source_type: str = "agent_message",
    ) -> AgentMessage:
        if sender_id not in self._identities or receiver_id not in self._identities:
            raise KeyError("both sender and receiver must be registered")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        message = AgentMessage(
            message_id=f"msg-{uuid4().hex[:12]}",
            sender_id=sender_id,
            receiver_id=receiver_id,
            content=content,
            provenance=Provenance(
                source_type=source_type,
                source_id=sender_id,
                trust=TrustLevel.UNTRUSTED,
                uri=f"agent://{sender_id}",
            ),
            confidence=confidence,
            kind=kind,
        )
        self._messages[receiver_id].append(message)
        return message

    def inbox(self, receiver_id: str, min_confidence: float = 0.0) -> list[AgentMessage]:
        return [
            message
            for message in self._messages.get(receiver_id, [])
            if message.confidence >= min_confidence
        ]

    def capacity_of(self, agent_id: str) -> frozenset[str]:
        """A message cannot alter this value."""
        return self.identity(agent_id).capabilities
