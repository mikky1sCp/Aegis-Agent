"""Human approval providers. All providers fail closed."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from agent.contracts import (
    ApprovalDecision,
    ApprovalDisposition,
    ApprovalRequest,
)


class ApprovalProvider(ABC):
    @abstractmethod
    def review(self, request: ApprovalRequest) -> ApprovalDecision:
        raise NotImplementedError


class DenyAllApprovals(ApprovalProvider):
    """Safe default: no human is available, so high-risk actions are denied."""

    def review(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            request_id=request.request_id,
            disposition=ApprovalDisposition.DENIED,
            approver="default-policy",
            comment="no approval provider configured",
        )


class PendingApprovals(ApprovalProvider):
    """Stop the run and surface the request; no execution occurs."""

    def review(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            request_id=request.request_id,
            disposition=ApprovalDisposition.PENDING,
            approver="human-operator",
            comment="awaiting explicit human approval",
        )


class StaticApprovals(ApprovalProvider):
    """Test/demo approver. Never construct this from model output."""

    def __init__(
        self,
        disposition: ApprovalDisposition = ApprovalDisposition.APPROVED,
        approver: str = "test-operator",
        comment: str = "approved in test",
    ) -> None:
        self.disposition = disposition
        self.approver = approver
        self.comment = comment
        self.requests: list[ApprovalRequest] = []

    def review(self, request: ApprovalRequest) -> ApprovalDecision:
        self.requests.append(request)
        return ApprovalDecision(
            request_id=request.request_id,
            disposition=self.disposition,
            approver=self.approver,
            comment=self.comment,
        )


class CallbackApprovals(ApprovalProvider):
    def __init__(
        self,
        callback: Callable[[ApprovalRequest], ApprovalDecision],
        approver: str = "callback-operator",
    ) -> None:
        self.callback = callback
        self.approver = approver
        self.requests: list[ApprovalRequest] = []

    def review(self, request: ApprovalRequest) -> ApprovalDecision:
        self.requests.append(request)
        return self.callback(request)


def approval_provider_from_mode(mode: str) -> ApprovalProvider:
    normalised = mode.strip().lower()
    if normalised == "deny":
        return DenyAllApprovals()
    if normalised == "pending":
        return PendingApprovals()
    raise ValueError(
        f"unsupported AEGIS_APPROVAL_MODE={mode!r}; use 'deny' or 'pending' "
        "(auto-approval is intentionally unavailable in production modes)"
    )
