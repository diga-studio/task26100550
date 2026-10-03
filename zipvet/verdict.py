"""核验结论类型定义。"""
from __future__ import annotations

import enum


class Decision(enum.Enum):
    ACCEPT = "accept"
    QUARANTINE = "quarantine"


class Verdict:
    """核验结论：接收或隔离，附原因。"""

    __slots__ = ("decision", "reason")

    def __init__(self, decision: Decision, reason: str = "") -> None:
        self.decision = decision
        self.reason = reason

    @property
    def accepted(self) -> bool:
        return self.decision is Decision.ACCEPT

    def __repr__(self) -> str:
        return f"Verdict({self.decision.value!r}, {self.reason!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Verdict):
            return NotImplemented
        return self.decision is other.decision and self.reason == other.reason
