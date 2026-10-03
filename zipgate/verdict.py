"""核验结论类型定义。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Decision(Enum):
    """入库结论：接收或隔离。"""

    ACCEPT = "accept"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class Verdict:
    """对整个归档的核验结论。"""

    decision: Decision
    reason: str

    @property
    def accepted(self) -> bool:
        return self.decision is Decision.ACCEPT
