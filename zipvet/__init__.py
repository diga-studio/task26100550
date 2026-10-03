"""ZIP 入库核验库：结构伪造拦截，仅核验不修改。"""
from .api import verify_zip
from .verdict import Decision, Verdict

__all__ = ["verify_zip", "Decision", "Verdict"]
