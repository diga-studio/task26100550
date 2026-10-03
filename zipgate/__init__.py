"""ZIP 文件入库核验库。

对单个本地 ZIP 归档做结构伪造核验，返回接收或隔离结论。
不修改原文件，不保存解压内容。

用法::

    import zipgate

    verdict = zipgate.verify_archive("/path/to/archive.zip")
    if verdict.accepted:
        ...  # 接收
    else:
        ...  # 隔离，verdict.reason 给出原因
"""

from __future__ import annotations

import os

from .verdict import Decision, Verdict
from .verifier import verify_file

__all__ = ["Decision", "Verdict", "verify_archive"]


def verify_archive(path: "os.PathLike[str] | str") -> Verdict:
    """核验指定路径的 ZIP 归档，返回接收或隔离结论及原因。"""
    try:
        fp = open(path, "rb")
    except OSError as exc:
        return Verdict(Decision.QUARANTINE, f"无法读取文件：{exc}")
    with fp:
        try:
            file_size = os.fstat(fp.fileno()).st_size
            return verify_file(fp, file_size)
        except OSError as exc:
            return Verdict(Decision.QUARANTINE, f"读取文件失败：{exc}")
