"""对外入口：verify_zip(path) -> Verdict。"""
from __future__ import annotations

import os

from .content import check_contents
from .records import ParseError, find_eocd_candidates, parse_central_directory
from .structure import check_structure
from .verdict import Decision, Verdict


def verify_zip(path: str | os.PathLike[str]) -> Verdict:
    """核验单个 ZIP 文件，返回接收或隔离结论。只读输入，不做任何修改。

    完整文件必须能且只能得到一种有效解析：对所有对齐文件末尾的
    EOCD 候选逐一做结构核验，恰好一个通过时才继续核对条目内容。
    """
    try:
        with open(path, "rb") as fp:
            file_size = os.fstat(fp.fileno()).st_size
            try:
                candidates = find_eocd_candidates(fp, file_size)
            except ParseError as exc:
                return Verdict(Decision.QUARANTINE, str(exc))
            structural = []
            first_error: str | None = None
            for eocd in candidates:
                try:
                    entries = parse_central_directory(fp, eocd)
                    structural.append(check_structure(fp, file_size, eocd, entries))
                except ParseError as exc:
                    if first_error is None:
                        first_error = str(exc)
            if not structural:
                return Verdict(Decision.QUARANTINE,
                               first_error or "未找到有效的归档结构")
            if len(structural) > 1:
                return Verdict(Decision.QUARANTINE, "归档存在多种有效解析")
            try:
                check_contents(fp, structural[0])
            except ParseError as exc:
                return Verdict(Decision.QUARANTINE, str(exc))
            return Verdict(Decision.ACCEPT, "结构与内容核验通过")
    except OSError as exc:
        return Verdict(Decision.QUARANTINE, f"无法读取文件: {exc}")
