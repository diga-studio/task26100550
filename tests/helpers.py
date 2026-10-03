"""手工构造 ZIP 归档的辅助工具，用于精确控制字节级结构。"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

LFH_SIG = 0x04034B50
CD_SIG = 0x02014B50
EOCD_SIG = 0x06054B50
DD_SIG = 0x08074B50


def deflate_raw(content: bytes) -> bytes:
    obj = zlib.compressobj(6, zlib.DEFLATED, -15)
    return obj.compress(content) + obj.flush()


@dataclass
class EntrySpec:
    name: bytes
    content: bytes
    method: int = 8
    dd: str | None = None  # None / "signed" / "unsigned"
    flags_extra: int = 0
    local_extra: bytes = b""
    central_extra: bytes = b""
    file_comment: bytes = b""
    # 本地头数值覆盖：(crc32, csize, usize)；None 表示按规则填写
    local_values: tuple[int, int, int] | None = None
    # 中央目录数值覆盖
    central_values: tuple[int, int, int] | None = None
    # 压缩数据覆盖（默认按 method 计算）
    compressed_override: bytes | None = None
    method_local: int | None = None  # 本地头方法（默认与中央一致）
    flags_local: int | None = None  # 本地头标志（默认与中央一致）
    name_local: bytes | None = None  # 本地头文件名（默认与中央一致）


@dataclass
class BuiltEntry:
    spec: EntrySpec
    local_offset: int = 0
    crc: int = 0
    csize: int = 0
    usize: int = 0
    flags: int = 0
    compressed: bytes = b""


def _prepare(spec: EntrySpec) -> BuiltEntry:
    content = spec.content
    if spec.compressed_override is not None:
        compressed = spec.compressed_override
    elif spec.method == 0:
        compressed = content
    else:
        compressed = deflate_raw(content)
    entry = BuiltEntry(spec=spec)
    entry.crc = zlib.crc32(content)
    entry.csize = len(compressed)
    entry.usize = len(content)
    entry.flags = (0x08 if spec.dd else 0x00) | spec.flags_extra
    entry.compressed = compressed
    return entry


def _local_header(entry: BuiltEntry) -> bytes:
    spec = entry.spec
    flags = spec.flags_local if spec.flags_local is not None else entry.flags
    method = spec.method_local if spec.method_local is not None else spec.method
    name = spec.name_local if spec.name_local is not None else spec.name
    if spec.local_values is not None:
        crc, csize, usize = spec.local_values
    elif spec.dd:
        crc, csize, usize = 0, 0, 0
    else:
        crc, csize, usize = entry.crc, entry.csize, entry.usize
    head = struct.pack(
        "<IHHHHHIIIHH",
        LFH_SIG,
        20,
        flags,
        method,
        0,
        0,
        crc,
        csize,
        usize,
        len(name),
        len(spec.local_extra),
    )
    return head + name + spec.local_extra


def _data_descriptor(entry: BuiltEntry) -> bytes:
    if entry.spec.dd == "signed":
        return struct.pack("<IIII", DD_SIG, entry.crc, entry.csize, entry.usize)
    if entry.spec.dd == "unsigned":
        return struct.pack("<III", entry.crc, entry.csize, entry.usize)
    return b""


def _central_record(entry: BuiltEntry) -> bytes:
    spec = entry.spec
    crc, csize, usize = (
        spec.central_values
        if spec.central_values is not None
        else (entry.crc, entry.csize, entry.usize)
    )
    head = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        CD_SIG,
        20,
        20,
        entry.flags,
        spec.method,
        0,
        0,
        crc,
        csize,
        usize,
        len(spec.name),
        len(spec.central_extra),
        len(spec.file_comment),
        0,
        0,
        0,
        entry.local_offset,
    )
    return head + spec.name + spec.central_extra + spec.file_comment


def build_archive(
    specs: list[EntrySpec],
    archive_comment: bytes = b"",
    cd_order: list[int] | None = None,
) -> bytes:
    """按本地条目顺序拼装归档，中央目录顺序可由 cd_order 重排。"""
    entries = [_prepare(s) for s in specs]
    out = bytearray()
    for entry in entries:
        entry.local_offset = len(out)
        out += _local_header(entry)
        out += entry.compressed
        out += _data_descriptor(entry)
    cd_offset = len(out)
    order = cd_order if cd_order is not None else list(range(len(entries)))
    for idx in order:
        out += _central_record(entries[idx])
    cd_size = len(out) - cd_offset
    out += struct.pack(
        "<IHHHHIIH", EOCD_SIG, 0, 0, len(entries), len(entries), cd_size, cd_offset,
        len(archive_comment),
    )
    out += archive_comment
    return bytes(out)


def crc_patch(prefix: bytes, target: int) -> bytes:
    """计算 4 字节补丁，使 crc32(prefix + patch) == target。"""
    base = zlib.crc32(prefix + b"\x00\x00\x00\x00")
    columns = []
    for bit in range(32):
        patch = bytearray(4)
        patch[bit // 8] = 1 << (bit % 8)
        columns.append(zlib.crc32(prefix + bytes(patch)) ^ base)
    rhs = target ^ base
    # 高斯消元（GF(2)）：方程 i 为 sum_j M[i][j] x_j = rhs[i]
    matrix = []
    for i in range(32):
        row = 0
        for j in range(32):
            if (columns[j] >> i) & 1:
                row |= 1 << j
        if (rhs >> i) & 1:
            row |= 1 << 32
        matrix.append(row)
    pivot_cols = []
    r = 0
    for c in range(32):
        pivot = next((k for k in range(r, 32) if (matrix[k] >> c) & 1), None)
        if pivot is None:
            continue
        matrix[r], matrix[pivot] = matrix[pivot], matrix[r]
        for k in range(32):
            if k != r and (matrix[k] >> c) & 1:
                matrix[k] ^= matrix[r]
        pivot_cols.append(c)
        r += 1
    solution = 0
    for i, c in enumerate(pivot_cols):
        if (matrix[i] >> 32) & 1:
            solution |= 1 << c
    patch = solution.to_bytes(4, "little")
    assert zlib.crc32(prefix + patch) == target
    return prefix + patch
