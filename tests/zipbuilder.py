"""手工构造 ZIP 字节流的测试辅助：精确控制描述符、标志、注释与各类篡改。"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

DD_SIG = 0x08074B50


def deflate_raw(data: bytes, level: int = 9) -> bytes:
    obj = zlib.compressobj(level, zlib.DEFLATED, -15)
    return obj.compress(data) + obj.flush()


def find_suffix_for_crc(target: int, prefix: bytes = b"") -> bytes:
    """求 4 字节后缀使 crc32(prefix + suffix) == target（CRC 对 4 字节为双射）。"""
    base = zlib.crc32(prefix + b"\x00" * 4)
    cols = []
    for i in range(32):
        suffix = bytearray(4)
        suffix[i // 8] = 1 << (i % 8)
        cols.append(zlib.crc32(prefix + bytes(suffix)) ^ base)
    rhs = target ^ base
    # 高斯消元：第 bit 行表示该输出位的方程
    rows = []
    for bit in range(32):
        mask = 0
        for i in range(32):
            if (cols[i] >> bit) & 1:
                mask |= 1 << i
        rows.append([mask, (rhs >> bit) & 1])
    for col in range(32):
        pivot = next(r for r in range(col, 32) if (rows[r][0] >> col) & 1)
        rows[col], rows[pivot] = rows[pivot], rows[col]
        for r in range(32):
            if r != col and (rows[r][0] >> col) & 1:
                rows[r][0] ^= rows[col][0]
                rows[r][1] ^= rows[col][1]
    solution = 0
    for col in range(32):
        if rows[col][1]:
            solution |= 1 << col
    suffix = solution.to_bytes(4, "little")
    assert zlib.crc32(prefix + suffix) == target
    return suffix


@dataclass
class EntrySpec:
    name: bytes
    data: bytes
    method: int = 8
    use_dd: bool = False
    dd_with_sig: bool = True
    utf8: bool = False
    local_extra: bytes = b""
    central_extra: bytes = b""
    comment: bytes = b""
    compressed_override: bytes | None = None   # 替换压缩数据（用于夹带/截断）
    local_crc: int | None = None
    local_comp: int | None = None
    local_uncomp: int | None = None
    cd_crc: int | None = None
    cd_comp: int | None = None
    cd_uncomp: int | None = None
    cd_name: bytes | None = None
    cd_method: int | None = None
    cd_flags: int | None = None
    cd_lfh_offset: int | None = None           # 覆盖目录中的本地头偏移
    flags_extra: int = 0                        # 额外通用标志位（如加密位）


def build_zip(entries: list[EntrySpec], comment: bytes = b"",
              cd_order: list[int] | None = None,
              preamble: bytes = b"", trailer: bytes = b"") -> bytes:
    """按规范构造归档；cd_order 指定中央目录顺序（下标排列）。"""
    flags_base = 0
    local_parts: list[bytes] = []
    central_parts: list[bytes] = []
    offset = len(preamble)
    for spec in entries:
        flags = flags_base | spec.flags_extra
        if spec.use_dd:
            flags |= 0x08
        if spec.utf8:
            flags |= 0x800
        if spec.compressed_override is not None:
            comp = spec.compressed_override
        elif spec.method == 0:
            comp = spec.data
        else:
            comp = deflate_raw(spec.data)
        crc = zlib.crc32(spec.data)
        uncomp = len(spec.data)
        # 本地头：启用描述符时按惯例置零（除非显式覆盖）
        if spec.use_dd:
            l_crc = spec.local_crc if spec.local_crc is not None else 0
            l_comp = spec.local_comp if spec.local_comp is not None else 0
            l_uncomp = spec.local_uncomp if spec.local_uncomp is not None else 0
        else:
            l_crc = spec.local_crc if spec.local_crc is not None else crc
            l_comp = spec.local_comp if spec.local_comp is not None else len(comp)
            l_uncomp = spec.local_uncomp if spec.local_uncomp is not None else uncomp
        lfh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, spec.method,
                          0, 0, l_crc, l_comp, l_uncomp,
                          len(spec.name), len(spec.local_extra))
        lfh += spec.name + spec.local_extra + comp
        if spec.use_dd:
            dd = struct.pack("<III", crc, len(comp), uncomp)
            if spec.dd_with_sig:
                dd = struct.pack("<I", DD_SIG) + dd
            lfh += dd
        local_parts.append(lfh)
        cd_flags = spec.cd_flags if spec.cd_flags is not None else flags
        central = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50, 20, 20, cd_flags,
            spec.cd_method if spec.cd_method is not None else spec.method,
            0, 0,
            spec.cd_crc if spec.cd_crc is not None else crc,
            spec.cd_comp if spec.cd_comp is not None else len(comp),
            spec.cd_uncomp if spec.cd_uncomp is not None else uncomp,
            len(spec.cd_name) if spec.cd_name is not None else len(spec.name),
            len(spec.central_extra), len(spec.comment),
            0, 0, 0,
            spec.cd_lfh_offset if spec.cd_lfh_offset is not None else offset)
        central += (spec.cd_name if spec.cd_name is not None else spec.name)
        central += spec.central_extra + spec.comment
        central_parts.append(central)
        offset += len(lfh)
    cd_offset = len(preamble) + sum(len(p) for p in local_parts)
    if cd_order is not None:
        central_parts = [central_parts[i] for i in cd_order]
    cd = b"".join(central_parts)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
                       len(cd), cd_offset, len(comment)) + comment
    return preamble + b"".join(local_parts) + cd + eocd + trailer
