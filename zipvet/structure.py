"""结构一致性核验：目录与本地条目一一对应、布局无缝隙无重叠无尾随。"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO

from .records import (DD_SIG, CentralEntry, EndOfCentralDirectory, ParseError,
                      parse_local_header)

FLAG_DATA_DESCRIPTOR = 0x08


@dataclass(frozen=True)
class ResolvedEntry:
    """结构核验通过的条目：中央目录记录 + 压缩数据位置。"""
    central: CentralEntry
    data_offset: int


def _resolve_data_descriptor(fp: BinaryIO, entry: CentralEntry, dd_offset: int) -> int:
    """确定数据描述符长度（12 或 16 字节），其值必须与中央目录一致。

    CRC32 恰好等于描述符签名时，有签名与无签名两种形式都可能匹配；
    若两种解释同时成立则布局存在二义，拒绝接收。
    """
    fp.seek(dd_offset)
    raw = fp.read(16)
    if len(raw) < 12:
        raise ParseError("数据描述符不完整")
    expect = struct.pack("<III", entry.crc32, entry.compressed_size,
                         entry.uncompressed_size)
    with_sig = raw[:4] == struct.pack("<I", DD_SIG) and raw[4:16] == expect
    without_sig = raw[:12] == expect
    if with_sig and without_sig:
        raise ParseError("数据描述符布局存在二义")
    if with_sig:
        return 16
    if without_sig:
        return 12
    raise ParseError("数据描述符与中央目录声明不一致")


def check_structure(fp: BinaryIO, file_size: int, eocd: EndOfCentralDirectory,
                    entries: list[CentralEntry]) -> list[ResolvedEntry]:
    """核验整体布局，返回解析后的条目列表；失败抛 ParseError。"""
    if eocd.cd_offset + eocd.cd_size != eocd.offset:
        raise ParseError("中央目录与 EOCD 之间存在空隙或重叠")
    if eocd.offset + 22 + len(eocd.comment) != file_size:
        raise ParseError("EOCD 之后存在尾随内容")

    seen_offsets: set[int] = set()
    extents: list[tuple[int, int]] = []
    resolved: list[ResolvedEntry] = []
    for entry in entries:
        lfh_off = entry.local_header_offset
        if lfh_off in seen_offsets:
            raise ParseError("多条中央目录记录共用同一本地条目")
        seen_offsets.add(lfh_off)
        local = parse_local_header(fp, lfh_off)
        if local.name != entry.name:
            raise ParseError("本地头与中央目录文件名不一致")
        if local.method != entry.method or local.flags != entry.flags:
            raise ParseError("本地头与中央目录的方法或标志不一致")
        if local.flags & FLAG_DATA_DESCRIPTOR:
            for field_name, local_val, central_val in (
                    ("CRC32", local.crc32, entry.crc32),
                    ("压缩大小", local.compressed_size, entry.compressed_size),
                    ("原始大小", local.uncompressed_size, entry.uncompressed_size)):
                if local_val not in (0, central_val):
                    raise ParseError(f"本地头{field_name}与中央目录矛盾")
            dd_len = _resolve_data_descriptor(
                fp, entry, local.data_offset + entry.compressed_size)
        else:
            if (local.crc32, local.compressed_size, local.uncompressed_size) != \
                    (entry.crc32, entry.compressed_size, entry.uncompressed_size):
                raise ParseError("本地头与中央目录的 CRC/大小不一致")
            dd_len = 0
        data_end = local.data_offset + entry.compressed_size + dd_len
        extents.append((lfh_off, data_end))
        resolved.append(ResolvedEntry(central=entry, data_offset=local.data_offset))

    extents.sort()
    cursor = 0
    for start, end in extents:
        if start != cursor:
            raise ParseError("本地条目之间存在前置内容、空洞或重叠")
        if end <= start:
            raise ParseError("本地条目长度非法")
        cursor = end
    if cursor != eocd.cd_offset:
        raise ParseError("本地条目区与中央目录不衔接")
    return resolved
