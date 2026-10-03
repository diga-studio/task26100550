"""ZIP 记录结构的底层解析（EOCD / 中央目录 / 本地头 / 数据描述符）。"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO

EOCD_SIG = 0x06054B50
CD_SIG = 0x02014B50
LFH_SIG = 0x04034B50
DD_SIG = 0x08074B50

EOCD_MIN_LEN = 22
CD_FIXED_LEN = 46
LFH_FIXED_LEN = 30
MAX_COMMENT_LEN = 0xFFFF

ALLOWED_FLAGS = 0x0808  # 仅允许位3(数据描述符)和位11(UTF-8)
METHOD_STORED = 0
METHOD_DEFLATE = 8
ZIP64_EXTRA_ID = 0x0001

_U32_SENTINEL = 0xFFFFFFFF
_U16_SENTINEL = 0xFFFF


@dataclass(frozen=True)
class EndOfCentralDirectory:
    offset: int            # EOCD 记录本身的文件偏移
    cd_offset: int         # 中央目录起始偏移
    cd_size: int           # 中央目录字节数
    total_entries: int     # 本卷条目数
    comment: bytes         # 归档注释原始字节


@dataclass(frozen=True)
class CentralEntry:
    offset: int            # 该中央目录记录的文件偏移
    local_header_offset: int
    flags: int
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    name: bytes
    comment: bytes


@dataclass(frozen=True)
class LocalHeader:
    offset: int            # 本地头记录的文件偏移
    flags: int
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    name: bytes
    data_offset: int       # 压缩数据起始偏移


class ParseError(Exception):
    """结构解析失败，调用方据此给出隔离结论。"""


def _read_at(fp: BinaryIO, offset: int, size: int) -> bytes:
    fp.seek(offset)
    data = fp.read(size)
    if len(data) != size:
        raise ParseError(f"读取失败: offset={offset} size={size}")
    return data


def _check_extra_fields(data: bytes) -> None:
    """附加字段必须依次由完整的 (类型, 长度, 内容) 组成；ZIP64 字段不支持。"""
    pos = 0
    end = len(data)
    while pos < end:
        if pos + 4 > end:
            raise ParseError("附加字段头不完整")
        field_id, field_len = struct.unpack_from("<HH", data, pos)
        pos += 4
        if pos + field_len > end:
            raise ParseError("附加字段内容超出声明长度")
        if field_id == ZIP64_EXTRA_ID:
            raise ParseError("不支持 ZIP64 附加字段")
        pos += field_len


def find_eocd_candidates(fp: BinaryIO, file_size: int) -> list[EndOfCentralDirectory]:
    """返回所有“记录末尾恰好对齐文件末尾”的 EOCD 候选，按偏移升序。

    归档注释中的伪 EOCD 可能同样对齐，候选需由上层逐一做一致性核验；
    真正的结束记录不会被注释内的签名遮蔽。
    """
    if file_size < EOCD_MIN_LEN:
        raise ParseError("文件太小，不是 ZIP")
    window = min(file_size, EOCD_MIN_LEN + MAX_COMMENT_LEN)
    tail = _read_at(fp, file_size - window, window)
    candidates: list[EndOfCentralDirectory] = []
    first_error: str | None = None
    for pos in range(window - EOCD_MIN_LEN, -1, -1):
        if struct.unpack_from("<I", tail, pos)[0] != EOCD_SIG:
            continue
        (disk_no, cd_disk, disk_entries, total_entries,
         cd_size, cd_offset, comment_len) = struct.unpack_from("<HHHHIIH", tail, pos + 4)
        if pos + EOCD_MIN_LEN + comment_len != window:
            continue  # 声明注释长度未对齐文件末尾，不是有效结束记录
        if disk_no != 0 or cd_disk != 0 or disk_entries != total_entries:
            first_error = first_error or "不支持多卷归档"
            continue
        if total_entries == _U16_SENTINEL or cd_size == _U32_SENTINEL \
                or cd_offset == _U32_SENTINEL:
            first_error = first_error or "不支持 ZIP64"
            continue
        eocd_offset = file_size - window + pos
        comment = tail[pos + EOCD_MIN_LEN:pos + EOCD_MIN_LEN + comment_len]
        candidates.append(EndOfCentralDirectory(
            offset=eocd_offset, cd_offset=cd_offset, cd_size=cd_size,
            total_entries=total_entries, comment=comment))
    candidates.sort(key=lambda e: e.offset)
    if not candidates:
        raise ParseError(first_error or "未找到有效的 EOCD 记录")
    return candidates


def parse_central_directory(fp: BinaryIO, eocd: EndOfCentralDirectory) -> list[CentralEntry]:
    if eocd.cd_offset + eocd.cd_size > eocd.offset:
        raise ParseError("中央目录越界")
    entries: list[CentralEntry] = []
    pos = eocd.cd_offset
    cd_end = eocd.cd_offset + eocd.cd_size
    for _ in range(eocd.total_entries):
        fixed = _read_at(fp, pos, CD_FIXED_LEN)
        sig, = struct.unpack_from("<I", fixed, 0)
        if sig != CD_SIG:
            raise ParseError(f"中央目录记录签名错误: offset={pos}")
        (flags, method, crc32, comp_size, uncomp_size,
         name_len, extra_len, comment_len, disk_start,
         lfh_offset) = (fixed[8] | fixed[9] << 8,
                        fixed[10] | fixed[11] << 8,
                        *struct.unpack_from("<IIIHHH", fixed, 16),
                        struct.unpack_from("<H", fixed, 34)[0],
                        struct.unpack_from("<I", fixed, 42)[0])
        if flags & ~ALLOWED_FLAGS:
            raise ParseError(f"通用标志含不支持的位: 0x{flags:04x}")
        if method not in (METHOD_STORED, METHOD_DEFLATE):
            raise ParseError(f"不支持的压缩方法: {method}")
        if disk_start != 0:
            raise ParseError("不支持多卷归档")
        if _U32_SENTINEL in (crc32, comp_size, uncomp_size, lfh_offset):
            raise ParseError("不支持 ZIP64")
        var = _read_at(fp, pos + CD_FIXED_LEN, name_len + extra_len + comment_len)
        name = var[:name_len]
        extra = var[name_len:name_len + extra_len]
        comment = var[name_len + extra_len:]
        _check_extra_fields(extra)
        entries.append(CentralEntry(
            offset=pos, local_header_offset=lfh_offset, flags=flags, method=method,
            crc32=crc32, compressed_size=comp_size, uncompressed_size=uncomp_size,
            name=name, comment=comment))
        pos += CD_FIXED_LEN + name_len + extra_len + comment_len
    if pos != cd_end:
        raise ParseError("中央目录大小与记录不符")
    return entries


def parse_local_header(fp: BinaryIO, offset: int) -> LocalHeader:
    fixed = _read_at(fp, offset, LFH_FIXED_LEN)
    sig, = struct.unpack_from("<I", fixed, 0)
    if sig != LFH_SIG:
        raise ParseError(f"本地头签名错误: offset={offset}")
    (flags, method, crc32, comp_size, uncomp_size,
     name_len, extra_len) = (fixed[6] | fixed[7] << 8,
                             fixed[8] | fixed[9] << 8,
                             *struct.unpack_from("<IIIHH", fixed, 14))
    if flags & ~ALLOWED_FLAGS:
        raise ParseError(f"本地头通用标志含不支持的位: 0x{flags:04x}")
    if method not in (METHOD_STORED, METHOD_DEFLATE):
        raise ParseError(f"本地头不支持的压缩方法: {method}")
    if _U32_SENTINEL in (crc32, comp_size, uncomp_size):
        raise ParseError("不支持 ZIP64")
    var = _read_at(fp, offset + LFH_FIXED_LEN, name_len + extra_len)
    name = var[:name_len]
    extra = var[name_len:]
    _check_extra_fields(extra)
    return LocalHeader(
        offset=offset, flags=flags, method=method, crc32=crc32,
        compressed_size=comp_size, uncompressed_size=uncomp_size,
        name=name, data_offset=offset + LFH_FIXED_LEN + name_len + extra_len)
