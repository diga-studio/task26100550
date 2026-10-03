"""ZIP 结构解析：EOCD、中央目录、本地条目。

只接受单卷 ZIP32，压缩方法为 stored/deflate，
通用标志仅允许位 3（数据描述符）和位 11（UTF-8 文件名）。
解析失败一律抛出 Quarantine。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO

LFH_SIG = 0x04034B50
CD_SIG = 0x02014B50
EOCD_SIG = 0x06054B50
DD_SIG = 0x08074B50

ALLOWED_METHODS = (0, 8)  # stored, deflate
ALLOWED_FLAGS = 0x0808  # 仅位 3 与位 11
FLAG_DATA_DESCRIPTOR = 0x08

ZIP64_EXTRA_ID = 0x0001
ZIP64_SENTINEL16 = 0xFFFF
ZIP64_SENTINEL32 = 0xFFFFFFFF

EOCD_FIXED_SIZE = 22
MAX_COMMENT = 0xFFFF

_LFH_FIXED = struct.Struct("<IHHHHHIIIHH")
_CD_FIXED = struct.Struct("<IHHHHHHIIIHHHHHII")
_EOCD_FIXED = struct.Struct("<IHHHHIIH")
_EXTRA_HEAD = struct.Struct("<HH")
_DD_REST = struct.Struct("<III")


class Quarantine(Exception):
    """结构或内容不满足接收条件时抛出，消息即隔离原因。"""


@dataclass(frozen=True)
class EndOfCentralDirectory:
    """目录结束记录。"""

    offset: int
    entry_count: int
    cd_offset: int
    cd_size: int
    comment: bytes


@dataclass(frozen=True)
class CentralRecord:
    """中央目录记录。"""

    offset: int
    name: bytes
    method: int
    flags: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    local_header_offset: int


@dataclass(frozen=True)
class LocalEntry:
    """本地条目（本地文件头 + 数据区 + 可选数据描述符）。"""

    offset: int
    record: CentralRecord
    data_offset: int
    end_offset: int


def _read_at(fp: BinaryIO, offset: int, size: int, what: str) -> bytes:
    if offset < 0 or size < 0:
        raise Quarantine(f"{what}：偏移或长度为负")
    fp.seek(offset)
    data = fp.read(size)
    if len(data) != size:
        raise Quarantine(f"{what}：读取超出文件范围")
    return data


def _check_extra_fields(data: bytes, what: str) -> None:
    """附加字段必须依次由完整的类型、长度及声明内容组成。"""
    pos = 0
    while pos < len(data):
        if pos + _EXTRA_HEAD.size > len(data):
            raise Quarantine(f"{what}：附加字段头不完整")
        field_id, field_len = _EXTRA_HEAD.unpack_from(data, pos)
        pos += _EXTRA_HEAD.size
        if pos + field_len > len(data):
            raise Quarantine(f"{what}：附加字段内容超出声明长度")
        if field_id == ZIP64_EXTRA_ID:
            raise Quarantine(f"{what}：不支持 ZIP64 附加字段")
        pos += field_len


def _parse_eocd_at(buf: bytes, pos: int, base: int, file_size: int) -> EndOfCentralDirectory:
    fixed = _EOCD_FIXED.unpack_from(buf, pos)
    (
        _sig,
        disk_num,
        cd_start_disk,
        entries_this_disk,
        entries_total,
        cd_size,
        cd_offset,
        comment_len,
    ) = fixed
    file_pos = base + pos
    if file_pos + EOCD_FIXED_SIZE + comment_len != file_size:
        raise Quarantine("EOCD 声明的注释长度与文件尾不一致")
    if disk_num != 0 or cd_start_disk != 0 or entries_this_disk != entries_total:
        raise Quarantine("不支持多卷归档")
    if entries_total == ZIP64_SENTINEL16:
        raise Quarantine("条目计数使用 ZIP64 扩展")
    if cd_size == ZIP64_SENTINEL32 or cd_offset == ZIP64_SENTINEL32:
        raise Quarantine("目录长度或偏移使用 ZIP64 扩展")
    if cd_offset + cd_size != file_pos:
        raise Quarantine("中央目录与 EOCD 之间存在空隙或重叠")
    comment = buf[pos + EOCD_FIXED_SIZE : pos + EOCD_FIXED_SIZE + comment_len]
    return EndOfCentralDirectory(
        offset=file_pos,
        entry_count=entries_total,
        cd_offset=cd_offset,
        cd_size=cd_size,
        comment=bytes(comment),
    )


def find_eocd_candidates(fp: BinaryIO, file_size: int) -> list[EndOfCentralDirectory]:
    """在文件尾部扫描所有结构自洽的 EOCD 候选。

    归档注释中碰巧出现的 EOCD 签名不会遮蔽真正的结束记录：
    只有注释长度恰好覆盖到文件末尾的候选才会被返回。
    """
    if file_size < EOCD_FIXED_SIZE:
        raise Quarantine("文件太小，不是 ZIP 归档")
    window = min(file_size, EOCD_FIXED_SIZE + MAX_COMMENT)
    buf = _read_at(fp, file_size - window, window, "EOCD 扫描窗口")
    base = file_size - window
    candidates: list[EndOfCentralDirectory] = []
    sig = struct.pack("<I", EOCD_SIG)
    pos = buf.rfind(sig)
    while pos != -1:
        if pos + EOCD_FIXED_SIZE <= len(buf):
            try:
                candidates.append(_parse_eocd_at(buf, pos, base, file_size))
            except Quarantine:
                pass
        pos = buf.rfind(sig, 0, pos)
    if not candidates:
        raise Quarantine("未找到有效的目录结束记录")
    return candidates


def parse_central_directory(
    fp: BinaryIO, eocd: EndOfCentralDirectory
) -> list[CentralRecord]:
    """按 EOCD 声明解析中央目录，长度必须与声明完全一致。"""
    buf = _read_at(fp, eocd.cd_offset, eocd.cd_size, "中央目录")
    records: list[CentralRecord] = []
    pos = 0
    for _ in range(eocd.entry_count):
        if pos + _CD_FIXED.size > len(buf):
            raise Quarantine("中央目录记录不完整")
        fixed = _CD_FIXED.unpack_from(buf, pos)
        (
            sig,
            _ver_made,
            _ver_need,
            flags,
            method,
            _mtime,
            _mdate,
            crc32,
            csize,
            usize,
            nlen,
            elen,
            clen,
            disk_start,
            _iattr,
            _eattr,
            lho,
        ) = fixed
        if sig != CD_SIG:
            raise Quarantine("中央目录记录签名错误")
        rec_offset = eocd.cd_offset + pos
        pos += _CD_FIXED.size
        if pos + nlen + elen + clen > len(buf):
            raise Quarantine("中央目录记录的文件名或附加字段越界")
        name = bytes(buf[pos : pos + nlen])
        extra = buf[pos + nlen : pos + nlen + elen]
        pos += nlen + elen + clen
        if flags & ~ALLOWED_FLAGS:
            raise Quarantine("中央目录记录包含不支持的通用标志位")
        if method not in ALLOWED_METHODS:
            raise Quarantine("中央目录记录使用不支持的压缩方法")
        if disk_start != 0:
            raise Quarantine("不支持多卷归档")
        if ZIP64_SENTINEL32 in (crc32, csize, usize, lho):
            raise Quarantine("中央目录记录使用 ZIP64 扩展")
        _check_extra_fields(extra, "中央目录记录")
        records.append(
            CentralRecord(
                offset=rec_offset,
                name=name,
                method=method,
                flags=flags,
                crc32=crc32,
                compressed_size=csize,
                uncompressed_size=usize,
                local_header_offset=lho,
            )
        )
    if pos != len(buf):
        raise Quarantine("中央目录实际长度与 EOCD 声明不一致")
    offsets = [r.local_header_offset for r in records]
    if len(set(offsets)) != len(offsets):
        raise Quarantine("多条中央目录记录共用同一本地条目")
    return records


def _parse_data_descriptor(
    fp: BinaryIO, dd_pos: int, limit: int, record: CentralRecord
) -> int:
    """解析数据描述符，返回条目结束偏移。

    CRC32 恰好等于描述符签名时，有签名与无签名两种形式都可能成立；
    取与中央目录数值一致的唯一解释，两种都成立则无法唯一解析。
    """
    first = _read_at(fp, dd_pos, 4, "数据描述符")
    (head,) = struct.unpack("<I", first)
    ends: set[int] = set()
    if head == DD_SIG:
        # 解释一：带签名，数值在签名之后。
        if dd_pos + 4 + _DD_REST.size <= limit:
            crc, csize, usize = _DD_REST.unpack(
                _read_at(fp, dd_pos + 4, _DD_REST.size, "数据描述符")
            )
            if (crc, csize, usize) == (
                record.crc32,
                record.compressed_size,
                record.uncompressed_size,
            ):
                ends.add(dd_pos + 4 + _DD_REST.size)
        # 解释二：无签名，CRC32 恰好等于签名值。
        if record.crc32 == DD_SIG and dd_pos + _DD_REST.size <= limit:
            csize, usize = struct.unpack(
                "<II", _read_at(fp, dd_pos + 4, 8, "数据描述符")
            )
            if (csize, usize) == (record.compressed_size, record.uncompressed_size):
                ends.add(dd_pos + _DD_REST.size)
    else:
        if dd_pos + _DD_REST.size > limit:
            raise Quarantine("数据描述符超出中央目录边界")
        crc, csize, usize = struct.unpack(
            "<III", first + _read_at(fp, dd_pos + 4, 8, "数据描述符")
        )
        if (crc, csize, usize) != (
            record.crc32,
            record.compressed_size,
            record.uncompressed_size,
        ):
            raise Quarantine("数据描述符数值与中央目录不一致")
        ends.add(dd_pos + _DD_REST.size)
    if not ends:
        raise Quarantine("数据描述符数值与中央目录不一致")
    if len(ends) > 1:
        raise Quarantine("数据描述符存在多种有效解析")
    return ends.pop()


def parse_local_entries(
    fp: BinaryIO, records: list[CentralRecord], cd_offset: int
) -> list[LocalEntry]:
    """从文件起点顺序解析本地条目，必须恰好铺满到中央目录起点。"""
    by_offset = {r.local_header_offset: r for r in records}
    entries: list[LocalEntry] = []
    matched: set[int] = set()
    pos = 0
    while pos < cd_offset:
        fixed = _LFH_FIXED.unpack(_read_at(fp, pos, _LFH_FIXED.size, "本地文件头"))
        (
            sig,
            _ver,
            flags,
            method,
            _mtime,
            _mdate,
            crc32,
            csize,
            usize,
            nlen,
            elen,
        ) = fixed
        if sig != LFH_SIG:
            raise Quarantine(f"偏移 {pos} 处不是本地文件头")
        if pos + _LFH_FIXED.size + nlen + elen > cd_offset:
            raise Quarantine("本地文件头的文件名或附加字段越界")
        name = _read_at(fp, pos + _LFH_FIXED.size, nlen, "本地文件名")
        extra = _read_at(fp, pos + _LFH_FIXED.size + nlen, elen, "本地附加字段")
        record = by_offset.get(pos)
        if record is None:
            raise Quarantine("存在未被中央目录引用的本地条目")
        matched.add(pos)
        if flags & ~ALLOWED_FLAGS:
            raise Quarantine("本地文件头包含不支持的通用标志位")
        if method not in ALLOWED_METHODS:
            raise Quarantine("本地文件头使用不支持的压缩方法")
        if name != record.name:
            raise Quarantine("本地文件头与中央目录的文件名不一致")
        if method != record.method or flags != record.flags:
            raise Quarantine("本地文件头与中央目录的方法或标志不一致")
        _check_extra_fields(extra, "本地文件头")
        data_offset = pos + _LFH_FIXED.size + nlen + elen
        data_end = data_offset + record.compressed_size
        if data_end > cd_offset:
            raise Quarantine("压缩数据越过中央目录边界")
        if flags & FLAG_DATA_DESCRIPTOR:
            for value, central_value, label in (
                (crc32, record.crc32, "CRC32"),
                (csize, record.compressed_size, "压缩大小"),
                (usize, record.uncompressed_size, "原始大小"),
            ):
                if value not in (0, central_value):
                    raise Quarantine(f"本地文件头{label}与中央目录矛盾")
            end = _parse_data_descriptor(fp, data_end, cd_offset, record)
        else:
            if (crc32, csize, usize) != (
                record.crc32,
                record.compressed_size,
                record.uncompressed_size,
            ):
                raise Quarantine("本地文件头数值与中央目录不一致")
            end = data_end
        entries.append(
            LocalEntry(offset=pos, record=record, data_offset=data_offset, end_offset=end)
        )
        pos = end
    if matched != set(by_offset):
        raise Quarantine("中央目录引用了不存在的本地条目")
    return entries
