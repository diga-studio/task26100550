"""内容核验：逐条目解压核对真实 CRC32 与字节数，限制展开总量。"""
from __future__ import annotations

import zlib
from typing import BinaryIO

from .records import METHOD_DEFLATE, METHOD_STORED, ParseError
from .structure import ResolvedEntry

EXPANDED_TOTAL_LIMIT = 1 << 30  # 1 GiB，恰好达到可接收，超过即隔离
_READ_CHUNK = 1 << 16           # 64 KiB
_DECOMPRESS_MAX = 1 << 20       # 单次解压输出上限 1 MiB，约束峰值内存


def _verify_stored(fp: BinaryIO, offset: int, size: int) -> tuple[int, int]:
    crc = 0
    total = 0
    remaining = size
    fp.seek(offset)
    while remaining:
        chunk = fp.read(min(_READ_CHUNK, remaining))
        if not chunk:
            raise ParseError("压缩数据不完整")
        crc = zlib.crc32(chunk, crc)
        total += len(chunk)
        remaining -= len(chunk)
    return crc, total


def _verify_deflate(fp: BinaryIO, offset: int, size: int) -> tuple[int, int]:
    """压缩区必须恰好是一个完整的原始 deflate 流。

    流结束后的剩余整字节（含拼接的第二个流）一律拒绝；
    最后一个字节内未使用的填充位由 zlib 自然吸收，不算夹带。
    """
    decomp = zlib.decompressobj(-15)
    crc = 0
    total = 0
    remaining = size
    fp.seek(offset)
    while remaining:
        chunk = fp.read(min(_READ_CHUNK, remaining))
        if not chunk:
            raise ParseError("压缩数据不完整")
        remaining -= len(chunk)
        if decomp.eof:
            raise ParseError("deflate 流结束后存在夹带数据")
        data = chunk
        while data:
            out = decomp.decompress(data, _DECOMPRESS_MAX)
            crc = zlib.crc32(out, crc)
            total += len(out)
            data = decomp.unconsumed_tail
            if decomp.eof:
                if decomp.unused_data or data:
                    raise ParseError("deflate 流结束后存在夹带数据")
                break
    if not decomp.eof:
        raise ParseError("deflate 流被截断")
    if decomp.unused_data:
        raise ParseError("deflate 流结束后存在夹带数据")
    return crc, total


def check_contents(fp: BinaryIO, resolved: list[ResolvedEntry]) -> None:
    """逐条目核对真实解压内容；失败抛 ParseError。"""
    expanded_total = 0
    for item in resolved:
        entry = item.central
        if entry.method == METHOD_STORED:
            if entry.compressed_size != entry.uncompressed_size:
                raise ParseError("stored 条目压缩大小与原始大小不符")
            crc, total = _verify_stored(fp, item.data_offset, entry.compressed_size)
        elif entry.method == METHOD_DEFLATE:
            crc, total = _verify_deflate(fp, item.data_offset, entry.compressed_size)
        else:
            raise ParseError(f"不支持的压缩方法: {entry.method}")
        if crc != entry.crc32:
            raise ParseError("条目实际 CRC32 与声明不符")
        if total != entry.uncompressed_size:
            raise ParseError("条目实际大小与声明不符")
        expanded_total += total
        if expanded_total > EXPANDED_TOTAL_LIMIT:
            raise ParseError("条目展开总量超过 1 GiB 上限")
