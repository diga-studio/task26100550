"""核验编排与解压内容校验。

对每个条目核对真实解压内容的 CRC32 与字节数；
deflate 数据区必须恰好是一个完整流。全部条目展开总量上限 1 GiB。
解压按小块流式进行，峰值内存与压缩率无关。
"""

from __future__ import annotations

import zlib
from typing import BinaryIO, Iterator

from .parser import (
    Quarantine,
    find_eocd_candidates,
    parse_central_directory,
    parse_local_entries,
)
from .verdict import Decision, Verdict

TOTAL_UNCOMPRESSED_LIMIT = 1 << 30  # 1 GiB
READ_CHUNK = 1 << 20  # 1 MiB
DECOMPRESS_CHUNK = 1 << 20  # 单次解压输出上限，约束峰值内存


def _read_chunks(fp: BinaryIO, offset: int, size: int) -> Iterator[bytes]:
    pos = offset
    remaining = size
    while remaining > 0:
        step = min(READ_CHUNK, remaining)
        fp.seek(pos)
        data = fp.read(step)
        if len(data) != step:
            raise Quarantine("压缩数据读取超出文件范围")
        yield data
        pos += step
        remaining -= step


class _Budget:
    """跨条目共享的展开字节预算。"""

    def __init__(self) -> None:
        self.total = 0

    def consume(self, amount: int) -> None:
        if self.total + amount > TOTAL_UNCOMPRESSED_LIMIT:
            raise Quarantine("全部条目展开总量超过 1 GiB 上限")
        self.total += amount


def _check_stored(fp: BinaryIO, offset: int, size: int, budget: _Budget) -> tuple[int, int]:
    crc = 0
    count = 0
    for chunk in _read_chunks(fp, offset, size):
        crc = zlib.crc32(chunk, crc)
        count += len(chunk)
    budget.consume(count)
    return crc, count


def _check_deflate(fp: BinaryIO, offset: int, size: int, budget: _Budget) -> tuple[int, int]:
    decomp = zlib.decompressobj(-15)
    crc = 0
    count = 0
    fed = 0
    for chunk in _read_chunks(fp, offset, size):
        fed += len(chunk)
        data = chunk
        while True:
            if decomp.eof:
                raise Quarantine("deflate 流结束后夹带额外数据")
            out = decomp.decompress(data, DECOMPRESS_CHUNK)
            crc = zlib.crc32(out, crc)
            count += len(out)
            budget.consume(len(out))
            if decomp.eof:
                if decomp.unused_data:
                    raise Quarantine("deflate 流结束后夹带额外数据")
                if fed < size or decomp.unconsumed_tail:
                    raise Quarantine("deflate 流结束后夹带额外数据")
                break
            if decomp.unconsumed_tail:
                data = decomp.unconsumed_tail
                continue
            if len(out) == DECOMPRESS_CHUNK:
                # 输出达到单次上限且输入已耗尽：用空输入取回悬挂输出
                data = b""
                continue
            break
    if not decomp.eof:
        raise Quarantine("deflate 流被截断")
    return crc, count


def check_entry_data(
    fp: BinaryIO, method: int, data_offset: int, compressed_size: int, budget: _Budget
) -> tuple[int, int]:
    """核对单个条目的真实解压内容，返回 (CRC32, 展开字节数)。"""
    if method == 0:
        return _check_stored(fp, data_offset, compressed_size, budget)
    return _check_deflate(fp, data_offset, compressed_size, budget)


def _verify_with_eocd(fp: BinaryIO, eocd) -> None:
    records = parse_central_directory(fp, eocd)
    entries = parse_local_entries(fp, records, eocd.cd_offset)
    budget = _Budget()
    for entry in entries:
        record = entry.record
        if record.method == 0 and record.compressed_size != record.uncompressed_size:
            raise Quarantine("stored 条目压缩大小与原始大小不符")
        crc, count = check_entry_data(
            fp, record.method, entry.data_offset, record.compressed_size, budget
        )
        if crc != record.crc32:
            raise Quarantine("条目实际内容 CRC32 与声明不符")
        if count != record.uncompressed_size:
            raise Quarantine("条目实际展开大小与声明不符")


def verify_file(fp: BinaryIO, file_size: int) -> Verdict:
    """对已打开的归档文件执行完整核验。

    归档注释中的伪 EOCD 可能产生多个候选：逐一完整核验，
    恰好一个候选通过才接收，零个或多个通过都隔离。
    """
    try:
        candidates = find_eocd_candidates(fp, file_size)
    except Quarantine as exc:
        return Verdict(Decision.QUARANTINE, str(exc))
    failures: list[str] = []
    passes = 0
    for eocd in candidates:
        try:
            _verify_with_eocd(fp, eocd)
            passes += 1
        except Quarantine as exc:
            failures.append(str(exc))
    if passes == 1:
        return Verdict(Decision.ACCEPT, "结构与内容核验通过")
    if passes > 1:
        return Verdict(Decision.QUARANTINE, "归档存在多种有效解析")
    reason = failures[0] if len(failures) == 1 else "所有 EOCD 候选均核验失败"
    return Verdict(Decision.QUARANTINE, reason)
