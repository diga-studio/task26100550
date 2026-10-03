"""规模上限与内存约束测试。"""

import resource
import zlib

import zipgate
from zipgate import Decision

from helpers import EntrySpec, build_archive

GIB = 1 << 30
MIB = 1 << 20


def _zeros_stream(total: int):
    """生成 total 字节全零内容的 (crc32, 压缩数据)，全程只占小块内存。"""
    chunk = b"\x00" * MIB
    crc = 0
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    parts = []
    remaining = total
    while remaining > 0:
        step = min(MIB, remaining)
        block = chunk[:step]
        crc = zlib.crc32(block, crc)
        parts.append(comp.compress(block))
        remaining -= step
    parts.append(comp.flush())
    return crc, b"".join(parts)


def _archive_of_zeros(tmp_path, total: int):
    crc, compressed = _zeros_stream(total)
    spec = EntrySpec(
        b"zeros.bin",
        b"",
        compressed_override=compressed,
        local_values=(crc, len(compressed), total),
        central_values=(crc, len(compressed), total),
    )
    path = tmp_path / "big.zip"
    path.write_bytes(build_archive([spec]))
    return path


def test_exactly_1gib_expansion_accepted(tmp_path):
    path = _archive_of_zeros(tmp_path, GIB)
    verdict = zipgate.verify_archive(path)
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_1gib_plus_one_byte_quarantined(tmp_path):
    path = _archive_of_zeros(tmp_path, GIB + 1)
    verdict = zipgate.verify_archive(path)
    assert verdict.decision is Decision.QUARANTINE
    assert "1 GiB" in verdict.reason


def test_high_ratio_expansion_memory_bounded(tmp_path):
    # 256 MiB 展开自约 256 KiB 压缩数据（约 1000:1），核验峰值内存增量须远低于 64 MiB
    path = _archive_of_zeros(tmp_path, 256 * MIB)
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    verdict = zipgate.verify_archive(path)
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assert verdict.decision is Decision.ACCEPT, verdict.reason
    assert after - before < 64 * MIB


def test_many_entries_accepted(tmp_path):
    specs = [
        EntrySpec(f"file-{i:05d}.txt".encode(), f"content-{i}".encode() * 3, method=0)
        for i in range(50000)
    ]
    path = tmp_path / "many.zip"
    path.write_bytes(build_archive(specs))
    verdict = zipgate.verify_archive(path)
    assert verdict.decision is Decision.ACCEPT, verdict.reason
