"""规模与资源限制：1 GiB 展开上限、64 MiB 内存约束、大文件与海量条目。"""
import os
import resource
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from zipbuilder import EntrySpec, build_zip
from zipvet import Decision, verify_zip
from zipvet.content import EXPANDED_TOTAL_LIMIT

CHUNK = 1 << 20


def _finish_zero_archive(path: Path, total: int, crc: int, comp_size: int,
                         data_offset: int) -> None:
    name = b"zeros.bin"
    with open(path, "r+b") as fp:
        lfh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0,
                          crc, comp_size, total, len(name), 0)
        fp.seek(0)
        fp.write(lfh + name)
        # 数据偏移随名字长度变化，压缩数据整体后移已在写入时按 30+len(name) 预留
        cd_offset = data_offset + comp_size + len(name)
        fp.seek(cd_offset)
        cd = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 8, 0, 0,
                         crc, comp_size, total, len(name), 0, 0, 0, 0, 0, 0)
        fp.write(cd + name)
        eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1,
                           len(cd) + len(name), cd_offset, 0)
        fp.write(eocd)


def _make_zero_archive(path: Path, total: int) -> None:
    # 先按 30+len(name) 预留本地头空间
    name_len = len(b"zeros.bin")
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    crc = 0
    comp_size = 0
    block = b"\x00" * CHUNK
    with open(path, "wb") as fp:
        fp.write(b"\x00" * (30 + name_len))
        remaining = total
        while remaining:
            n = min(CHUNK, remaining)
            piece = block[:n]
            crc = zlib.crc32(piece, crc)
            out = comp.compress(piece)
            fp.write(out)
            comp_size += len(out)
            remaining -= n
        out = comp.flush()
        fp.write(out)
        comp_size += len(out)
    _finish_zero_archive(path, total, crc, comp_size, 30)


def _rss_bytes() -> int:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # macOS: 字节


def test_expanded_total_exactly_1gib_accepted(tmp_path):
    p = tmp_path / "exact.zip"
    _make_zero_archive(p, EXPANDED_TOTAL_LIMIT)
    assert verify_zip(p).decision is Decision.ACCEPT


def test_expanded_total_1gib_plus_one_quarantined(tmp_path):
    p = tmp_path / "overflow.zip"
    _make_zero_archive(p, EXPANDED_TOTAL_LIMIT + 1)
    verdict = verify_zip(p)
    assert verdict.decision is Decision.QUARANTINE
    assert "1 GiB" in verdict.reason


def test_high_compression_ratio_within_memory_limit(tmp_path):
    p = tmp_path / "ratio.zip"
    _make_zero_archive(p, 300 << 20)  # 300 MiB 展开自约 300 KiB 压缩数据
    before = _rss_bytes()
    verdict = verify_zip(p)
    delta = _rss_bytes() - before
    assert verdict.decision is Decision.ACCEPT
    assert delta < 64 << 20, f"峰值内存超出约束: {delta >> 20} MiB"


def test_large_stored_archive_within_memory_limit(tmp_path):
    # 500 MiB stored 大文件：流式读取，内存不随文件增长
    p = tmp_path / "large.zip"
    total = 500 << 20
    name = b"big.bin"
    rng_block = os.urandom(CHUNK)
    crc = 0
    with open(p, "wb") as fp:
        fp.write(b"\x00" * (30 + len(name)))
        remaining = total
        while remaining:
            n = min(CHUNK, remaining)
            piece = rng_block[:n]
            crc = zlib.crc32(piece, crc)
            fp.write(piece)
            remaining -= n
        cd_offset = 30 + len(name) + total
        lfh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0,
                          crc, total, total, len(name), 0)
        fp.seek(0)
        fp.write(lfh + name)
        fp.seek(cd_offset)
        cd = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0,
                         crc, total, total, len(name), 0, 0, 0, 0, 0, 0)
        fp.write(cd + name)
        fp.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1,
                             len(cd) + len(name), cd_offset, 0))
    before = _rss_bytes()
    verdict = verify_zip(p)
    delta = _rss_bytes() - before
    assert verdict.decision is Decision.ACCEPT
    assert delta < 64 << 20, f"峰值内存超出约束: {delta >> 20} MiB"


def test_many_entries_accepted(tmp_path):
    entries = [EntrySpec(name=f"f{i:05d}".encode(), data=b"", method=0)
               for i in range(50000)]
    p = tmp_path / "many.zip"
    p.write_bytes(build_zip(entries))
    assert verify_zip(p).decision is Decision.ACCEPT


def test_expanded_total_across_entries_limited(tmp_path):
    # 多条目合计超限同样隔离
    half = EXPANDED_TOTAL_LIMIT // 2 + 1
    p1 = tmp_path / "part.zip"
    _make_zero_archive(p1, half)
    raw = p1.read_bytes()
    # 提取压缩数据复用：直接构造双条目归档
    comp_len = struct.unpack_from("<I", raw, 18)[0]
    comp = raw[30 + 9:30 + 9 + comp_len]
    crc = struct.unpack_from("<I", raw, 14)[0]
    entries = []
    for nm in (b"p1.bin", b"p2.bin"):
        entries.append(EntrySpec(name=nm, data=b"", method=8,
                                 compressed_override=comp,
                                 cd_crc=crc, cd_comp=len(comp),
                                 cd_uncomp=half,
                                 local_crc=crc, local_comp=len(comp),
                                 local_uncomp=half))
    p2 = tmp_path / "double.zip"
    p2.write_bytes(build_zip(entries))
    verdict = verify_zip(p2)
    assert verdict.decision is Decision.QUARANTINE
