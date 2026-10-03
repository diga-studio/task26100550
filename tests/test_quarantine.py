"""伪造或矛盾结构必须被隔离的场景。"""

import struct
import zlib

import zipgate
from zipgate import Decision

from helpers import (
    CD_SIG,
    DD_SIG,
    EOCD_SIG,
    EntrySpec,
    build_archive,
    deflate_raw,
)


def verify(tmp_path, data: bytes):
    path = tmp_path / "bad.zip"
    path.write_bytes(data)
    return zipgate.verify_archive(path)


def assert_quarantined(tmp_path, data: bytes):
    verdict = verify(tmp_path, data)
    assert verdict.decision is Decision.QUARANTINE
    assert verdict.reason
    return verdict


def test_not_a_zip(tmp_path):
    assert_quarantined(tmp_path, b"not a zip file at all")


def test_local_name_differs_from_central(tmp_path):
    spec = EntrySpec(b"central.txt", b"data" * 10, name_local=b"local.txt")
    assert_quarantined(tmp_path, build_archive([spec]))


def test_local_method_differs(tmp_path):
    spec = EntrySpec(b"a.txt", b"data" * 10, method=8, method_local=0)
    assert_quarantined(tmp_path, build_archive([spec]))


def test_local_flags_differ(tmp_path):
    spec = EntrySpec(b"a.txt", b"data" * 10, dd="signed", flags_local=0x00)
    assert_quarantined(tmp_path, build_archive([spec]))


def test_local_values_contradict_central_without_dd(tmp_path):
    spec = EntrySpec(b"a.txt", b"data" * 10, local_values=(1, 2, 3))
    assert_quarantined(tmp_path, build_archive([spec]))


def test_local_values_contradict_central_with_dd(tmp_path):
    spec = EntrySpec(b"a.txt", b"data" * 10, dd="signed", local_values=(1, 2, 3))
    assert_quarantined(tmp_path, build_archive([spec]))


def test_two_records_share_one_local_entry(tmp_path):
    # 两条中央记录指向同一本地条目
    spec_a = EntrySpec(b"a.txt", b"alpha" * 10)
    spec_b = EntrySpec(b"b.txt", b"alpha" * 10)
    data = bytearray(build_archive([spec_a, spec_b]))
    # 找到第二条中央记录，把其本地偏移改成第一条的
    cd_start = data.find(struct.pack("<I", CD_SIG))
    second = data.find(struct.pack("<I", CD_SIG), cd_start + 1)
    struct.pack_into("<I", data, second + 42, 0)
    assert_quarantined(tmp_path, bytes(data))


def test_unreferenced_local_entry(tmp_path):
    # 文件中有两个本地条目，但中央目录只引用一个
    data = build_archive([EntrySpec(b"a.txt", b"a" * 10), EntrySpec(b"b.txt", b"b" * 10)])
    # 重建：保留两个本地条目，只写一条中央记录
    specs = [EntrySpec(b"a.txt", b"a" * 10)]
    good = build_archive(specs)
    # 把 b 的本地条目插到 a 的本地条目之后、中央目录之前
    b_local = build_archive([EntrySpec(b"b.txt", b"b" * 10)])
    b_local_part = b_local[: b_local.find(struct.pack("<I", CD_SIG))]
    cd_pos = good.find(struct.pack("<I", CD_SIG))
    merged = bytearray()
    merged += good[:cd_pos]
    merged += b_local_part
    cd = bytearray(good[cd_pos:])
    # 修正 EOCD 中的目录偏移与目录内本地偏移不受影响（a 仍在 0）
    eocd_pos = len(cd) - 22
    (cd_offset,) = struct.unpack_from("<I", cd, eocd_pos + 12)
    struct.pack_into("<I", cd, eocd_pos + 12, cd_offset + len(b_local_part))
    merged += cd
    assert_quarantined(tmp_path, bytes(merged))


def test_trailing_bytes_after_deflate_stream(tmp_path):
    content = b"hello world" * 100
    compressed = deflate_raw(content) + b"\x00"  # 完整流后夹带整字节
    spec = EntrySpec(b"a.txt", content, compressed_override=compressed)
    # 中央目录声明的压缩大小包含夹带字节
    data = build_archive([spec])
    verdict = assert_quarantined(tmp_path, data)
    assert "夹带" in verdict.reason or "额外" in verdict.reason


def test_two_concatenated_deflate_streams(tmp_path):
    content = b"abc" * 50
    compressed = deflate_raw(content) + deflate_raw(content)
    spec = EntrySpec(b"a.txt", content, compressed_override=compressed)
    assert_quarantined(tmp_path, build_archive([spec]))


def test_truncated_deflate_stream(tmp_path):
    content = b"abc" * 500
    compressed = deflate_raw(content)[:-2]
    spec = EntrySpec(b"a.txt", content, compressed_override=compressed)
    assert_quarantined(tmp_path, build_archive([spec]))


def test_crc_mismatch_quarantined(tmp_path):
    content = b"real content" * 20
    spec = EntrySpec(b"a.txt", content)
    data = bytearray(build_archive([spec]))
    # 篡改压缩数据中的一个字节（保持长度不变）
    pos = 30 + len(b"a.txt") + 5
    data[pos] ^= 0xFF
    assert_quarantined(tmp_path, bytes(data))


def test_declared_size_mismatch(tmp_path):
    content = b"size check" * 30
    spec = EntrySpec(b"a.txt", content, central_values=(zlib.crc32(content), 10, 10))
    assert_quarantined(tmp_path, build_archive([spec]))


def test_encrypted_entry_quarantined(tmp_path):
    spec = EntrySpec(b"a.txt", b"secret" * 10, flags_extra=0x01)
    assert_quarantined(tmp_path, build_archive([spec]))


def test_unsupported_method_quarantined(tmp_path):
    spec = EntrySpec(b"a.txt", b"data" * 10, method=12, compressed_override=b"x" * 8)
    assert_quarantined(tmp_path, build_archive([spec]))


def test_zip64_sentinel_quarantined(tmp_path):
    spec = EntrySpec(b"a.txt", b"data" * 10)
    data = bytearray(build_archive([spec]))
    eocd_pos = data.rfind(struct.pack("<I", EOCD_SIG))
    struct.pack_into("<H", data, eocd_pos + 10, 0xFFFF)  # 条目计数 ZIP64 哨兵
    assert_quarantined(tmp_path, bytes(data))


def test_zip64_extra_field_quarantined(tmp_path):
    extra = struct.pack("<HH", 0x0001, 0)
    spec = EntrySpec(b"a.txt", b"data" * 10, central_extra=extra)
    assert_quarantined(tmp_path, build_archive([spec]))


def test_truncated_extra_field_quarantined(tmp_path):
    extra = struct.pack("<HH", 0xCAFE, 10) + b"ab"  # 声明 10 字节只有 2 字节
    spec = EntrySpec(b"a.txt", b"data" * 10, local_extra=extra)
    assert_quarantined(tmp_path, build_archive([spec]))


def test_prepended_junk_quarantined(tmp_path):
    data = build_archive([EntrySpec(b"a.txt", b"x" * 10)])
    junk = b"MZ" + data
    # 修正偏移使常规工具可能打开：EOCD 与中央目录偏移都 +2
    junk = bytearray(junk)
    eocd_pos = len(junk) - 22
    (cd_offset,) = struct.unpack_from("<I", junk, eocd_pos + 12)
    struct.pack_into("<I", junk, eocd_pos + 12, cd_offset + 2)
    cd_pos = junk.find(struct.pack("<I", CD_SIG))
    (lho,) = struct.unpack_from("<I", junk, cd_pos + 42)
    struct.pack_into("<I", junk, cd_pos + 42, lho + 2)
    assert_quarantined(tmp_path, bytes(junk))


def test_trailing_junk_after_eocd_quarantined(tmp_path):
    data = build_archive([EntrySpec(b"a.txt", b"x" * 10)])
    assert_quarantined(tmp_path, data + b"junk")


def test_gap_between_local_entries_quarantined(tmp_path):
    data = bytearray(build_archive([EntrySpec(b"a.txt", b"x" * 10),
                                    EntrySpec(b"b.txt", b"y" * 10)]))
    # 在第二个本地条目前插入空洞，并修正其偏移
    first_len = 30 + len(b"a.txt") + 10
    gap = b"\x00" * 7
    patched = data[:first_len] + gap + data[first_len:]
    cd_pos = patched.find(struct.pack("<I", CD_SIG))
    second_cd = patched.find(struct.pack("<I", CD_SIG), cd_pos + 1)
    struct.pack_into("<I", patched, second_cd + 42, first_len + len(gap))
    eocd_pos = len(patched) - 22
    (cd_offset,) = struct.unpack_from("<I", patched, eocd_pos + 12)
    struct.pack_into("<I", patched, eocd_pos + 12, cd_offset + len(gap))
    assert_quarantined(tmp_path, bytes(patched))


def test_multidisk_quarantined(tmp_path):
    data = bytearray(build_archive([EntrySpec(b"a.txt", b"x" * 10)]))
    eocd_pos = len(data) - 22
    struct.pack_into("<H", data, eocd_pos + 4, 1)  # 磁盘编号非零
    assert_quarantined(tmp_path, bytes(data))


def test_entry_count_mismatch_quarantined(tmp_path):
    data = bytearray(build_archive([EntrySpec(b"a.txt", b"x" * 10)]))
    eocd_pos = len(data) - 22
    struct.pack_into("<H", data, eocd_pos + 10, 2)  # 声称 2 条实际 1 条
    assert_quarantined(tmp_path, bytes(data))


def test_fake_eocd_shadowing_real_one(tmp_path):
    # 注释中的伪 EOCD 指向错误目录，不能据此放行伪造结构
    specs = [EntrySpec(b"real.txt", b"real" * 20)]
    good = build_archive(specs)
    fake = struct.pack("<IHHHHIIH", EOCD_SIG, 0, 0, 0, 0, 0, 0, 0)
    data = good + fake  # 尾随伪 EOCD：真实 EOCD 的注释长度不再到达文件尾
    assert_quarantined(tmp_path, data)


def test_descriptor_values_contradict_central(tmp_path):
    content = b"dd check" * 20
    spec = EntrySpec(b"a.txt", content, dd="signed")
    data = bytearray(build_archive([spec]))
    # 篡改描述符中的 CRC
    dd_pos = data.find(struct.pack("<I", DD_SIG))
    struct.pack_into("<I", data, dd_pos + 4, 0xDEADBEEF)
    assert_quarantined(tmp_path, bytes(data))


def test_harmless_looking_name_still_quarantined(tmp_path):
    # 文件名看似无害，但 CRC 错误仍须隔离
    content = b"readme" * 10
    spec = EntrySpec(b"README.txt", content)
    data = bytearray(build_archive([spec]))
    pos = 30 + len(b"README.txt")
    data[pos] ^= 0x01
    assert_quarantined(tmp_path, bytes(data))


def test_stored_content_crc_mismatch(tmp_path):
    content = b"stored payload" * 10
    spec = EntrySpec(b"doc.txt", content, method=0)
    data = bytearray(build_archive([spec]))
    pos = 30 + len(b"doc.txt")
    data[pos] ^= 0x01
    verdict = assert_quarantined(tmp_path, bytes(data))
    assert "CRC" in verdict.reason
