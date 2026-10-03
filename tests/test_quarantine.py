"""应被隔离的场景：结构伪造、描述符矛盾、流夹带、不支持的形态。"""
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

import zipfile

from zipbuilder import EntrySpec, build_zip, deflate_raw
from zipvet import Decision, verify_zip


def make(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "sample.zip"
    p.write_bytes(data)
    return p


def assert_quarantined(tmp_path, data: bytes):
    verdict = verify_zip(make(tmp_path, data))
    assert verdict.decision is Decision.QUARANTINE, "应隔离但被接收"
    return verdict


def test_local_header_contradicts_directory(tmp_path):
    # 未启用描述符时本地头 CRC 与目录矛盾
    spec = EntrySpec(name=b"a.txt", data=b"hello", local_crc=0xDEADBEEF)
    assert_quarantined(tmp_path, build_zip([spec]))


def test_local_method_contradicts_directory(tmp_path):
    spec = EntrySpec(name=b"a.txt", data=b"hello", cd_method=0)
    assert_quarantined(tmp_path, build_zip([spec]))


def test_local_name_contradicts_directory(tmp_path):
    spec = EntrySpec(name=b"a.txt", data=b"hello", cd_name=b"b.txt")
    assert_quarantined(tmp_path, build_zip([spec]))


def test_dd_local_field_neither_zero_nor_matching(tmp_path):
    spec = EntrySpec(name=b"a.txt", data=b"hello", use_dd=True, local_comp=999)
    assert_quarantined(tmp_path, build_zip([spec]))


def test_dd_values_contradict_directory(tmp_path):
    raw = bytearray(build_zip([EntrySpec(name=b"a.txt", data=b"hello",
                                         use_dd=True)]))
    # 找到描述符（本地头 30 + 名字 5 + 压缩数据），篡改其 CRC
    comp = deflate_raw(b"hello")
    dd_off = 30 + 5 + len(comp)
    assert struct.unpack_from("<I", raw, dd_off)[0] == 0x08074B50
    struct.pack_into("<I", raw, dd_off + 4, 0x12345678)
    assert_quarantined(tmp_path, bytes(raw))


def test_two_records_share_one_local_entry(tmp_path):
    good = EntrySpec(name=b"a.txt", data=b"hello")
    shared = EntrySpec(name=b"b.txt", data=b"hello", cd_lfh_offset=0)
    assert_quarantined(tmp_path, build_zip([good, shared]))


def test_unreferenced_local_entry(tmp_path):
    # 两个本地条目，目录只引用第二个 -> 第一个成为未被引用的条目（前置空洞）
    raw = build_zip([EntrySpec(name=b"a.txt", data=b"aaa"),
                     EntrySpec(name=b"b.txt", data=b"bbb")])
    # 重新构造：目录两条记录都指向第二个条目之前的偏移不行，直接删掉第一条目录记录
    # 简单做法：保留全部本地数据，但 EOCD 计数减一且目录只含第二条
    entries = [EntrySpec(name=b"a.txt", data=b"aaa"),
               EntrySpec(name=b"b.txt", data=b"bbb")]
    full = build_zip(entries)
    # 手工拼装：本地区不变，目录只写第二条
    la = 30 + 5 + len(deflate_raw(b"aaa"))
    lb = 30 + 5 + len(deflate_raw(b"bbb"))
    local_region = full[:la + lb]
    cd_b = full[la + lb:][46 + 5:]  # 跳过第一条目录记录
    cd_b = cd_b[:46 + 5]
    cd_b = cd_b[:42] + struct.pack("<I", la) + cd_b[46:]  # 指向 b 的本地头
    cd = cd_b
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd),
                       la + lb, 0)
    assert_quarantined(tmp_path, local_region + cd + eocd)


def test_trailing_bytes_after_deflate_stream(tmp_path):
    data = b"stream data " * 50
    comp = deflate_raw(data) + b"\x00EXTRA"  # 完整流后夹带整字节
    spec = EntrySpec(name=b"a.txt", data=data, compressed_override=comp)
    raw = build_zip([spec])
    # 常规解压工具能打开：zipfile 接受并读出正确内容
    p = make(tmp_path, raw)
    with zipfile.ZipFile(p) as zf:
        assert zf.read("a.txt") == data
    assert verify_zip(p).decision is Decision.QUARANTINE


def test_concatenated_second_deflate_stream(tmp_path):
    data = b"first stream"
    comp = deflate_raw(data) + deflate_raw(b"second stream")
    spec = EntrySpec(name=b"a.txt", data=data, compressed_override=comp)
    assert_quarantined(tmp_path, build_zip([spec]))


def test_truncated_deflate_stream(tmp_path):
    data = b"x" * 1000
    comp = deflate_raw(data)[:-3]
    spec = EntrySpec(name=b"a.txt", data=data, compressed_override=comp)
    assert_quarantined(tmp_path, build_zip([spec]))


def test_crc_mismatch_quarantined(tmp_path):
    spec = EntrySpec(name=b"a.txt", data=b"real content", method=0,
                     cd_crc=zlib.crc32(b"other content"))
    assert_quarantined(tmp_path, build_zip([spec]))


def test_size_mismatch_quarantined(tmp_path):
    spec = EntrySpec(name=b"a.txt", data=b"real content",
                     cd_uncomp=len(b"real content") + 1)
    assert_quarantined(tmp_path, build_zip([spec]))


def test_encrypted_flag_quarantined(tmp_path):
    spec = EntrySpec(name=b"a.txt", data=b"secret", flags_extra=0x01)
    assert_quarantined(tmp_path, build_zip([spec]))


def test_unsupported_method_quarantined(tmp_path):
    spec = EntrySpec(name=b"a.txt", data=b"data", method=12,
                     compressed_override=b"whatever")
    assert_quarantined(tmp_path, build_zip([spec]))


def test_zip64_extra_field_quarantined(tmp_path):
    extra = struct.pack("<HH", 0x0001, 8) + struct.pack("<Q", 100)
    spec = EntrySpec(name=b"a.txt", data=b"data", central_extra=extra)
    assert_quarantined(tmp_path, build_zip([spec]))


def test_zip64_sentinel_sizes_quarantined(tmp_path):
    spec = EntrySpec(name=b"a.txt", data=b"data", cd_comp=0xFFFFFFFF)
    assert_quarantined(tmp_path, build_zip([spec]))


def test_multidisk_quarantined(tmp_path):
    raw = bytearray(build_zip([EntrySpec(name=b"a.txt", data=b"d")]))
    eocd_off = len(raw) - 22
    struct.pack_into("<H", raw, eocd_off + 4, 1)  # 磁盘编号非零
    assert_quarantined(tmp_path, bytes(raw))


def test_preamble_quarantined(tmp_path):
    raw = build_zip([EntrySpec(name=b"a.txt", data=b"d")],
                    preamble=b"SFX!")
    # 前置内容使目录声明的偏移与结构不符
    assert_quarantined(tmp_path, raw)


def test_trailing_content_after_eocd_quarantined(tmp_path):
    raw = build_zip([EntrySpec(name=b"a.txt", data=b"d")],
                    trailer=b"junk")
    assert_quarantined(tmp_path, raw)


def test_gap_between_local_entries_quarantined(tmp_path):
    raw = build_zip([EntrySpec(name=b"a.txt", data=b"aaa"),
                     EntrySpec(name=b"b.txt", data=b"bbb")])
    la = 30 + 5 + len(deflate_raw(b"aaa"))
    # 在两条本地条目间插入空洞，并修正第二条目录记录与 EOCD 偏移
    gap = b"\x00" * 16
    spliced = raw[:la] + gap + raw[la:]
    # 修正第二条目录记录中的本地头偏移
    first_cd = spliced.index(struct.pack("<I", 0x02014B50))
    second_cd = spliced.index(struct.pack("<I", 0x02014B50), first_cd + 4)
    old_off = struct.unpack_from("<I", spliced, second_cd + 42)[0]
    struct.pack_into("<I", spliced := bytearray(spliced), second_cd + 42,
                     old_off + 16)
    # 修正 EOCD 的目录偏移
    eocd_off = bytes(spliced).rindex(struct.pack("<I", 0x06054B50))
    struct.pack_into("<I", spliced, eocd_off + 16,
                     struct.unpack_from("<I", spliced, eocd_off + 16)[0] + 16)
    assert_quarantined(tmp_path, bytes(spliced))


def test_malformed_extra_field_quarantined(tmp_path):
    # 声明 10 字节内容但字段总长不足
    extra = struct.pack("<HH", 0xCAFE, 10) + b"abc"
    spec = EntrySpec(name=b"a.txt", data=b"data", central_extra=extra)
    assert_quarantined(tmp_path, build_zip([spec]))


def test_not_a_zip_quarantined(tmp_path):
    assert_quarantined(tmp_path, b"this is not a zip file at all")


def test_empty_file_quarantined(tmp_path):
    assert_quarantined(tmp_path, b"")


def test_fake_eocd_only_quarantined(tmp_path):
    # 文件里只有一个伪 EOCD，没有真实结构
    fake = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, 46, 0, 0)
    assert_quarantined(tmp_path, b"\x00" * 46 + fake)
