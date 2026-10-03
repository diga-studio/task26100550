"""合法归档应被接收的场景。"""
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

import zipfile

from zipbuilder import DD_SIG, EntrySpec, build_zip, find_suffix_for_crc
from zipvet import Decision, verify_zip


def make(tmp_path: Path, data: bytes, name: str = "sample.zip") -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_empty_archive_accepted(tmp_path):
    p = make(tmp_path, build_zip([]))
    assert verify_zip(p).decision is Decision.ACCEPT


def test_empty_archive_with_comment_accepted(tmp_path):
    p = make(tmp_path, build_zip([], comment=b"release notes"))
    assert verify_zip(p).decision is Decision.ACCEPT


def test_central_order_differs_from_local_order(tmp_path):
    entries = [EntrySpec(name=b"a.txt", data=b"aaa"),
               EntrySpec(name=b"b.txt", data=b"bbb", method=0),
               EntrySpec(name=b"c.txt", data=b"ccc" * 100)]
    p = make(tmp_path, build_zip(entries, cd_order=[2, 0, 1]))
    assert verify_zip(p).decision is Decision.ACCEPT


def test_data_descriptor_with_and_without_signature(tmp_path):
    entries = [
        EntrySpec(name=b"sig.bin", data=b"with signature " * 20,
                  use_dd=True, dd_with_sig=True),
        EntrySpec(name=b"nosig.bin", data=b"without signature " * 20,
                  use_dd=True, dd_with_sig=False),
        EntrySpec(name=b"plain.bin", data=b"no descriptor"),
    ]
    p = make(tmp_path, build_zip(entries))
    assert verify_zip(p).decision is Decision.ACCEPT


def test_crc32_equal_to_dd_signature_both_forms(tmp_path):
    suffix = find_suffix_for_crc(DD_SIG, b"payload-")
    data = b"payload-" + suffix
    assert zlib.crc32(data) == DD_SIG
    for with_sig in (True, False):
        entries = [EntrySpec(name=b"tricky.bin", data=data,
                             use_dd=True, dd_with_sig=with_sig)]
        p = make(tmp_path, build_zip(entries), name=f"crc_sig_{with_sig}.zip")
        verdict = verify_zip(p)
        assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_fake_eocd_inside_archive_comment(tmp_path):
    fake_cd_offset = 12345
    fake_eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 9, 9, 500,
                            fake_cd_offset, 0)
    comment = b"notes " + fake_eocd + b" end"
    entries = [EntrySpec(name=b"x.txt", data=b"content")]
    p = make(tmp_path, build_zip(entries, comment=comment))
    verdict = verify_zip(p)
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_zip_signature_bytes_inside_file_content(tmp_path):
    blob = struct.pack("<IIII", 0x04034B50, 0x02014B50, 0x06054B50, 0x08074B50)
    entries = [EntrySpec(name=b"sigs.bin", data=blob * 10)]
    p = make(tmp_path, build_zip(entries))
    assert verify_zip(p).decision is Decision.ACCEPT


def test_file_comment_and_utf8_flag_accepted(tmp_path):
    entries = [EntrySpec(name="文件.txt".encode(), data="内容".encode() * 30,
                         utf8=True, comment=b"per-file comment")]
    p = make(tmp_path, build_zip(entries, comment="归档注释".encode()))
    assert verify_zip(p).decision is Decision.ACCEPT


def test_unknown_extra_fields_accepted(tmp_path):
    extra = struct.pack("<HH", 0xCAFE, 5) + b"meta!" + struct.pack("<HH", 0x000A, 0)
    entries = [EntrySpec(name=b"e.bin", data=b"extra fields",
                         local_extra=extra, central_extra=extra)]
    p = make(tmp_path, build_zip(entries))
    assert verify_zip(p).decision is Decision.ACCEPT


def test_dd_with_local_header_values_matching_directory(tmp_path):
    # 启用描述符时本地头字段允许为零，也允许与目录一致
    data = b"local header mirrors directory"
    comp_len = len(build_zip([EntrySpec(name=b"t", data=data, use_dd=True)]))
    spec = EntrySpec(name=b"t.bin", data=data, use_dd=True)
    raw = build_zip([spec])
    # 用与目录一致的值重写本地头三字段
    import zlib as _z
    crc = _z.crc32(data)
    from zipbuilder import deflate_raw
    comp = deflate_raw(data)
    patched = bytearray(raw)
    struct.pack_into("<III", patched, 14, crc, len(comp), len(data))
    p = make(tmp_path, bytes(patched))
    assert verify_zip(p).decision is Decision.ACCEPT


def test_stdlib_zipfile_roundtrip(tmp_path):
    # 与独立生成的原始内容核对：zipfile 创建 -> 本库接收 -> 内容一致
    payload = {f"dir/file{i}.txt": (f"content-{i}-" * (i * 37 + 1)).encode()
               for i in range(20)}
    p = tmp_path / "stdlib.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.comment = b"stdlib comment"
        for name, blob in payload.items():
            zf.writestr(name, blob)
    assert verify_zip(p).decision is Decision.ACCEPT
    with zipfile.ZipFile(p) as zf:
        for name, blob in payload.items():
            assert zf.read(name) == blob
            assert zf.getinfo(name).CRC == zlib.crc32(blob)


def test_input_file_not_modified(tmp_path):
    entries = [EntrySpec(name=b"a", data=b"data" * 100, use_dd=True)]
    p = make(tmp_path, build_zip(entries, comment=b"c"))
    before = p.read_bytes()
    stat_before = p.stat()
    verify_zip(p)
    assert p.read_bytes() == before
    assert p.stat().st_mtime_ns == stat_before.st_mtime_ns
