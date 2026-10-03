"""合法归档必须被接收的场景。"""

import zipfile

import zipgate
from zipgate import Decision

from helpers import DD_SIG, EOCD_SIG, EntrySpec, build_archive, crc_patch
import struct


def verify(tmp_path, data: bytes):
    path = tmp_path / "sample.zip"
    path.write_bytes(data)
    return zipgate.verify_archive(path)


def test_empty_archive_accepted(tmp_path):
    verdict = verify(tmp_path, build_archive([]))
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_empty_archive_with_comment_accepted(tmp_path):
    verdict = verify(tmp_path, build_archive([], archive_comment=b"hello archive"))
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_stdlib_zipfile_archive_accepted(tmp_path):
    path = tmp_path / "std.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", b"alpha" * 100)
        zf.writestr("dir/b.bin", bytes(range(256)) * 4)
        zf.comment = b"stdlib comment"
    verdict = zipgate.verify_archive(path)
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_central_order_differs_from_local_order(tmp_path):
    specs = [
        EntrySpec(b"first.txt", b"1" * 1000),
        EntrySpec(b"second.txt", b"2" * 2000, method=0),
        EntrySpec(b"third.txt", b"3" * 3000, dd="signed"),
    ]
    data = build_archive(specs, cd_order=[2, 0, 1])
    verdict = verify(tmp_path, data)
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_both_data_descriptor_forms(tmp_path):
    specs = [
        EntrySpec(b"signed.bin", b"signed body" * 50, dd="signed"),
        EntrySpec(b"unsigned.bin", b"unsigned body" * 50, dd="unsigned"),
        EntrySpec(b"plain.bin", b"no descriptor", method=0),
    ]
    verdict = verify(tmp_path, build_archive(specs))
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_crc_equal_to_dd_signature_both_forms(tmp_path):
    # 构造 CRC32 恰好等于数据描述符签名 0x08074B50 的内容
    content = crc_patch(b"crc-equals-dd-sig:", DD_SIG)
    import zlib

    assert zlib.crc32(content) == DD_SIG
    for dd in ("signed", "unsigned"):
        specs = [EntrySpec(b"edge.bin", content, dd=dd)]
        verdict = verify(tmp_path, build_archive(specs))
        assert verdict.decision is Decision.ACCEPT, (dd, verdict.reason)


def test_fake_eocd_in_archive_comment(tmp_path):
    # 注释中放入一个结构逼真的伪 EOCD，真实 EOCD 仍须生效
    fake = struct.pack("<IHHHHIIH", EOCD_SIG, 0, 0, 0, 0, 0, 0, 8) + b"fakeeocd"
    specs = [EntrySpec(b"real.txt", b"real content" * 20)]
    verdict = verify(tmp_path, build_archive(specs, archive_comment=fake))
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_zip_signatures_inside_content_and_names(tmp_path):
    # 文件内容与注释中碰巧出现 ZIP 签名不影响接收
    blob = struct.pack("<IIII", 0x04034B50, 0x02014B50, 0x06054B50, 0x08074B50) * 30
    specs = [
        EntrySpec(b"siggy.bin", blob, dd="signed", file_comment=b"\x50\x4b\x05\x06"),
        EntrySpec(b"other.bin", blob, method=0),
    ]
    verdict = verify(tmp_path, build_archive(specs, archive_comment=blob))
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_utf8_flag_and_file_comment(tmp_path):
    specs = [
        EntrySpec("文件名-ü.txt".encode("utf-8"), "内容".encode("utf-8") * 10,
                  flags_extra=0x0800, file_comment=b"note"),
    ]
    verdict = verify(tmp_path, build_archive(specs))
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_unknown_extra_fields_allowed(tmp_path):
    extra = struct.pack("<HH", 0xCAFE, 4) + b"abcd" + struct.pack("<HH", 0x000A, 0)
    specs = [EntrySpec(b"x.bin", b"data" * 10, local_extra=extra, central_extra=extra)]
    verdict = verify(tmp_path, build_archive(specs))
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_local_header_values_may_repeat_central_with_dd(tmp_path):
    # 启用数据描述符时，本地头三个字段允许为零或与目录一致
    spec = EntrySpec(b"rep.bin", b"repeat" * 100, dd="signed")
    data = build_archive([spec])
    verdict = verify(tmp_path, data)
    assert verdict.decision is Decision.ACCEPT, verdict.reason

    spec2 = EntrySpec(b"rep2.bin", b"repeat" * 100, dd="signed")
    prepared = build_archive([spec2])
    # 手工把本地头字段改成与目录一致的非零值
    import zlib

    content = b"repeat" * 100
    crc = zlib.crc32(content)
    from helpers import deflate_raw

    csize = len(deflate_raw(content))
    usize = len(content)
    patched = bytearray(prepared)
    struct.pack_into("<III", patched, 14, crc, csize, usize)
    verdict2 = verify(tmp_path, bytes(patched))
    assert verdict2.decision is Decision.ACCEPT, verdict2.reason


def test_source_file_untouched(tmp_path):
    specs = [EntrySpec(b"a.txt", b"payload" * 500, dd="unsigned")]
    data = build_archive(specs, archive_comment=b"c")
    path = tmp_path / "keep.zip"
    path.write_bytes(data)
    before = path.read_bytes()
    zipgate.verify_archive(path)
    assert path.read_bytes() == before
