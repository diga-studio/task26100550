"""解析唯一性与调用容错。"""

import struct

import zipgate
from zipgate import Decision

from helpers import EOCD_SIG, EntrySpec, build_archive


def test_self_consistent_fake_eocd_does_not_shadow_real(tmp_path):
    # 注释中的伪 EOCD 自身结构自洽（注释长度到达文件尾、目录偏移自洽），
    # 但深层核验失败时，真正的 EOCD 仍须生效
    specs = [EntrySpec(b"real.txt", b"real" * 20)]
    good = build_archive(specs)
    # 伪 EOCD 位于注释起点，声称空目录就在它自己前面
    fake_pos = len(good)  # 注释起点即伪 EOCD 位置
    fake = struct.pack("<IHHHHIIH", EOCD_SIG, 0, 0, 0, 0, 0, fake_pos, 0)
    # 重建归档：真实 EOCD 的注释 = 伪 EOCD
    real_eocd_pos = len(good) - 22
    patched = bytearray(good)
    struct.pack_into("<H", patched, real_eocd_pos + 20, len(fake))
    patched += fake
    path = tmp_path / "shadow.zip"
    path.write_bytes(bytes(patched))
    verdict = zipgate.verify_archive(path)
    assert verdict.decision is Decision.ACCEPT, verdict.reason


def test_missing_file_quarantined(tmp_path):
    verdict = zipgate.verify_archive(tmp_path / "does-not-exist.zip")
    assert verdict.decision is Decision.QUARANTINE
    assert verdict.reason


def test_directory_path_quarantined(tmp_path):
    verdict = zipgate.verify_archive(tmp_path)
    assert verdict.decision is Decision.QUARANTINE
