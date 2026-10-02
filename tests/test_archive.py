import gzip
import io
import struct
import zipfile

from conftest import make_tar, make_zip
from upload_guard import ArchiveLimits, inspect_archive, inspect_compressed, inspect_zip
from upload_guard.security.archive import BoundedReader, _gzip_factory, is_unsafe_link_target, is_unsafe_member_path


def _codes(findings):
    return {f.code for f in findings}


def test_benign_zip():
    data = make_zip({"a.txt": "hello", "dir/b.txt": "world" * 10})
    report, findings = inspect_zip(io.BytesIO(data))
    assert report.entry_count == 2
    assert report.total_uncompressed == 5 + 50
    assert not findings


def test_zip_bomb_by_total_size():
    data = make_zip({"zeros.bin": bytes(5 * 1024 * 1024)})
    report, findings = inspect_zip(io.BytesIO(data), ArchiveLimits(max_total_uncompressed=1024 * 1024))
    assert "archive.bomb_size" in _codes(findings)
    assert report.truncated


def test_zip_bomb_by_ratio():
    data = make_zip({"zeros.bin": bytes(2 * 1024 * 1024)})  # ~1000:1
    report, findings = inspect_zip(io.BytesIO(data), ArchiveLimits(max_ratio=50.0))
    assert "archive.bomb_ratio" in _codes(findings)
    assert report.ratio > 50
    # tiny files are exempt from the ratio rule
    small = make_zip({"z.bin": bytes(10_000)})
    _, findings = inspect_zip(io.BytesIO(small), ArchiveLimits(max_ratio=5.0))
    assert "archive.bomb_ratio" not in _codes(findings)


def test_zip_slip_and_too_many_entries():
    data = make_zip({"../../etc/cron.d/evil": "x", "/abs/path": "y", "ok.txt": "z", "C:\\win.ini": "w"})
    report, findings = inspect_zip(io.BytesIO(data))
    assert "archive.path_traversal" in _codes(findings)
    assert len(report.unsafe_paths) == 3
    many = make_zip({"f%d" % i: "x" for i in range(50)})
    _, findings = inspect_zip(io.BytesIO(many), ArchiveLimits(max_entries=10))
    assert "archive.too_many_entries" in _codes(findings)


def test_zip_symlink():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)
        zf.writestr(info, "../../etc/passwd")
        zf.writestr("ok.txt", "x")
    _, findings = inspect_zip(io.BytesIO(buf.getvalue()))
    assert "archive.symlink" in _codes(findings)
    _, findings = inspect_zip(io.BytesIO(buf.getvalue()), ArchiveLimits(allow_symlinks=True))
    assert "archive.symlink_escape" in _codes(findings)


def test_nested_zip_counts_toward_total():
    inner = make_zip({"zeros.bin": bytes(3 * 1024 * 1024)})
    outer = make_zip({"inner.zip": inner, "readme.txt": "hi"}, compression=zipfile.ZIP_STORED)
    report, findings = inspect_zip(io.BytesIO(outer), ArchiveLimits(max_total_uncompressed=1024 * 1024, max_nesting=1))
    assert "archive.bomb_size" in _codes(findings)
    assert "inner.zip" in report.nested_archives
    assert report.max_depth == 1
    report, findings = inspect_zip(io.BytesIO(outer), ArchiveLimits(max_nesting=0))
    assert "archive.nested_uninspected" in _codes(findings)


def test_overlapping_entries_bomb():
    # Hand-build a zip whose two central-directory entries point at the same local header.
    payload = bytes(1000)
    import zlib
    comp = zlib.compress(payload)[2:-4]
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    name = b"a"
    local = b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, 8, 0, 0, crc, len(comp), len(payload), len(name), 0) + name + comp
    def central(n):
        return b"PK\x01\x02" + struct.pack("<HHHHHHIIIHHHHHII", 20, 20, 0, 8, 0, 0, crc, len(comp), len(payload), len(n), 0, 0, 0, 0, 0, 0) + n
    cd = central(b"a") + central(b"b")
    eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 2, 2, len(cd), len(local), 0)
    data = local + cd + eocd
    _, findings = inspect_zip(io.BytesIO(data))
    assert "archive.overlapping_entries" in _codes(findings)


def test_zip_verify_sizes_detects_lying_header():
    data = bytearray(make_zip({"a.bin": bytes(100_000)}))
    # patch the central directory file_size down to 10 bytes
    idx = data.rfind(b"PK\x01\x02")
    struct.pack_into("<I", data, idx + 24, 10)
    _, findings = inspect_zip(io.BytesIO(bytes(data)), ArchiveLimits(verify_sizes=True))
    assert "archive.size_mismatch" in _codes(findings)


def test_corrupt_zip():
    _, findings = inspect_zip(io.BytesIO(b"PK\x03\x04garbage"))
    assert "archive.corrupt" in _codes(findings)


def test_tar_gz_walk():
    data = make_tar({"a.txt": b"x" * 100, "dir/b.txt": b"y" * 5000, "../evil": b"z", "ln": ("symlink", "/etc/passwd")}, "gz")
    report, findings = inspect_compressed(io.BytesIO(data), "gzip")
    assert report.format == "tar+gzip"
    assert report.entry_count == 4
    assert report.total_uncompressed >= 5100
    assert "archive.path_traversal" in _codes(findings)
    assert "archive.symlink" in _codes(findings)
    _, findings = inspect_compressed(io.BytesIO(data), "gzip", ArchiveLimits(allow_symlinks=True))
    assert "archive.symlink_escape" in _codes(findings)


def test_plain_tar_and_bz2_xz():
    for comp in ("", "bz2", "xz"):
        data = make_tar({"a.txt": b"hello"}, comp)
        kind = {"": "tar", "bz2": "bzip2", "xz": "xz"}[comp]
        report, findings = inspect_compressed(io.BytesIO(data), kind)
        assert report.entry_count == 1, comp
        assert report.total_uncompressed == 5, comp
        assert not findings, comp


def test_gzip_bomb_streams_with_cap():
    bomb = gzip.compress(bytes(20 * 1024 * 1024))  # 20 MiB → ~20 KiB
    report, findings = inspect_compressed(io.BytesIO(bomb), "gzip", ArchiveLimits(max_total_uncompressed=1024 * 1024))
    assert "archive.bomb_size" in _codes(findings)
    assert report.total_uncompressed <= 1024 * 1024 + 64 * 1024 * 2  # never buffered much past the cap


def test_bounded_reader_multi_member_gzip_and_trailing_zeros():
    data = gzip.compress(b"a" * 1000) + gzip.compress(b"b" * 1000)
    r = BoundedReader(io.BytesIO(data), _gzip_factory, 10_000)
    assert r.drain() == 2000
    padded = gzip.compress(b"abc") + bytes(512)
    r = BoundedReader(io.BytesIO(padded), _gzip_factory, 10_000)
    assert r.drain() == 3


def test_dispatcher():
    zip_data = make_zip({"x": "y"})
    report, _ = inspect_archive(io.BytesIO(zip_data), "application/zip")
    assert report is not None and report.format == "zip"
    report, findings = inspect_archive(io.BytesIO(b"\x89PNG"), "image/png")
    assert report is None and findings == []
    docx_like = make_zip({"[Content_Types].xml": "x", "word/document.xml": bytes(3_000_000)})
    report, findings = inspect_archive(io.BytesIO(docx_like), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ArchiveLimits(max_total_uncompressed=1_000_000))
    assert "archive.bomb_size" in _codes(findings)


def test_path_helpers():
    assert is_unsafe_member_path("../x")
    assert is_unsafe_member_path("a/../../x")
    assert not is_unsafe_member_path("a/../x")
    assert is_unsafe_member_path("/etc/passwd")
    assert is_unsafe_member_path("C:\\x")
    assert is_unsafe_member_path("a\x00b")
    assert not is_unsafe_member_path("./a/b")
    assert is_unsafe_link_target("dir/link", "../../etc/passwd")
    assert not is_unsafe_link_target("dir/link", "../other")
    assert is_unsafe_link_target("link", "/abs")
