import pytest

from upload_guard import DetectedType, Severity, TypeRule, check_filename, extension_matches, sanitize_filename, split_filename
from upload_guard.extension import all_extensions, canonical_extension, compile_rules, mime_for_extension


def test_split_and_canonical():
    assert split_filename("photo.JPEG") == ("photo", "jpeg")
    assert split_filename("archive.tar.gz") == ("archive.tar", "gz")
    assert split_filename(".bashrc") == (".bashrc", None)
    assert split_filename("noext") == ("noext", None)
    assert split_filename("trailing.txt. ") == ("trailing", "txt")
    assert split_filename("dir/sub\\file.png") == ("file", "png")
    assert canonical_extension(".JPEG") == "jpg"
    assert canonical_extension("htm") == "html"
    assert all_extensions("shell.php.jpg") == ["php", "jpg"]


def test_extension_matches_aliases():
    jpeg = DetectedType("image/jpeg", ("jpg", "jpeg"))
    assert extension_matches("JPG", jpeg)
    assert extension_matches(".jpeg", jpeg)
    assert not extension_matches("png", jpeg)
    assert mime_for_extension("docx").endswith("wordprocessingml.document")


def test_type_rules():
    png = DetectedType("image/png", ("png",), category="image")
    assert TypeRule("image/*").matches(png)
    assert TypeRule("image/png").matches(png)
    assert TypeRule(".png").matches(png)
    assert TypeRule("PNG").matches(png)
    assert TypeRule("category:image").matches(png)
    assert not TypeRule("application/pdf").matches(png)
    assert len(compile_rules(["image/*", ".pdf"])) == 2
    with pytest.raises(ValueError):
        TypeRule("not a mime/")


def _codes(findings):
    return {f.code for f in findings}


def test_filename_traversal_and_null():
    assert "filename.path_traversal" in _codes(check_filename("../../etc/passwd"))
    assert "filename.path_traversal" in _codes(check_filename("..\\..\\windows\\win.ini"))
    assert "filename.null_byte" in _codes(check_filename("shell.php\x00.jpg"))
    assert "filename.absolute_path" in _codes(check_filename("/etc/passwd"))
    assert "filename.absolute_path" in _codes(check_filename("C:\\Windows\\x.txt"))
    assert "filename.path_separator" in _codes(check_filename("a/b.txt"))


def test_filename_unicode_spoofing():
    # "invoice_\u202Egnp.exe" renders as "invoice_exe.png"
    f = check_filename("invoice_\u202egnp.exe")
    assert "filename.bidi_override" in _codes(f)
    assert any(x.severity == Severity.CRITICAL for x in f)
    assert "filename.invisible_chars" in _codes(check_filename("a\u200b.png"))
    assert "filename.control_chars" in _codes(check_filename("a\x07.png"))


def test_filename_dangerous_and_double_extensions():
    assert "filename.dangerous_extension" in _codes(check_filename("run.exe"))
    assert "filename.dangerous_extension" in _codes(check_filename("x.PHP"))
    f = check_filename("shell.php.jpg")
    double = [x for x in f if x.code == "filename.double_extension"]
    assert double and double[0].severity == Severity.MEDIUM
    f = check_filename("backup.tar.gz")
    double = [x for x in f if x.code == "filename.double_extension"]
    assert double and double[0].severity == Severity.INFO
    assert "filename.reserved_name" in _codes(check_filename("CON.txt"))
    assert "filename.server_config" in _codes(check_filename(".htaccess"))
    assert "filename.hidden" in _codes(check_filename(".secret.png"))
    assert "filename.no_extension" in _codes(check_filename("README"))
    assert "filename.too_long" in _codes(check_filename("a" * 300 + ".png"))
    assert "filename.empty" in _codes(check_filename(""))
    assert _codes(check_filename("holiday photo (1).jpeg")) == set()


def test_sanitize_filename():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\win.ini") == "win.ini"
    assert sanitize_filename("shell.php\x00.jpg") == "shell.php.jpg"
    assert sanitize_filename("invoice_\u202egnp.exe") == "invoice_gnp.exe"
    assert sanitize_filename('bad<>:"|?*name.txt') == "bad_name.txt"
    assert sanitize_filename("CON.txt") == "_CON.txt"
    assert sanitize_filename("  spaced   out .png ") == "spaced out.png"
    assert sanitize_filename("...") == "upload"
    assert sanitize_filename("") == "upload"
    assert sanitize_filename(None) == "upload"
    long = sanitize_filename("x" * 300 + ".jpeg", max_length=40)
    assert long.endswith(".jpeg") and len(long.encode()) <= 40
    assert sanitize_filename("照片 日本.PNG") == "照片 日本.PNG"
    assert sanitize_filename("café.png", ascii_only=True) == "cafe.png"
    assert sanitize_filename("ﬁle.txt") == "file.txt"  # NFKC ligature
