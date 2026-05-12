from forensicator.pathnorm import normalize_path, is_case_insensitive_os


def test_collapse_slashes():
    assert normalize_path("a//b///c", os="linux") == "a/b/c"


def test_backslash_to_slash():
    assert normalize_path("a\\b\\c", os="linux") == "a/b/c"


def test_strip_leading_dot_slash():
    assert normalize_path("./a/b", os="linux") == "a/b"


def test_strip_trailing_slash():
    assert normalize_path("a/b/", os="linux") == "a/b"


def test_root_preserved():
    assert normalize_path("/", os="linux") == "/"


def test_case_fold_on_mac():
    assert normalize_path("Photos/2024", os="darwin") == "photos/2024"


def test_no_case_fold_on_linux():
    assert normalize_path("Photos/2024", os="linux") == "Photos/2024"


def test_case_fold_on_windows():
    assert normalize_path("Photos\\2024", os="MSWin32") == "photos/2024"


def test_is_case_insensitive_os():
    assert is_case_insensitive_os("darwin")
    assert is_case_insensitive_os("MSWin32")
    assert is_case_insensitive_os("win32")
    assert not is_case_insensitive_os("linux")
