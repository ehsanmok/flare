"""Tests for :func:`flare.utils.dylib.find_flare_lib`'s search order."""

from std.os import getenv, setenv, unsetenv
from std.testing import assert_equal, assert_false

from flare.utils.dylib import find_flare_lib


def test_never_resolves_against_the_working_directory() raises:
    """With no CONDA_PREFIX the resolver returned
    ``build/libflare_<name>.so``, which dlopen reads relative to the
    working directory: a program started in a directory someone else
    could write to loaded their library."""
    var saved_prefix = getenv("CONDA_PREFIX", "")
    var saved_dir = getenv("FLARE_LIB_DIR", "")
    _ = unsetenv("CONDA_PREFIX")
    _ = unsetenv("FLARE_LIB_DIR")
    var bare = find_flare_lib("tls")
    _ = setenv("FLARE_LIB_DIR", "relative/dir")
    var relative = find_flare_lib("tls")
    _ = setenv("FLARE_LIB_DIR", "/opt/flare/lib")
    var explicit = find_flare_lib("tls")
    _ = setenv("CONDA_PREFIX", saved_prefix)
    if saved_dir != "":
        _ = setenv("FLARE_LIB_DIR", saved_dir)
    else:
        _ = unsetenv("FLARE_LIB_DIR")
    assert_equal(bare, "libflare_tls.so")
    assert_false("/" in relative, "a relative FLARE_LIB_DIR was used")
    assert_equal(explicit, "/opt/flare/lib/libflare_tls.so")


def main() raises:
    test_never_resolves_against_the_working_directory()
    print("test_dylib: 1 passed")
