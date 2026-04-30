import pytest

from pyenvector.utils import version as version_utils


def test_hotfix_compat_allows_patch_diff():
    assert version_utils.is_hotfix_compatible("1.2.1", "v1.2.0")
    assert version_utils.is_hotfix_compatible("v1.2.5", "1.2.7")


@pytest.mark.parametrize(
    "server_version, expected",
    [
        (None, False),
        ("", False),
        ("vct", False),
        ("v1", False),
        ("v1.2", False),
        ("v1.2.3", True),
        ("V1.2.3", True),
        (" v1.2.3 ", True),
        ("v1.2.3-rc.1", True),
        ("v1.2.3rc1", True),
        ("v1.2.3+build.1", True),
        ("v1.2.3.4", False),
        ("1", False),
        ("1.2", False),
        ("1.2.3", True),
        (" 1.2.3 ", True),
        ("1.2.3-rc.1", True),
        ("1.2.3rc1", True),
        ("1.2.3+build.1", True),
        ("1.2.3.4", False),
    ],
)
def test_should_check_requires_semver_core(server_version, expected):
    assert version_utils.should_check(server_version) is expected


@pytest.mark.parametrize(
    "sdk_version, server_version",
    [
        ("1.1.5", "1.1.6"),  # below minimum threshold
        ("1.2.1-rc1", "1.2.0"),  # prerelease not allowed
        ("1.3.0", "1.2.5"),  # different minor version
        ("2.0.0", "1.2.5"),  # different major version
        ("invalid", "1.2.0"),  # unparsable versions
    ],
)
def test_hotfix_compat_rejects_invalid_cases(sdk_version, server_version):
    assert version_utils.is_hotfix_compatible(sdk_version, server_version) is False
