# ========================================================================================
#  Copyright (C) 2025 CryptoLab Inc. All rights reserved.
#
#  This software is proprietary and confidential.
#  Unauthorized use, modification, reproduction, or redistribution is strictly prohibited.
#
#  Commercial use is permitted only under a separate, signed agreement with CryptoLab Inc.
#
#  For licensing inquiries or permission requests, please contact: pypi@cryptolab.co.kr
# ========================================================================================

from __future__ import annotations

import re
from typing import Optional, Tuple


def parse_version(version: Optional[str]) -> Optional[Tuple[int, int, int, Optional[str], Optional[int]]]:
    """
    Parse version into a comparable tuple: (major, minor, patch, pre_tag, pre_num).

    - Accepts semver-like (e.g., 'v1.1.0-rc.4', '1.1.0-beta2', '1.1.0+build')
    - Accepts PEP 440-like (e.g., '1.1.0rc4', '1.1.0a1', '1.1.0b2')
    - pre_tag is one of: 'a', 'b', 'rc', or None
    - pre_num is an int or None
    """
    if not version:
        return None
    try:
        v = version.strip()
        # strip build metadata (e.g., +build.1)
        if "+" in v:
            v = v.split("+", 1)[0]
        # strip optional leading 'v'
        if v and v[0] in ("v", "V"):
            v = v[1:]

        core = v
        pre_tag: Optional[str] = None
        pre_num: Optional[int] = None

        # Try semver prerelease via '-' separator (e.g., rc.3, alpha.1, beta2)
        if "-" in v:
            core, pre = v.split("-", 1)
            m = re.match(r"(?i)^(alpha|beta|rc|a|b)[\.-]?(\d+)?$", pre)
            if m:
                tag = m.group(1).lower()
                num = m.group(2)
                if tag in ("alpha", "a"):
                    pre_tag = "a"
                elif tag in ("beta", "b"):
                    pre_tag = "b"
                else:
                    pre_tag = "rc"
                pre_num = int(num) if num else 0

        # Try PEP 440 style (e.g., 1.2.3rc1)
        if pre_tag is None:
            m2 = re.match(r"^(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?$", v, flags=re.IGNORECASE)
            if m2:
                core = m2.group(1)
                if m2.group(2):
                    pre_tag = m2.group(2).lower()
                    pre_num = int(m2.group(3)) if m2.group(3) else 0

        parts = core.split(".")
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch, pre_tag, pre_num)
    except Exception:
        return None


def to_pep440(version: Optional[str]) -> Optional[str]:
    p = parse_version(version)
    if not p:
        return None
    major, minor, patch, pre_tag, pre_num = p
    base = f"{major}.{minor}.{patch}"
    if pre_tag:
        n = pre_num if pre_num is not None else 0
        return f"{base}{pre_tag}{n}"
    return base


def is_equal(v1: Optional[str], v2: Optional[str]) -> bool:
    p1 = parse_version(v1)
    p2 = parse_version(v2)
    return p1 is not None and p1 == p2


def should_check(server_version: Optional[str]) -> bool:
    """Return True only if server version explicitly starts with 'v' or 'V'."""
    if not server_version:
        return False
    return server_version.strip().lower().startswith("v")
