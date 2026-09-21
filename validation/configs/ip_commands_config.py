"""
IP Commands Validation Configuration

Consolidates all hardcoded parameters used in IP commands validation (ip_commands.py).
Modify these constants to adjust IP commands validation behavior without changing code logic.

To adjust validation rules:
1. Modify the constants below (especially IPV6_CMD_PATTERN for regex changes)
2. No changes needed to validation logic (ip_commands.py)
3. Run tests to verify behavior
"""

import re

# ---------------------------------------------------------------------------
# Canonical "ip addr add" command patterns
# ---------------------------------------------------------------------------
# These are the single source of truth for parsing ip-addr assignment commands.
# Two flavours are derived from one core body per address family:
#   * *_CMD_EXTRACT_REGEX : unanchored, for scanning free-form StaticRoute text
#                           with findall() (used by analyzer/prefixes.py).
#   * *_CMD_REGEX         : anchored (^...$), for validating a single command
#                           line with match() (used by validation/ip_commands.py).
#
# Capture groups (both flavours): (address, prefix_length, interface)
#
# Interface names use [a-zA-Z0-9_.-]+ (eth0, eth1.100, wlan0, ...).
# A "/" separator tolerates surrounding whitespace (addr / mask).
# IPv4 addresses are matched loosely ([0-9.]+) during extraction and strictly
# (four octets) during validation, since validation is where malformed input
# should be rejected.

_IFACE = r'[a-zA-Z0-9_.-]+'
_SLASH = r'\s*/\s*'

# --- IPv6 ---
# ip -6 addr add <ipv6>/<mask> dev <iface>
IPV6_CMD_BODY = (
    r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)' + _SLASH + r'(\d+)\s+dev\s+(' + _IFACE + r')'
)
IPV6_CMD_EXTRACT_REGEX = re.compile(IPV6_CMD_BODY)
IPV6_CMD_REGEX = re.compile(r'^\s*' + IPV6_CMD_BODY + r'\s*$')
IPV6_CMD_PATTERN = IPV6_CMD_REGEX.pattern  # backwards-compat alias

# --- IPv4 ---
# ip addr add <ipv4>/<mask> dev <iface>  |  ip -4 addr add ...
IPV4_CMD_BODY = (
    r'ip\s+(?:-4\s+)?addr\s+add\s+([0-9.]+)' + _SLASH + r'(\d+)\s+dev\s+(' + _IFACE + r')'
)
IPV4_CMD_EXTRACT_REGEX = re.compile(IPV4_CMD_BODY)
# Validation is stricter: require four octets.
IPV4_CMD_REGEX = re.compile(
    r'^\s*ip(?:\s+-4)?\s+addr\s+add\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})'
    + _SLASH + r'(\d+)\s+dev\s+(' + _IFACE + r')\s*$'
)
IPV4_CMD_PATTERN = IPV4_CMD_REGEX.pattern  # backwards-compat alias

# Valid range for IPv4 prefix length (/0 .. /32)
IPV4_PREFIX_LENGTH_MIN = 0
IPV4_PREFIX_LENGTH_MAX = 32

# Valid range for IPv6 prefix length (/0 .. /128)
IPV6_PREFIX_LENGTH_MIN = 0
IPV6_PREFIX_LENGTH_MAX = 128
