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

# IPv6 address assignment command pattern
# Matches: ip -6 addr add <IPv6_ADDRESS>/<PREFIX> dev <INTERFACE>
# Examples that match:
#   ip -6 addr add 2001:db8::1/64 dev eth0
#   ip -6 addr add fd00::1/64 dev eth1
#   ip -6 addr add 2001:db8::1/127 dev wlan0
# To support additional IPv6 command variations, modify this regex
IPV6_CMD_PATTERN = (
    r'^\s*ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)/(\d+)\s+dev\s+([a-zA-Z0-9_.-]+)\s*$'
)

# Compiled regex for performance
IPV6_CMD_REGEX = re.compile(IPV6_CMD_PATTERN)

# Valid range for IPv6 prefix length
# IPv6 prefix lengths range from /1 to /128
# Typical values:
#   /64 - subnet prefix
#   /127 - point-to-point link
#   /48 - organization prefix
#   /32 - internet service provider assignment
IPV6_PREFIX_LENGTH_MIN = 0
IPV6_PREFIX_LENGTH_MAX = 128
