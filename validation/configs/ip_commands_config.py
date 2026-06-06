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

# IPv4 address assignment command pattern
# Matches: ip addr add <IPv4_ADDRESS>/<PREFIX> dev <INTERFACE>
# or:     ip -4 addr add <IPv4_ADDRESS>/<PREFIX> dev <INTERFACE>
# Examples that match:
#   ip addr add 192.168.1.1/24 dev eth0
#   ip -4 addr add 10.0.0.1/30 dev eth1
# To support additional IPv4 command variations, modify this regex
IPV4_CMD_PATTERN = (
    r'^\s*ip(?:\s+-4)?\s+addr\s+add\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})/(\d+)\s+dev\s+([a-zA-Z0-9_.-]+)\s*$'
)

# Compiled regex for performance
IPV4_CMD_REGEX = re.compile(IPV4_CMD_PATTERN)

# Valid range for IPv4 prefix length
# IPv4 prefix lengths range from /0 to /32
# Typical values:
#   /24 - LAN subnet
#   /30 - point-to-point link
#   /16 - large internal network
IPV4_PREFIX_LENGTH_MIN = 0
IPV4_PREFIX_LENGTH_MAX = 32

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
