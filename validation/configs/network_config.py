"""
Network Validation Configuration

Consolidates all hardcoded parameters used in network validation (networks.py).
Modify these constants to adjust network validation behavior without changing code logic.

To adjust validation rules:
1. Modify the constants below
2. No changes needed to validation logic (networks.py)
3. Run tests to verify behavior
"""

# Prefix length requirements by network kind
# These define what IPv6 prefix length is expected for each network type
# Examples:
#   - LAN networks should use /64 (link-local + site-local scoping)
#   - P2P links should use /127 (point-to-point requires exactly 2 addresses)
PREFIX_LENGTH_REQUIREMENTS = {
    "lan": 64,
    "wireless": 64,
    "point-to-point": 127,
}

# Maximum number of prefixes allowed per network
# Currently allows IPv6 global + IPv6 site-local prefixes (2 total)
# Increase if you want to support additional address families
MAX_PREFIXES_PER_NETWORK = 2

# Pattern to identify admin networks (case-insensitive substring matching)
# Used to determine if special rules apply to a network
# For example: "admin" networks should not have global IPv6 prefixes
# Example network names that match: "Admin", "ADMIN", "admin-net", "network-admin"
ADMIN_NETWORK_PATTERN = "admin"

# Required prefix types per network kind
# Defines which IPv6 address families are mandatory for each network type
# Keys: network kinds ("lan", "wireless", "point-to-point")
# Values: list of required prefix type names ("site", "global")
# Modify to enforce different prefix requirements
REQUIRED_PREFIX_TYPES = {
    "lan": ["site", "global"],
    "wireless": ["site", "global"],
    "point-to-point": ["site", "global"],
}
