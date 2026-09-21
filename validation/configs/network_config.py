"""
Network Validation Configuration

Consolidates all hardcoded parameters used in network validation (networks.py).
Modify these constants to adjust network validation behavior without changing code logic.

To adjust validation rules:
1. Modify the constants below
2. No changes needed to validation logic (networks.py)
3. Run tests to verify behavior
"""

# Pattern to identify admin networks (case-insensitive substring matching)
# Used to determine if special rules apply to a network
# For example: "admin" networks should not have global IPv6 prefixes
# Example network names that match: "Admin", "ADMIN", "admin-net", "network-admin"
ADMIN_NETWORK_PATTERN = "admin"
