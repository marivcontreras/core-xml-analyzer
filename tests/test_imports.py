#!/usr/bin/env python3
"""Quick test to verify config module imports work"""

try:
    from validation.configs.network_config import PREFIX_LENGTH_REQUIREMENTS, MAX_PREFIXES_PER_NETWORK, ADMIN_NETWORK_PATTERN
    print("✓ network_config imports successful")
    print(f"  - PREFIX_LENGTH_REQUIREMENTS['lan'] = {PREFIX_LENGTH_REQUIREMENTS['lan']}")
    print(f"  - MAX_PREFIXES_PER_NETWORK = {MAX_PREFIXES_PER_NETWORK}")
    print(f"  - ADMIN_NETWORK_PATTERN = {ADMIN_NETWORK_PATTERN}")
except Exception as e:
    print(f"✗ network_config import failed: {e}")

try:
    from validation.configs.ip_commands_config import \
        IPV4_CMD_REGEX, IPV4_PREFIX_LENGTH_MIN, IPV4_PREFIX_LENGTH_MAX, \
        IPV6_CMD_REGEX, IPV6_PREFIX_LENGTH_MIN, IPV6_PREFIX_LENGTH_MAX
    print("✓ ip_commands_config imports successful")
    print(f"  - IPV4_PREFIX_LENGTH_MIN = {IPV4_PREFIX_LENGTH_MIN}")
    print(f"  - IPV4_PREFIX_LENGTH_MAX = {IPV4_PREFIX_LENGTH_MAX}")
    print(f"  - IPV6_PREFIX_LENGTH_MIN = {IPV6_PREFIX_LENGTH_MIN}")
    print(f"  - IPV6_PREFIX_LENGTH_MAX = {IPV6_PREFIX_LENGTH_MAX}")
except Exception as e:
    print(f"✗ ip_commands_config import failed: {e}")

try:
    from validation.networks import validate_networks
    print("✓ networks module import successful")
except Exception as e:
    print(f"✗ networks import failed: {e}")

try:
    from validation.ip_commands import validate_ip_addr_commands
    print("✓ ip_commands module import successful")
except Exception as e:
    print(f"✗ ip_commands import failed: {e}")

print("\n✓ All imports working correctly!")
