# Validation Configuration Guide

## Overview

This guide explains how to adjust validation behavior in the core-xml-analyzer without modifying validation logic code.

All validation parameters are organized into domain-specific configuration modules in the `validation/` directory:

- **`network_config.py`** - Network topology validation rules
- **`ip_commands_config.py`** - IP address command validation rules
- **`radvd_config.py`** - Router advertisement daemon validation rules
- **`routingHelper.py`** - Expected routing matrix (topology-specific)

## Quick Start: Changing a Validation Rule

### Example 1: Adjust Maximum Prefix Count Per Network

**Current behavior:** Networks can have a maximum of 2 prefixes (IPv6 global + IPv6 site-local).

**To change to 3 prefixes maximum:**

1. Open `validation/network_config.py`
2. Find the line:
   ```python
   MAX_PREFIXES_PER_NETWORK = 2
   ```
3. Change it to:
   ```python
   MAX_PREFIXES_PER_NETWORK = 3
   ```
4. Run your tests to verify the new behavior

### Example 2: Change Prefix Length Requirements for LAN Networks

**Current behavior:** LAN networks must use /64 IPv6 prefix.

**To change to /48 prefix:**

1. Open `validation/network_config.py`
2. Find:
   ```python
   PREFIX_LENGTH_REQUIREMENTS = {
       "lan": 64,
       ...
   }
   ```
3. Change to:
   ```python
   PREFIX_LENGTH_REQUIREMENTS = {
       "lan": 48,
       ...
   }
   ```

### Example 3: Change Admin Network Naming Pattern

**Current behavior:** Networks with "admin" in the name are treated as admin networks.

**To recognize networks ending with "-mgmt" instead:**

1. Open `validation/network_config.py`
2. Find:
   ```python
   ADMIN_NETWORK_PATTERN = "admin"
   ```
3. Change to:
   ```python
   ADMIN_NETWORK_PATTERN = "mgmt"
   ```

Note: Pattern matching is case-insensitive substring matching. If you need regex support, modify the validation logic in `networks.py` to compile the pattern as a regex.

### Example 4: Modify IPv6 Command Validation Pattern

**Current behavior:** Matches `ip -6 addr add <IPv6>/<PREFIX> dev <INTERFACE>`

**To support additional command variations:**

1. Open `validation/ip_commands_config.py`
2. Find the `IPV6_CMD_PATTERN` regex
3. Modify the pattern to match your desired format
4. Update the compiled regex `IPV6_CMD_REGEX` (or it will be auto-compiled)

Example: To support variable whitespace:
```python
IPV6_CMD_PATTERN = (
    r'^\s*ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)/(\d+)\s+dev\s+([a-zA-Z0-9_.\-]+)\s*$'
)
```

## Configuration Files Reference

### network_config.py

Controls validation of network topology and IPv6 addressing.

| Parameter | Type | Current Value | Purpose |
|-----------|------|---------------|---------|
| `PREFIX_LENGTH_REQUIREMENTS` | dict | `{"lan": 64, "wireless": 64, "point-to-point": 127}` | Expected IPv6 prefix length by network type |
| `MAX_PREFIXES_PER_NETWORK` | int | `2` | Maximum number of address prefixes per network |
| `ADMIN_NETWORK_PATTERN` | str | `"admin"` | Pattern identifying admin networks (case-insensitive substring) |
| `REQUIRED_PREFIX_TYPES` | dict | `{"lan": ["site", "global"], ...}` | Required prefix types per network kind |

**When to modify:**
- Network topology changes with different prefix requirements
- Naming conventions for special network types change
- Prefix type requirements become more/less strict

### ip_commands_config.py

Controls validation of IPv6 static address configuration.

| Parameter | Type | Current Value | Purpose |
|-----------|------|---------------|---------|
| `IPV6_CMD_PATTERN` | str | regex pattern | Regex matching valid `ip -6 addr add` commands |
| `IPV6_CMD_REGEX` | compiled | compiled pattern | Pre-compiled regex for performance |
| `IPV6_PREFIX_LENGTH_MIN` | int | `0` | Minimum valid IPv6 prefix length |
| `IPV6_PREFIX_LENGTH_MAX` | int | `128` | Maximum valid IPv6 prefix length |

**When to modify:**
- Support different IPv6 configuration command formats
- Change acceptable prefix length ranges
- Tighten validation regex for security

### radvd_config.py

Controls validation of router advertisement daemon configuration (currently no parameters).

**When to modify:**
- If radvd-specific thresholds or patterns are needed in the future

### routingHelper.py

Defines the expected routing topology matrix and routing builders.

**Structure:**
- `TABLES` - Policy routing table definitions
- `direct()`, `default()`, `indirect()`, `policy_default()`, `policy_drop()` - Route builders
- `EXPECTED_ROUTING_MATRIX` - Expected routes per router (~280 lines)
- `ISP_EXPECTED` - ISP route expectations

**When to modify:**
- Network topology changes (new routers, routes, or links)
- Routing policies change
- Different ISP connections expected

See comprehensive documentation in the file header for detailed modification instructions.

## Testing Your Changes

After modifying any configuration:

1. **Run validation tests** with your expected XML topology
2. **Verify warning messages** match the new rules
3. **Check warnings are triggered** for violations of new rules
4. **Ensure no new false positives** with valid configurations

Example:
```bash
# Run parser with your modified config and test XML
python -c "
from parser.parser import parse_xml
with open('test.xml') as f:
    data = parse_xml(f.read())
    for w in data['warnings']:
        print(w)
"
```

## Common Patterns

### Pattern 1: Making Validation More Permissive

**Goal:** Allow networks to have more prefixes

**Action:** Increase `MAX_PREFIXES_PER_NETWORK` in `network_config.py`

### Pattern 2: Making Validation Stricter

**Goal:** Require global prefixes on all networks (not just non-admin)

**Action:** Modify logic in `networks.py` to always check for global prefix, or extract the condition to config

### Pattern 3: Supporting New Network Type

**Goal:** Add validation rules for a new network kind (e.g., "vlan")

**Action:**
1. Add entry to `PREFIX_LENGTH_REQUIREMENTS` in `network_config.py`
2. Add entry to `REQUIRED_PREFIX_TYPES` in `network_config.py`
3. Add conditional checks in `networks.py` if needed

## Troubleshooting

**Issue:** Changed config but validation still uses old values

**Solution:** Ensure you're modifying the right `*_config.py` file and importing from it

**Issue:** Regex doesn't match commands

**Solution:** Test the regex pattern independently with sample commands, e.g.:
```python
import re
pattern = r'...'  # your pattern
regex = re.compile(pattern)
test_line = "ip -6 addr add 2001:db8::1/64 dev eth0"
if regex.match(test_line):
    print("✓ Matches")
else:
    print("✗ Doesn't match")
```

**Issue:** Increased max prefixes but still getting warnings

**Solution:** Verify the change is in the right place and saved correctly

## File Locations

```
validation/
├── network_config.py           ← Network validation parameters
├── ip_commands_config.py       ← IP command validation parameters
├── radvd_config.py             ← Radvd validation parameters (placeholder)
├── routingHelper.py            ← Routing matrix & builders
├── networks.py                 ← Network validation logic (reads from network_config)
├── ip_commands.py              ← IP command validation logic (reads from ip_commands_config)
├── radvd.py                    ← Radvd validation logic (data-driven)
└── routingValidation.py        ← Routing matrix validation (reads from routingHelper)
```

## Next Steps

1. **Understand your current configuration:** Review each `*_config.py` file to see current parameters
2. **Identify what needs changing:** Compare expected vs. actual topology
3. **Make targeted changes:** Modify specific parameters in the right `*_config.py`
4. **Test thoroughly:** Verify with representative XML topologies
5. **Document your changes:** Add comments to unusual settings for future reference
