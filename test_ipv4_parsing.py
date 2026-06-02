#!/usr/bin/env python3
import re
import ipaddress

# Test data with both IPv4 and IPv6 commands
test_text = """
ip -6 addr add 2001:db8::1/64 dev eth0
ip addr add 192.168.1.1/24 dev eth0
ip -4 addr add 10.0.0.1/8 dev eth1
ip addr add fd12:3456:7890:1::1/64 dev eth1
"""

print("=" * 60)
print("IPv4 + IPv6 Parsing Test")
print("=" * 60)

# IPv6 pattern
ipv6_matches = re.findall(
    r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)/(\d+)\s+dev\s+(\S+)',
    test_text
)

# IPv4 pattern
ipv4_matches = re.findall(
    r'ip\s+(?:-4\s+)?addr\s+add\s+([0-9.]+)/(\d+)\s+dev\s+(\S+)',
    test_text
)

all_matches = ipv6_matches + ipv4_matches

print(f"\nIPv6 matches found: {len(ipv6_matches)}")
for addr, mask, dev in ipv6_matches:
    print(f"  IPv6: {addr}/{mask} on {dev}")

print(f"\nIPv4 matches found: {len(ipv4_matches)}")
for addr, mask, dev in ipv4_matches:
    print(f"  IPv4: {addr}/{mask} on {dev}")

print(f"\nTotal: {len(all_matches)} addresses parsed")

print("\nNetwork prefixes created:")
for addr, mask, dev in all_matches:
    try:
        net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
        print(f"  {net} (IPv{net.version}) on {dev}")
    except Exception as e:
        print(f"  Error parsing {addr}/{mask}: {e}")

print("\n✓ Test complete!")
