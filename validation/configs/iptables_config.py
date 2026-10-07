"""
iptables Commands Validation Configuration

Consolidates the parameters used by validation/iptables_commands.py.
Extend the sets/dicts below to accept more tables, targets or options
without touching the validation logic.
"""

IPTABLES_BINARIES = ("iptables", "ip6tables")

IPTABLES_TABLES = {"filter", "nat", "mangle", "raw", "security"}

# Rule operations that take a chain (and, for -I/-R, an optional rule number).
RULE_OPERATIONS = {
    "-A": "append", "--append": "append",
    "-I": "insert", "--insert": "insert",
    "-D": "delete", "--delete": "delete",
    "-C": "check", "--check": "check",
    "-R": "replace", "--replace": "replace",
}

# Operations that do not define a rule; their arguments are not validated.
OTHER_OPERATIONS = {
    "-N", "--new-chain", "-X", "--delete-chain", "-F", "--flush",
    "-L", "--list", "-S", "--list-rules", "-P", "--policy",
    "-Z", "--zero", "-E", "--rename-chain",
}

BUILTIN_TARGETS = {
    "ACCEPT", "DROP", "REJECT", "RETURN", "QUEUE", "LOG", "ULOG", "NFLOG",
    "MARK", "CONNMARK", "MASQUERADE", "SNAT", "DNAT", "REDIRECT", "TCPMSS",
    "TOS", "DSCP", "TTL", "NOTRACK", "CT", "TPROXY", "NFQUEUE", "SET",
}

PROTOCOLS = {
    "tcp", "udp", "udplite", "icmp", "icmpv6", "ipv6-icmp", "sctp", "dccp",
    "gre", "esp", "ah", "all",
}

# Protocols that accept --sport/--dport.
PORT_PROTOCOLS = {"tcp", "udp", "udplite", "sctp", "dccp"}

# option -> kind of value it takes. Kinds:
#   None      : flag without value
#   "any"     : one free-form value
#   "iface"   : interface name
#   "addr"    : IP address or network
#   "port"    : port, port range (a:b) or service name
#   "ports"   : comma separated list of ports (multiport)
#   "proto"   : protocol name or number
#   "table"   : iptables table
#   "target"  : target / chain name
#   "match"   : match module name
#   "mark"    : packet mark (value[/mask])
#   "nat"     : NAT address[:port] destination
#   "natport" : NAT port or port range (a-b)
#   "tcpflags": two values (mask and flags)
OPTION_KINDS = {
    "-t": "table", "--table": "table",
    "-p": "proto", "--protocol": "proto",
    "-s": "addr", "--source": "addr", "--src": "addr",
    "-d": "addr", "--destination": "addr", "--dst": "addr",
    "-i": "iface", "--in-interface": "iface",
    "-o": "iface", "--out-interface": "iface",
    "-j": "target", "--jump": "target",
    "-g": "target", "--goto": "target",
    "-m": "match", "--match": "match",
    "--sport": "port", "--source-port": "port",
    "--dport": "port", "--destination-port": "port",
    "--sports": "ports", "--source-ports": "ports",
    "--dports": "ports", "--destination-ports": "ports",
    "--ports": "ports",
    "--set-mark": "mark", "--set-xmark": "mark", "--mark": "mark",
    "--to": "nat", "--to-destination": "nat", "--to-source": "nat",
    "--to-ports": "natport",
    "--tcp-flags": "tcpflags",
    "--syn": None, "-f": None, "--fragment": None,
    "-v": None, "--verbose": None, "-n": None, "--numeric": None,
    "-x": None, "--exact": None, "--line-numbers": None,
    "--random": None, "--persistent": None,
    "-w": "any", "--wait": "any", "-W": "any",
    "--state": "any", "--ctstate": "any", "--icmp-type": "any",
    "--icmpv6-type": "any", "--reject-with": "any", "--log-prefix": "any",
    "--log-level": "any", "--comment": "any", "--limit": "any",
    "--limit-burst": "any", "--uid-owner": "any", "--gid-owner": "any",
    "--tcp-option": "any", "--clamp-mss-to-pmtu": None, "--set-mss": "any",
    "--ttl-eq": "any", "--ttl-set": "any", "--mac-source": "any",
    "--physdev-in": "iface", "--physdev-out": "iface",
    "--ctmark": "any", "--set-tos": "any", "--set-dscp": "any",
}

PORT_MIN = 1
PORT_MAX = 65535
