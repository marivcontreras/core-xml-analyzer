"""
ip route Commands Validation Configuration

Consolidates the parameters used by validation/route_commands.py.
Extend the sets/dicts below to accept more route types or attributes
without touching the validation logic.
"""

# Actions that define a route; the rest of the actions are not validated.
ROUTE_DEFINING_ACTIONS = {"add", "append", "change", "replace", "prepend"}

# Actions that exist in iproute2 but do not define a route.
ROUTE_OTHER_ACTIONS = {"del", "delete", "show", "list", "flush", "get", "save", "restore"}

ROUTE_TYPES = {
    "unicast", "blackhole", "prohibit", "unreachable", "local", "broadcast",
    "multicast", "throw", "anycast", "nat",
}

# Route types that carry a destination but no next hop.
ROUTE_TYPES_WITHOUT_NEXT_HOP = {"blackhole", "prohibit", "unreachable", "throw"}

DEFAULT_DESTINATIONS = {"default", "0.0.0.0/0", "::/0"}

# keyword -> kind of value it takes. Kinds:
#   None    : flag without value
#   "addr"  : IP address (family must match the route)
#   "iface" : interface name
#   "table" : routing table name or number
#   "int"   : non negative integer
#   "word"  : free-form word
ROUTE_KEYWORDS = {
    "via": "addr",
    "dev": "iface",
    "table": "table",
    "metric": "int", "priority": "int", "preference": "int",
    "src": "addr",
    "proto": "word", "protocol": "word",
    "scope": "word",
    "mtu": "word", "advmss": "int", "window": "int", "rtt": "word",
    "realm": "word", "realms": "word",
    "onlink": None, "pervasive": None, "linkdown": None,
    "initcwnd": "int", "initrwnd": "int", "hoplimit": "int",
    "tos": "word", "dsfield": "word",
}

# Keywords that may only appear once.
ROUTE_UNIQUE_KEYWORDS = {"via", "dev", "table", "metric", "priority", "src", "scope", "proto", "protocol"}

# Maximum value of an unsigned 32-bit attribute (metric, table number).
ROUTE_INT_MAX = 4294967295
