"""
Routing Helper Module - Expected Routing Matrix Configuration

This module defines the expected routing configuration for the network topology under validation.
It serves as the source of truth for which routes should be present on each router.

ROUTING MATRIX STRUCTURE
========================

The EXPECTED_ROUTING_MATRIX is organized by router, with each router defining:
- Key: Router name (e.g., "R1-DC", "R4", "R5")
- Value: Dict mapping network destinations to expected route specifications

Each route specification includes:
- Route type (direct, indirect, policy route)
- Via information (next-hop device/interface)
- Output interface
- Routing table assignment
- Prefix type (IPv6 global, IPv6 site-local)

ROUTE BUILDERS
==============

Helper functions construct route specifications:

1. direct(iface)
   - For directly connected networks
   - Type: "DIR"
   - No via/next-hop needed
   - Automatically assigned to "local" table
   - Example: direct("eth0") for a network on eth0

2. default(iface, via, onlySite=False)
   - For default routes (0::/0)
   - Type: "IND" (indirect)
   - Parameters:
     * iface: output interface name
     * via: next-hop in format "ROUTER-INTERFACE" (e.g., "R4-eth1")
     * onlySite: if True, only create site-local default; else both global+site
   - Goes to "main" routing table

3. indirect(vias, devs=None, onlySite=False)
   - For reachable networks via one or more hops
   - Type: "IND"
   - Parameters:
     * vias: list of next-hops in format "ROUTER-INTERFACE"
     * devs: output interface(s), or ANY if flexible
     * onlySite: if True, only site-local; else both global+site
   - Uses "main" routing table

4. policy_default(table, iface, via, onlySite=False)
   - For policy-based default routes in specific tables
   - Type: "policy"
   - Goes to specified policy table (e.g., "guest-isolation")

5. policy_drop(table, drop_type=['blackhole','prohibit','unreachable'], onlySite=False)
   - For policy-based drop rules
   - Blocks traffic for specific prefix types to specific tables

TABLES
======

TABLES dict defines special routing tables for policy-based routing:
- "main": default routing table (used by most routes)
- "local": kernel-managed table for directly connected networks
- "to-r3": policy table redirecting TCP packets toward R3
- "guest-isolation": policy table preventing guest network access

MODIFYING THE ROUTING MATRIX
=============================

To adjust routing expectations for a topology change:

1. Identify affected routers
2. Find the route entry for the changed destination
3. Update the route specification using the appropriate builder function
4. Test with the topology XML to ensure validation matches expected behavior

Example: If R5's path to SwAdmin changes from R4 via eth0 to R6 via eth1:
   OLD: "SwAdmin": indirect(["R4-eth0", "R3-eth2"], onlySite=True)
   NEW: "SwAdmin": indirect(["R6-eth1", "R3-eth2"], onlySite=True)

IMPORTANT NOTES
===============

- EXPECTED_ROUTING_MATRIX validates the configuration in parse_xml()
- All changes here require corresponding configuration changes in the XML
- Validation is context-specific to the network topology being analyzed
- Consider adding comments to non-obvious routing decisions
"""

from utils.ip import PREFIX_TYPE

ANY = "__ANY__"
AUTO = "__AUTO__"

TABLES = {
    "main": "main",
    "local": "local",
    "to-r3": "redireccionar paquetes TCP hacia R3",
    "guest-isolation": "redireccionar el tráfico con origen en wguest",
}

def clone_with_prefix_type(route, prefix_type):
    cloned = dict(route)
    cloned["prefix_type"] = prefix_type
    return cloned

def direct(iface=None):
    return [{
        "type": "DIR",
        "via": None,
        "via_info": None,
        "dev": iface,
        "table": "local",
        "dst": AUTO,
        "score": 999,
        "is_default": False,
        "is_policy": False
    }]

def default(iface, via, onlySite=False):
    normalized_vias = []

    node, interface = via.rsplit("-", 1)

    normalized_vias.append({
            "node": node,
            "interface": interface,
            "type": "neighbor"
        })

    base_route =  {
        "type": "IND",
        "via": AUTO,
        "via_info": normalized_vias,
        "dev": iface,
        "table": "main",
        "dst": PREFIX_TYPE["default"],
        "score": 0,
        "is_default": True,
        "is_policy": False
    }

    if onlySite:
        return [
            clone_with_prefix_type(base_route, PREFIX_TYPE["site"])
        ]

    return [
        clone_with_prefix_type(base_route, PREFIX_TYPE["global"]),
        clone_with_prefix_type(base_route, PREFIX_TYPE["site"])
    ]

def indirectISP(vias, devs=None, onlySite = False):
    normalized_vias = []

    for via in vias:
        node, interface = via.rsplit("-", 1)

        normalized_vias.append({
            "node": node,
            "interface": interface,
            "type": "neighbor"
        })

    base_route = {
        "type": "IND",
        "via": AUTO,
        "via_info": normalized_vias,
        "dev": devs if devs else ANY,
        "table": "main",
        "dst": AUTO,
        "score": ANY,
        "is_default": ANY,
        "is_policy": False,
        "prefix_type": PREFIX_TYPE["ipv4"]
    }

    return [base_route]

def indirect(vias, devs=None, onlySite = False):
    normalized_vias = []

    for via in vias:
        node, interface = via.rsplit("-", 1)

        normalized_vias.append({
            "node": node,
            "interface": interface,
            "type": "neighbor"
        })

    base_route = {
        "type": "IND",
        "via": AUTO,
        "via_info": normalized_vias,
        "dev": devs if devs else ANY,
        "table": "main",
        "dst": AUTO,
        "score": ANY,
        "is_default": ANY,
        "is_policy": False
    }

    if onlySite:
        return [
            clone_with_prefix_type(base_route, PREFIX_TYPE["site"])
        ]

    return [
        clone_with_prefix_type(base_route, PREFIX_TYPE["global"]),
        clone_with_prefix_type(base_route, PREFIX_TYPE["site"])
    ]

def policy_default(table, iface, via, onlySite = False):
    normalized_vias = []

    node, interface = via.rsplit("-", 1)

    normalized_vias.append({
        "node": node,
        "interface": interface,
        "type": "neighbor"
    })

    base_route = {
        "type": "policy",
        "via": AUTO,
        "via_info": normalized_vias,
        "dev": iface,
        "table": table,
        "dst": PREFIX_TYPE["default"],
        "score": 0,
        "is_default": True,
        "is_policy": True
    }

    if onlySite:
        return [
            clone_with_prefix_type(base_route, PREFIX_TYPE["site"])
        ]

    return [
        clone_with_prefix_type(base_route, PREFIX_TYPE["global"]),
        clone_with_prefix_type(base_route, PREFIX_TYPE["site"])
    ]

EXPECTED_ROUTING_MATRIX = {
    "R1-DC": {
        "SwDataCenter": direct("eth0"),
        "WVentas": default("eth1", "R4-eth1"),
        "SwVentas": default("eth1", "R4-eth1"),
        "WGuest": default("eth1", "R4-eth1"),
        "SwAdmin": default("eth1", "R4-eth1", True),
        "SwOfiAdmin": default("eth1", "R4-eth1", True),
        "R4<>R1-DC": direct("eth1"),
        "R4<>R5": default("eth1", "R4-eth1"),
        "R5<>R6": default("eth1", "R4-eth1"),
        "R5<>R3": default("eth1", "R4-eth1"),
        "R4<>R3": default("eth1", "R4-eth1"),
        "R2<>R3": default("eth1", "R4-eth1"),
        "R2<>R4": default("eth1", "R4-eth1")
    },

    "R6": {
        "SwDataCenter": default("eth2", "R5-eth0"),
        "WVentas": direct("eth0"),
        "SwVentas": direct("eth1"),
        "WGuest": default("eth2", "R5-eth0"),
        "SwAdmin": default("eth2", "R5-eth0", True),
        "SwOfiAdmin": default("eth2", "R5-eth0", True),
        "R4<>R1-DC": default("eth2", "R5-eth0"),
        "R4<>R5": default("eth2", "R5-eth0"),
        "R5<>R6": direct("eth2"),
        "R5<>R3": default("eth2", "R5-eth0"),
        "R4<>R3": default("eth2", "R5-eth0"),
        "R2<>R3": default("eth2", "R5-eth0"),
        "R2<>R4": default("eth2", "R5-eth0")
    },

    "R3": {
        "SwDataCenter": indirect(["R2-eth1", "R4-eth3", "R5-eth3"]),
        "WVentas":  indirect(["R2-eth1", "R4-eth3", "R5-eth3"]),
        "SwVentas":  indirect(["R2-eth1", "R4-eth3", "R5-eth3"]),
        "WGuest":  indirect(["R2-eth1", "R4-eth3", "R5-eth3"]),
        "SwAdmin": direct("eth0"),
        "SwOfiAdmin": direct("eth1"),
        "R4<>R1-DC": indirect(["R2-eth1", "R4-eth3", "R5-eth3"]),
        "R4<>R5":  indirect(["R2-eth1", "R4-eth3", "R5-eth3"]),
        "R5<>R6":  indirect(["R2-eth1", "R4-eth3", "R5-eth3"]),
        "R5<>R3": direct("eth2"),
        "R4<>R3": direct("eth4"),
        "R2<>R3": direct("eth3"),
        "R2<>R4": indirect(["R2-eth1", "R4-eth3", "R5-eth3"])
    },

    "R5": {
        "SwDataCenter": indirect(["R4-eth0", "R3-eth2"]) + policy_default("guest-isolation", "eth3", "R3-eth2"),
        "WVentas": indirect(["R6-eth2"]) + policy_default("guest-isolation", "eth3", "R3-eth2"),
        "SwVentas": indirect(["R6-eth2"]) + policy_default("guest-isolation", "eth3", "R3-eth2"),
        "WGuest": direct("eth1"),
        "SwAdmin": indirect(["R4-eth0", "R3-eth2"], onlySite=True)  + policy_default("guest-isolation", "eth3", "R3-eth2", True) ,
        "SwOfiAdmin": indirect(["R4-eth0", "R3-eth2"], onlySite=True)  + policy_default("guest-isolation", "eth3", "R3-eth2", True),
        "R1-DC<>R4": indirect(["R4-eth0", "R3-eth2"]) + policy_default("guest-isolation", "eth3", "R3-eth2"),
        "R4<>R5": direct("eth2") + policy_default("guest-isolation", "eth3", "R3-eth2"),
        "R5<>R6": direct("eth0") + policy_default("guest-isolation", "eth3", "R3-eth2"),
        "R5<>R3": direct("eth3") + policy_default("guest-isolation", "eth3", "R3-eth2"),
        "R4<>R3": indirect(["R4-eth0", "R3-eth2"]) + policy_default("guest-isolation", "eth3", "R3-eth2"),
        "R2<>R3": indirect(["R4-eth0", "R3-eth2"]) + policy_default("guest-isolation", "eth3", "R3-eth2"),
        "R2<>R4": indirect(["R4-eth0", "R3-eth2"]) + policy_default("guest-isolation", "eth3", "R3-eth2"),
    },

    "R4": {
        "SwDataCenter": indirect(["R1-DC-eth1"]) + policy_default("to-r3", "eth3", "R3-eth4"),
        "WVentas": indirect(["R5-eth2", "R3-eth4"]) + policy_default("to-r3", "eth3", "R3-eth4"),
        "SwVentas": indirect(["R5-eth2", "R3-eth4"]) + policy_default("to-r3", "eth3", "R3-eth4"),
        "WGuest": indirect(["R5-eth2", "R3-eth4"]) + policy_default("to-r3", "eth3", "R3-eth4"),
        "SwAdmin": indirect(["R5-eth2", "R3-eth4"], onlySite=True) + policy_default("to-r3", "eth3", "R3-eth4", True),
        "SwOfiAdmin": indirect(["R5-eth2", "R3-eth4"], onlySite=True) + policy_default("to-r3", "eth3", "R3-eth4", True),
        "R1-DC<>R4": direct("eth1") + policy_default("to-r3", "eth3", "R3-eth4"),
        "R4<>R5": direct("eth0") + policy_default("to-r3", "eth3", "R3-eth4"),
        "R5<>R6": indirect(["R5-eth2", "R3-eth4"]) + policy_default("to-r3", "eth3", "R3-eth4"),
        "R5<>R3": indirect(["R5-eth2", "R3-eth4"]) + policy_default("to-r3", "eth3", "R3-eth4"),
        "R4<>R3": direct("eth3") + policy_default("to-r3", "eth3", "R3-eth4"),
        "R2<>R3": indirect(["R5-eth2", "R3-eth4", "R2-eth0"]) + policy_default("to-r3", "eth3", "R3-eth4"),
        "R2<>R4": direct("eth2") + policy_default("to-r3", "eth3", "R3-eth4"),
    },

    "R2": {
        "SwDataCenter": indirect(["R4-eth2", "R3-eth3"]),
        "WVentas": indirect(["R4-eth2", "R3-eth3"]),
        "SwVentas": indirect(["R4-eth2", "R3-eth3"]),
        "WGuest": indirect(["R4-eth2", "R3-eth3"]),
        "SwAdmin": indirect(["R4-eth2", "R3-eth3"], onlySite=True),
        "SwOfiAdmin": indirect(["R4-eth2", "R3-eth3"], onlySite=True),
        "R1-DC<>R4": indirect(["R4-eth2", "R3-eth3"]),
        "R4<>R5": indirect(["R4-eth2", "R3-eth3"]),
        "R5<>R6": indirect(["R4-eth2", "R3-eth3"]),
        "R5<>R3": indirect(["R4-eth2", "R3-eth3"]),
        "R4<>R3": indirect(["R4-eth2", "R3-eth3"]),
        "R2<>R3": direct("eth1"),
        "R2<>R4": direct("eth0")
    }
}

ISP_EXPECTED = {
        "ISP-Intranet": {
            "ISP-Casa<>R-Casa": indirectISP(["ISP-Casa-eth0"], devs=["eth1"]),
            "R2<>ISP-Intranet": direct("eth0"),
            "ISP-Casa<>ISP-Intranet": direct("eth1")
        },

        "ISP-Casa": {
            "R2<>ISP-Intranet": indirectISP(["ISP-Intranet-eth1"], devs=["eth0"]),
            "R-Casa<>ISP-Casa": direct("eth1"),
            "ISP-Casa<>ISP-Intranet": direct("eth0")
        }
    }


