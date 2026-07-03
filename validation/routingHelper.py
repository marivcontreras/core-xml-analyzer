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
        "score": ANY,
        "is_default": ANY,
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
        "score": ANY,
        "is_default": ANY,
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


# Routing matrices are now loaded from YAML config files (resources/{class}/routing.yaml)
# See: get_expected_routing_matrix() and get_expected_isp_routing_matrix()
# Removing hardcoded matrices - they have been migrated to:
# - resources/rdc2/routing.yaml (intranet_routers and internet_routers sections)
# - resources/rdc1/routing.yaml (placeholder with same structure)


def get_expected_routing_matrix():
    """
    Load the expected intranet routing matrix from YAML config.
    Returns empty dict if config or loading fails.
    
    Checks if a routing config path is configured in the current config,
    loads it, and returns the normalized routing matrix for intranet routers.
    
    Returns:
        Dict in format {router: {network: [route_dicts]}}
    """
    from utils.config_helper import get_config
    from utils.routing_config import get_routing_matrix
    
    current_config = get_config()
    
    # Try to load routing config from YAML
    if current_config and "routing_config" in current_config:
        routing_yaml_path = current_config["routing_config"]
        
        # Extract class name from routing config path (e.g., "rdc2" from "resources/rdc2/routing.yaml")
        import os
        class_name = os.path.basename(os.path.dirname(routing_yaml_path))
        
        try:
            loaded_matrix = get_routing_matrix(class_name, router_type="intranet_routers")
            if loaded_matrix:
                return loaded_matrix
        except Exception as e:
            print(f"Warning: Failed to load routing matrix from YAML: {e}")
    
    # Fallback: return empty matrix if no config or loading failed
    return {}


def get_expected_isp_routing_matrix():
    """
    Load the expected internet (ISP) routing matrix from YAML config.
    Returns empty dict if config or loading fails.
    
    Checks if a routing config path is configured in the current config,
    loads it, and returns the normalized routing matrix for internet routers.
    
    Returns:
        Dict in format {router: {network: [route_dicts]}}
    """
    from utils.config_helper import get_config
    from utils.routing_config import get_routing_matrix
    
    current_config = get_config()
    
    # Try to load routing config from YAML
    if current_config and "routing_config" in current_config:
        routing_yaml_path = current_config["routing_config"]
        
        # Extract class name from routing config path (e.g., "rdc2" from "resources/rdc2/routing.yaml")
        import os
        class_name = os.path.basename(os.path.dirname(routing_yaml_path))
        
        try:
            loaded_matrix = get_routing_matrix(class_name, router_type="internet_routers")
            if loaded_matrix:
                return loaded_matrix
        except Exception as e:
            print(f"Warning: Failed to load ISP routing matrix from YAML: {e}")
    
    # Fallback: return empty matrix if no config or loading failed
    return {}


