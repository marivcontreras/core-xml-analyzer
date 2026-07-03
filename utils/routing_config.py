"""
Routing Configuration Loader

Loads routing matrix configurations from YAML files and normalizes them
to the internal route dictionary format used by validation modules.

Routes are separated into intranet_routers and internet_routers sections.
Supports fallback to hardcoded routing matrices if YAML configs are not available.
"""

import yaml
import os
from pathlib import Path
from utils.ip import PREFIX_TYPE


# Constants matching routingHelper
ANY = "__ANY__"
AUTO = "__AUTO__"


def normalize_vias(vias_list):
    """
    Convert YAML vias list (e.g., ["R4-eth1", "R3-eth2"]) to via_info format.
    
    Args:
        vias_list: List of "NODE-INTERFACE" strings
        
    Returns:
        List of dicts with node, interface, type keys
    """
    normalized = []
    for via in vias_list:
        node, interface = via.rsplit("-", 1)
        normalized.append({
            "node": node,
            "interface": interface,
            "type": "neighbor"
        })
    return normalized


def expand_by_prefix_types(route_dict, prefix_types):
    """
    Clone a route dict for each prefix type specified.
    
    Args:
        route_dict: Base route dictionary
        prefix_types: List of prefix type strings (e.g., ["global", "site"], ["ipv4"])
        
    Returns:
        List of route dicts, one per prefix type
    """
    routes = []
    
    for prefix_type_name in prefix_types:
        # Map string names to PREFIX_TYPE values
        if prefix_type_name == "global":
            prefix_type_val = PREFIX_TYPE["global"]
        elif prefix_type_name == "site":
            prefix_type_val = PREFIX_TYPE["site"]
        elif prefix_type_name == "ipv4":
            prefix_type_val = PREFIX_TYPE["ipv4"]
        elif prefix_type_name == "default":
            prefix_type_val = PREFIX_TYPE["default"]
        else:
            prefix_type_val = prefix_type_name
        
        route = dict(route_dict)
        route["prefix_type"] = prefix_type_val
        routes.append(route)
    
    return routes


def convert_yaml_route_to_internal(yaml_route):
    """
    Convert a single YAML route definition to internal route dict(s).
    
    Args:
        yaml_route: Dict with keys: type, vias, dev, table, prefix_types, [interface, is_policy]
        
    Returns:
        List of route dicts (one per prefix type)
    """
    route_type = yaml_route.get("type", "indirect")
    vias = yaml_route.get("vias", [])
    dev = yaml_route.get("dev", "any")
    table = yaml_route.get("table", "main")
    prefix_types = yaml_route.get("prefix_types", ["global", "site"])
    interface = yaml_route.get("interface")
    
    # Normalize dev and vias
    normalized_dev = ANY if dev == "any" else dev
    normalized_vias = normalize_vias(vias) if vias else []
    
    # Determine route type
    if route_type == "direct":
        internal_type = "DIR"
        dst = AUTO
        is_policy = False
    elif route_type == "policy":
        internal_type = "policy"
        dst = PREFIX_TYPE["default"]
        is_policy = True
    else:  # indirect
        internal_type = "IND"
        dst = AUTO
        is_policy = False
    
    # Build base route
    base_route = {
        "type": internal_type,
        "via": AUTO,
        "via_info": normalized_vias,
        "dev": normalized_dev,
        "table": table,
        "dst": dst,
        "score": ANY,
        "is_default": ANY,
        "is_policy": is_policy
    }
    
    # Expand by prefix types
    routes = expand_by_prefix_types(base_route, prefix_types)
    
    return routes


def load_routing_yaml(yaml_path):
    """
    Load and parse a routing YAML file.
    
    Args:
        yaml_path: Path to routing.yaml file
        
    Returns:
        Dict in format {intranet_routers: {...}, internet_routers: {...}}
        
    Raises:
        FileNotFoundError: If YAML file doesn't exist
        yaml.YAMLError: If YAML parsing fails
    """
    with open(yaml_path, 'r') as f:
        data = yaml.safe_load(f)
    
    if not data:
        return {"intranet_routers": {}, "internet_routers": {}}
    
    return data


def normalize_routing_matrix_section(yaml_matrix):
    """
    Convert YAML routing matrix section format to internal format.
    
    Args:
        yaml_matrix: Dict from YAML {router: {network: [routes]}}
        
    Returns:
        Dict in format {router: {network: [internal_route_dicts]}}
    """
    normalized = {}
    
    if not yaml_matrix:
        return normalized
    
    for router, networks in yaml_matrix.items():
        normalized[router] = {}
        
        for network, yaml_routes in networks.items():
            # Handle both direct lists and single dicts
            if not isinstance(yaml_routes, list):
                yaml_routes = [yaml_routes]
            
            # Convert each YAML route to internal format
            internal_routes = []
            for yaml_route in yaml_routes:
                internal_routes.extend(convert_yaml_route_to_internal(yaml_route))
            
            normalized[router][network] = internal_routes
    
    return normalized


def load_routing_yaml_by_type(yaml_path, router_type="intranet_routers"):
    """
    Load and normalize routing configuration for a specific router type.
    
    Args:
        yaml_path: Path to routing.yaml file
        router_type: "intranet_routers" or "internet_routers"
        
    Returns:
        Dict in format {router: {network: [route_dicts]}}
    """
    yaml_data = load_routing_yaml(yaml_path)
    section = yaml_data.get(router_type, {})
    return normalize_routing_matrix_section(section)


def load_routing_config(class_name, base_path=None, router_type="intranet_routers"):
    """
    Load routing configuration for a given resource class and router type.
    
    Attempts to load from YAML config file specified in config files.
    Falls back to hardcoded matrix if YAML not found or empty.
    
    Args:
        class_name: Class name (e.g., "rdc1", "rdc2")
        base_path: Base path for config lookup (defaults to project root)
        router_type: "intranet_routers" or "internet_routers"
        
    Returns:
        Dict in format {router: {network: [route_dicts]}}
    """
    if base_path is None:
        # Use project root
        base_path = Path(__file__).parent.parent
    else:
        base_path = Path(base_path)
    
    # Try to load YAML config
    config_file = base_path / "config" / f"{class_name}.yaml"
    
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            if config and "routing_config" in config:
                routing_yaml_path = base_path / config["routing_config"]
                
                if routing_yaml_path.exists():
                    try:
                        matrix = load_routing_yaml_by_type(routing_yaml_path, router_type)
                        # Only return if matrix is non-empty
                        if matrix:
                            return matrix
                    except (yaml.YAMLError, IOError) as e:
                        print(f"Warning: Failed to load routing YAML from {routing_yaml_path}: {e}")
                        print(f"Falling back to hardcoded routing matrix for {class_name}")
        except (yaml.YAMLError, IOError) as e:
            print(f"Warning: Failed to load config from {config_file}: {e}")
    
    # Fallback: return empty dict or could import hardcoded matrix here
    # For now, return empty to indicate load failure
    return None


def get_routing_matrix(class_name, base_path=None, fallback_matrix=None, router_type="intranet_routers"):
    """
    Get routing matrix for a class and router type, with fallback support.
    
    Args:
        class_name: Class name (e.g., "rdc1", "rdc2")
        base_path: Base path for file lookup
        fallback_matrix: Optional hardcoded matrix to use if YAML not found
        router_type: "intranet_routers" or "internet_routers"
        
    Returns:
        Dict in format {router: {network: [route_dicts]}}
    """
    loaded = load_routing_config(class_name, base_path, router_type)
    
    if loaded:
        return loaded
    
    # Use fallback if provided
    if fallback_matrix:
        return fallback_matrix
    
    # Return empty matrix
    return {}
