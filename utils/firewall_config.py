"""
Firewall Configuration Loader

Loads the expected firewall configuration (resources/<class>/firewall.yaml)
referenced by `firewall_config` in the class config.
"""

import yaml

from utils.config_helper import get_config


def load_firewall_yaml():
    """Return the parsed firewall YAML for the current class ({} if none)."""
    config = get_config()
    path = config.get("firewall_config") if config else None
    if not path:
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        #print(f"Warning: Failed to load firewall YAML from {path}: {e}")
        return {}


def get_expected_filters():
    """Expected filter commands per device: {device_name: [command, ...]}."""
    return load_firewall_yaml().get("filters") or {}


def get_expected_routes():
    """Expected routes per router: {router_name: [route, ...]}."""
    return load_firewall_yaml().get("routes") or {}


def get_firewall_sections():
    """Report sections (one per group of consignas), in order: [{title, consignas, firewall, routing}]."""
    return load_firewall_yaml().get("sections") or []


def get_expected_masquerade_routers():
    """Names of the routers that must apply MASQUERADE towards the ISP."""
    masquerade = load_firewall_yaml().get("masquerade") or {}
    return list(masquerade.get("routers") or [])
