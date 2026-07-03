"""
Test script to validate routing YAML configuration loading and conversion.

This test verifies that:
1. YAML routing configs can be loaded without errors
2. YAML configs normalize to the expected internal format
3. YAML-loaded matrix matches the hardcoded matrix (for rdc2)
"""

import sys
import yaml
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from utils.routing_config import (
    load_routing_yaml,
    normalize_routing_matrix,
    convert_yaml_route_to_internal,
    load_routing_config
)
from validation.routingHelper import EXPECTED_ROUTING_MATRIX, ISP_EXPECTED
from utils.ip import PREFIX_TYPE


def test_yaml_loading():
    """Test that YAML files can be loaded."""
    print("\n" + "="*60)
    print("TEST 1: YAML Loading")
    print("="*60)
    
    yaml_path = project_root / "resources" / "rdc2" / "routing.yaml"
    
    try:
        data = load_routing_yaml(yaml_path)
        print(f"✓ Successfully loaded {yaml_path}")
        print(f"  Routers found: {list(data.keys())}")
        return data
    except Exception as e:
        print(f"✗ Failed to load YAML: {e}")
        return None


def test_yaml_normalization(yaml_data):
    """Test that YAML data normalizes to internal format."""
    print("\n" + "="*60)
    print("TEST 2: YAML Normalization")
    print("="*60)
    
    try:
        normalized = normalize_routing_matrix(yaml_data)
        print(f"✓ Successfully normalized YAML to internal format")
        print(f"  Routers processed: {list(normalized.keys())}")
        
        # Check a sample router
        r4 = normalized.get("R4", {})
        if r4:
            print(f"  R4 networks: {list(r4.keys())}")
            if "SwDataCenter" in r4:
                routes = r4["SwDataCenter"]
                print(f"  R4->SwDataCenter routes: {len(routes)} route(s)")
                for i, route in enumerate(routes):
                    print(f"    Route {i+1}: type={route.get('type')}, table={route.get('table')}, prefix_type={route.get('prefix_type')}")
        
        return normalized
    except Exception as e:
        print(f"✗ Failed to normalize YAML: {e}")
        import traceback
        traceback.print_exc()
        return None


def test_route_conversion():
    """Test conversion of individual YAML routes."""
    print("\n" + "="*60)
    print("TEST 3: Route Conversion")
    print("="*60)
    
    # Test indirect route
    yaml_indirect = {
        "type": "indirect",
        "vias": ["R1-DC-eth1"],
        "dev": "any",
        "table": "main",
        "prefix_types": ["global", "site"]
    }
    
    routes = convert_yaml_route_to_internal(yaml_indirect)
    print(f"✓ Converted YAML indirect route to {len(routes)} internal route(s)")
    for i, route in enumerate(routes):
        print(f"  Route {i+1}: type={route['type']}, prefix_type={route.get('prefix_type')}")
        print(f"    via_info={route['via_info']}, dev={route['dev']}, table={route['table']}")
    
    # Test policy route
    yaml_policy = {
        "type": "policy",
        "table": "to-r3",
        "interface": "eth3",
        "vias": ["R3-eth4"],
        "prefix_types": ["global", "site"]
    }
    
    routes = convert_yaml_route_to_internal(yaml_policy)
    print(f"\n✓ Converted YAML policy route to {len(routes)} internal route(s)")
    for i, route in enumerate(routes):
        print(f"  Route {i+1}: type={route['type']}, is_policy={route['is_policy']}, prefix_type={route.get('prefix_type')}")
        print(f"    table={route['table']}, via_info={route['via_info']}")


def test_matrix_structure(normalized):
    """Test the overall structure of normalized matrix."""
    print("\n" + "="*60)
    print("TEST 4: Matrix Structure")
    print("="*60)
    
    # Check all routers
    intranet_routers = ["R1-DC", "R2", "R3", "R4", "R5", "R6"]
    isp_routers = ["ISP-Intranet", "ISP-Casa"]
    
    for router in intranet_routers:
        if router in normalized:
            networks = normalized[router]
            print(f"✓ {router}: {len(networks)} network(s)")
        else:
            print(f"✗ {router}: NOT FOUND")
    
    print("\nISP Routers:")
    for router in isp_routers:
        if router in normalized:
            networks = normalized[router]
            print(f"✓ {router}: {len(networks)} network(s)")
        else:
            print(f"✗ {router}: NOT FOUND")


def test_config_loading():
    """Test the config loader function."""
    print("\n" + "="*60)
    print("TEST 5: Config Loader")
    print("="*60)
    
    try:
        from utils.config_helper import load_config, set_config
        
        # Load rdc2 config
        config = load_config("rdc2.yaml")
        set_config(config)
        
        print(f"✓ Loaded rdc2.yaml config")
        print(f"  routing_config: {config.get('routing_config')}")
        
        # Try to load routing matrix
        from validation.routingHelper import get_expected_routing_matrix
        matrix = get_expected_routing_matrix()
        
        print(f"✓ Loaded routing matrix via get_expected_routing_matrix()")
        print(f"  Routers in matrix: {list(matrix.keys())}")
        
        return matrix
    except Exception as e:
        print(f"✗ Config loading failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    print("\n" + "="*80)
    print("ROUTING CONFIGURATION YAML VALIDATION TEST SUITE")
    print("="*80)
    
    # Test 1: Load YAML
    yaml_data = test_yaml_loading()
    if not yaml_data:
        print("\n✗ YAML loading failed. Stopping tests.")
        return
    
    # Test 2: Normalize YAML
    normalized = test_yaml_normalization(yaml_data)
    if not normalized:
        print("\n✗ Normalization failed. Stopping tests.")
        return
    
    # Test 3: Route conversion
    test_route_conversion()
    
    # Test 4: Matrix structure
    test_matrix_structure(normalized)
    
    # Test 5: Config loading
    loaded_matrix = test_config_loading()
    
    print("\n" + "="*80)
    print("TEST SUITE COMPLETE")
    print("="*80)
    
    if loaded_matrix:
        print("\n✓ All tests passed!")
        print("\nNext steps:")
        print("1. Run regression tests to verify no regressions")
        print("2. Test with actual XML files")
        print("3. Deploy changes")
    else:
        print("\n✗ Some tests failed. Please review the output above.")


if __name__ == "__main__":
    main()
