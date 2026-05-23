from parser.routing import build_routing_matrix
from report.formatters import build_matrix_table, build_text_warning_summary
from validation.ip_commands import validate_ip_addr_commands
from validation.routingHelper import EXPECTED_ROUTING_MATRIX
from validation.routingValidation import validate_routing_matrix, validate_isp_routes, validate_tunnels, propagate_routing_warnings

from .devices import parse_devices, parse_l2_networks, parse_network_nodes
from .links import parse_links
from .services import parse_routing, parse_services

from analyzer.networks import infer_networks
from validation.networks import validate_networks
from validation.radvd import validate_radvd_interfaces
import xml.etree.ElementTree as ET

def parse_xml(xml_text):
    root = ET.fromstring(xml_text)

    data = {
        "devices": {},
        "links": [],
        "services": {},
        "routers": {},
        "networks": {},
        "nodes": {},
        "warnings": [],
        "routing_matrix": [],
        "routing_matrix_table": [],
        "routing_validation": {}
    }

    parse_devices(root, data)
    parse_network_nodes(root, data)
    parse_links(root, data)
    parse_services(root, data)    
    
    for node_id in data["services"]:
        validate_ip_addr_commands(node_id, data)

    parse_l2_networks(root, data)

    infer_networks(data)

    parse_routing(data)
    
    validate_networks(data)
    validate_radvd_interfaces(data)

    data["routing_matrix"] = build_routing_matrix(data)

    data["routing_validation"] = validate_routing_matrix(data["routing_matrix"], EXPECTED_ROUTING_MATRIX)

    propagate_routing_warnings(data, data["routing_validation"])

    data["routing_matrix_table"] = build_matrix_table(data["routing_matrix"], data["networks"], data["routing_validation"])

    validate_isp_routes(data)

    validate_tunnels(data)

    
    #print(data["routing_validation"]);

    return data