from parser.routing import build_routing_matrix
from report.formatters import build_matrix_table
from validation.ip_commands import validate_ip_addr_commands

from .devices import parse_devices, parse_network_nodes
from .links import parse_links
from .services import parse_routing, parse_services
from .l2 import parse_l2_networks

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
        "routing_matrix_table": []
    }

    parse_devices(root, data)
    parse_network_nodes(root, data)
    parse_links(root, data)
    parse_services(root, data)
    parse_routing(data)
    
    
    for node_id in data["services"]:
        validate_ip_addr_commands(node_id, data)

    parse_l2_networks(root, data)

    infer_networks(data)
    validate_networks(data)
    validate_radvd_interfaces(data)

    data["routing_matrix"] = build_routing_matrix(data)

    data["routing_matrix_table"] = build_matrix_table(data["routing_matrix"])

    return data