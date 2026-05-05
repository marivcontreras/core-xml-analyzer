from parser.devices import parse_ip6tables, parse_routes, parse_rules
from report.formatters import strip_comments

def parse_services(root, data):
    section = root.find("service_configurations")
    if section is None:
        return

    for svc in section.findall("service"):
        node = svc.get("node")
        name = svc.get("name")

        template = svc.find(".//template")
        text = template.text if template is not None and template.text else ""

        # 👇 limpiar comentarios acá
        text = strip_comments(text)

        if node not in data["services"]:
            data["services"][node] = {}

        data["services"][node][name] = text

def parse_routing(data):
    data["routing"] = {}

    for node_id, services in data["services"].items():
        if "StaticRoute" not in services:
            continue

        text = services["StaticRoute"]

        data["routing"][node_id] = {
            "routes": parse_routes(text),
            "rules": parse_rules(text),
            "iptables": parse_ip6tables(text)
        }