def parse_services(root, data):
    section = root.find("service_configurations")
    if section is None:
        return

    for svc in section.findall("service"):
        node = svc.get("node")
        name = svc.get("name")

        template = svc.find(".//template")
        text = template.text if template is not None and template.text else ""

        if node not in data["services"]:
            data["services"][node] = {}

        data["services"][node][name] = text