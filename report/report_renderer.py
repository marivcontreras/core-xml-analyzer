from jinja2 import Environment, FileSystemLoader
from pydantic import warnings
from parser.parser import parse_xml
from report.formatters import build_text_warning_summary, build_warning_rows, build_warning_summary, format_network_name, group_router_warnings_by_type, pretty_networks, summarize, group_warnings
from utils import config_helper
from utils.ip import PREFIX_TYPE, TYPE_LABELS

env = Environment(loader=FileSystemLoader("templates"))
env.filters["network_name"] = format_network_name

IPTABLES_COLUMN_LABELS = {
    "table": "Tabla",
    "chain": "Chain",
    "src": "Src",
    "dst": "Dst",
    "iif": "Eth-IN",
    "oif": "Eth-OUT",
    "protocol": "Proto",
    "mark": "Mark",
    "target": "Target",
}

# -------------------------------------------------------------
# Warnings that belong neither to a network nor to an existing router
# (those are shown in their own panels).
# -------------------------------------------------------------
def group_uncategorized_warnings(data, network_names):
    router_names = {router["name"] for router in data["routers"].values()}
    pending = []

    for w in data["warnings"]:
        if w.get("network", PREFIX_TYPE["global"]) in network_names:
            continue

        if w.get("scope") in ("node", "interface") and w.get("node") in router_names:
            continue

        pending.append(w)

    return group_warnings({"warnings": pending})

def render_report_html(xml_text, config, filename="uploaded.xml"):
    config_helper.set_config(config)
    result = parse_xml(xml_text)

    summary = summarize(result)
    networks = pretty_networks(result)
    grouped_warnings = group_warnings(result)
    network_names = {network["name"] for network in networks}
    uncategorized_warnings = group_uncategorized_warnings(result, network_names)
    router_warnings = group_router_warnings_by_type(result)

    template = env.get_template("report.html")

    html = template.render(
        filename=filename,
        summary=summary,
        networks=networks,
        warnings=grouped_warnings,
        uncategorized_warnings=uncategorized_warnings,
        router_warnings=router_warnings,
        data=result,
        warning_summary=build_warning_summary(result, grouped_warnings, router_warnings),
        warning_rows=build_warning_rows(result, router_warnings),
        warning_summary_text=build_text_warning_summary(result, grouped_warnings, router_warnings),
        TYPE_LABELS=TYPE_LABELS,
        IPTABLES_COLUMN_LABELS=IPTABLES_COLUMN_LABELS,
        iptables_columns=config_helper.get_iptables_columns(),
    )

    return html