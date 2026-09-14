from jinja2 import Environment, FileSystemLoader
from pydantic import warnings
from parser.parser import parse_xml
from report.formatters import build_text_warning_summary, build_warning_summary, format_network_name, group_router_warnings_by_type, pretty_networks, summarize, group_warnings
from utils import config_helper
from utils.ip import TYPE_LABELS

env = Environment(loader=FileSystemLoader("templates"))
env.filters["network_name"] = format_network_name

def render_report_html(xml_text, config, filename="uploaded.xml"):
    config_helper.set_config(config)
    result = parse_xml(xml_text)

    summary = summarize(result)
    networks = pretty_networks(result)
    grouped_warnings = group_warnings(result)
    network_names = {network["name"] for network in networks}
    uncategorized_warnings = {
        network_name: warnings
        for network_name, warnings in grouped_warnings.items()
        if network_name not in network_names
    }
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
        warning_summary_text=build_text_warning_summary(result, grouped_warnings, router_warnings),
        TYPE_LABELS=TYPE_LABELS
    )

    return html