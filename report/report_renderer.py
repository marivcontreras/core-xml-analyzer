from jinja2 import Environment, FileSystemLoader
from pydantic import warnings
from parser.parser import parse_xml
from report.formatters import build_warning_summary, group_router_warnings_by_type, pretty_networks, summarize, group_warnings

env = Environment(loader=FileSystemLoader("templates"))

TYPE_LABELS = {
    "syntax": "Sintaxis",
    "missing": "Faltante",
    "invalid": "Inválido",
    "design": "Diseño",
    "inconsistent": "Inconsistente",
    "isp": "ISP",
    "routing": "Ruteo",
    "tunnels": "Túneles",
    "error": "Errores",
    "warning": "Advertencias"
}

def render_report_html(xml_text, filename="uploaded.xml"):
    result = parse_xml(xml_text)

    summary = summarize(result)
    networks = pretty_networks(result)
    grouped_warnings = group_warnings(result)
    router_warnings = group_router_warnings_by_type(result)

    template = env.get_template("report.html")

    html = template.render(
        filename=filename,
        summary=summary,
        networks=networks,
        warnings=grouped_warnings,
        router_warnings=router_warnings,
        data=result,
        warning_summary=build_warning_summary(result, grouped_warnings, router_warnings),
        TYPE_LABELS=TYPE_LABELS
    )

    return html