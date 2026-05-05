from fastapi import FastAPI, Request, UploadFile, File
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from parser.parser import parse_xml
from report.formatters import group_router_warnings_by_type, group_warnings, pretty_networks, summarize

TYPE_LABELS = {
    "syntax": "Sintaxis",
    "missing": "Faltante",
    "invalid": "Inválido",
    "design": "Diseño",
    "inconsistent": "Inconsistente"
}

app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        name="index.html",
        request=request, 
        context={"id": id}
    )


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    result = parse_xml(text)
    summary = summarize(result)
    networks = pretty_networks(result)
    grouped_warnings = group_warnings(result)

    router_warnings = group_router_warnings_by_type(result)

    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "filename": file.filename,
            "summary": summary,
            "networks": networks,
            "warnings": grouped_warnings,
            "router_warnings": router_warnings,
            "data": result,
            "TYPE_LABELS": TYPE_LABELS
        }
    )

