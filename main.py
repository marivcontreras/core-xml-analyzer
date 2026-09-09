from logging import config

from fastapi import FastAPI, Form, Request, UploadFile, File
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from parser.parser import parse_xml
from report.formatters import group_router_warnings_by_type, group_warnings, pretty_networks, summarize
from report.report_renderer import render_report_html
from utils import config_helper
from utils.config_helper import load_config

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
async def analyze(request: Request, file: UploadFile = File(...), config: str = Form(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")

    cfg = load_config(f"{config}.yaml")
    config_helper.set_config(cfg)
    html = render_report_html(text, cfg, file.filename)

    return HTMLResponse(content=html)