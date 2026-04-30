from fastapi import FastAPI, Request, UploadFile, File
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from analyzer import parse_xml, pretty_networks, summarize

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

    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "filename": file.filename,
            "summary": summary,
            "networks": networks,
            "warnings": result["warnings"]
        }
    )