import os

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .demo import run_demo
from .engine import Engine, parse_eml
from .models import Message

app = FastAPI(title="SpectraGuard MVP")
engine = Engine()
STATIC = os.path.join(os.path.dirname(__file__), "static")


class MessageIn(BaseModel):
    channel: str = Field("email", pattern="^(email|chat)$")
    sender_addr: str
    sender_name: str = ""
    recipient: str = ""
    subject: str = ""
    body: str = ""
    html: str = ""
    headers: dict = {}
    ts: str | None = None


def _need(mid):
    m = engine.get(mid)
    if not m:
        raise HTTPException(404, "message not found")
    return m


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/config")
def config():
    return engine.cfg


@app.post("/api/messages")
def add_message(m: MessageIn):
    return engine.ingest(Message.from_dict(m.model_dump()))


@app.post("/api/messages/eml")
async def add_eml(request: Request):
    return engine.ingest(parse_eml(await request.body()))


@app.get("/api/messages")
def list_messages(folder: str | None = None):
    return engine.store.list(folder)


@app.get("/api/messages/{mid}")
def get_message(mid: int):
    return _need(mid)


@app.post("/api/messages/{mid}/quarantine")
def quarantine(mid: int):
    _need(mid)
    return engine.quarantine(mid)


@app.post("/api/messages/{mid}/release")
def release(mid: int):
    _need(mid)
    return engine.release(mid)


@app.post("/api/messages/{mid}/label")
def label(mid: int, label: str = Body(..., embed=True, pattern="^(phishing|benign)$")):
    _need(mid)
    return engine.label(mid, label)


@app.post("/api/reset")
def reset():
    engine.store.reset()
    return {"ok": True}


@app.post("/api/demo/run")
def demo():
    return run_demo(engine)
