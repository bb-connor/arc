from __future__ import annotations

import os

from fastapi import FastAPI
from pydantic import BaseModel

from arc_asgi import ArcASGIMiddleware
from arc_asgi.config import ArcASGIConfig


class EchoRequest(BaseModel):
    message: str
    count: int = 1


def create_app() -> FastAPI:
    app = FastAPI(
        title="hello-fastapi",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.add_middleware(
        ArcASGIMiddleware,
        config=ArcASGIConfig(
            sidecar_url=os.environ.get("ARC_SIDECAR_URL", "http://127.0.0.1:9090"),
            exclude_paths=frozenset({"/healthz"}),
        ),
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/hello")
    async def hello() -> dict[str, str]:
        return {"message": "hello from fastapi"}

    @app.post("/echo")
    async def echo(payload: EchoRequest) -> dict[str, object]:
        return {
            "message": payload.message,
            "count": payload.count,
        }

    return app


app = create_app()
