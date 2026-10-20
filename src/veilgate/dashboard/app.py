from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from veilgate.dashboard.api import get_db, router
from veilgate.repositories.db import DatabaseManager

DASHBOARD_DIR: Path = Path(__file__).parent
TEMPLATES_DIR: Path = DASHBOARD_DIR / "templates"
STATIC_DIR: Path = DASHBOARD_DIR / "static"


def create_dashboard_app(db_manager: DatabaseManager) -> FastAPI:
    """Instantiate and configure FastAPI dashboard application."""
    app = FastAPI(
        title="Veilgate Privacy Firewall Dashboard",
        version="0.1.0",
        description="Local-first observability and human-in-the-loop review dashboard for Veilgate.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def get_index() -> str:
        index_file = TEMPLATES_DIR / "index.html"
        if index_file.exists():
            return index_file.read_text(encoding="utf-8")
        return "<h1>Veilgate Dashboard</h1><p>Static templates not found.</p>"

    # Override dependency to provide live DatabaseManager
    app.dependency_overrides[get_db] = lambda: db_manager

    app.include_router(router)
    return app
