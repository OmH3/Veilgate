"""FastAPI application factory for Veilgate Dashboard."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from veilgate.dashboard.api import get_db, router
from veilgate.repositories.db import DatabaseManager


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

    # Override dependency to provide live DatabaseManager
    app.dependency_overrides[get_db] = lambda: db_manager

    app.include_router(router)
    return app
