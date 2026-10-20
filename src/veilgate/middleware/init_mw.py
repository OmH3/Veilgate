"""Initialization middleware handling MCP initialize handshake and server info."""

from fastmcp.server.middleware import Middleware


class InitMiddleware(Middleware):
    """Enriches and validates MCP initialize requests."""

    def __init__(self, server_name: str = "Veilgate", server_version: str = "0.1.0") -> None:
        self.server_name: str = server_name
        self.server_version: str = server_version
