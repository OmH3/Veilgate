"""Context middleware managing session lifecycle, correlation IDs, and transport metadata."""

from fastmcp.server.middleware import Middleware
from ulid import ULID

from veilgate.config.policy_models import Transport
from veilgate.services.models import SessionContext


class ContextMiddleware(Middleware):
    """Establishes and propagates SessionContext across incoming MCP requests."""

    def __init__(self, default_session_id: str | None = None, transport: Transport = Transport.STDIO) -> None:
        self.session_id: str = default_session_id or f"ses_{ULID()}"
        self.transport: Transport = transport
        self.session_ctx: SessionContext = SessionContext(
            session_id=self.session_id,
            correlation_id=str(ULID()),
            integrity="HIGH",
            transport=self.transport,
        )

    def get_session(self) -> SessionContext:
        """Retrieve active session context with refreshed correlation ID."""
        self.session_ctx.correlation_id = str(ULID())
        return self.session_ctx
