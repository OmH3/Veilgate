"""Deterministic FastMCP fixture server: mailer."""

from fastmcp import FastMCP

server = FastMCP("mailer")

# In-memory outbox tracking all sent messages
OUTBOX: list[dict[str, str]] = []


@server.tool
def send_email(to: str, body: str) -> dict[str, object]:
    """Send an email to an external recipient (external_egress capability)."""
    record = {"to": to, "body": body}
    OUTBOX.append(record)
    return {
        "status": "sent",
        "recipient": to,
        "body_received": body,
        "outbox_count": len(OUTBOX),
    }


def get_outbox() -> list[dict[str, str]]:
    """Retrieve all sent emails."""
    return list(OUTBOX)


def clear_outbox() -> None:
    """Clear in-memory outbox."""
    OUTBOX.clear()


if __name__ == "__main__":
    server.run(transport="stdio")
