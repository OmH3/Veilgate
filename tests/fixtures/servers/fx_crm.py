"""Deterministic FastMCP fixture server: crm with Indian PII entities."""

from fastmcp import FastMCP

server = FastMCP("crm")


@server.tool
def get_customer(customer_id: str) -> dict[str, object]:
    """Retrieve Indian enterprise customer details containing national identifiers."""
    return {
        "customer_id": customer_id,
        "name": "Rajesh Kumar",
        "email": "rajesh.kumar@example.in",
        "phone": "+91 98765 43210",
        "aadhaar_number": "2345 6789 0123",
        "pan_number": "ABCDE1234F",
        "ifsc_code": "HDFC0001234",
        "upi_id": "rajesh@okhdfcbank",
        "notes": "Verified client KYC on 2026-01-15",
    }


@server.tool
def update_customer_notes(customer_id: str, notes: str) -> dict[str, object]:
    """Update notes for customer."""
    return {
        "customer_id": customer_id,
        "notes_updated": notes,
        "status": "success",
    }


if __name__ == "__main__":
    server.run(transport="stdio")
