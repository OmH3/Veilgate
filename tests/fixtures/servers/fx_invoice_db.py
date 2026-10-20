"""Deterministic FastMCP fixture server: invoicedb."""

from fastmcp import FastMCP

server = FastMCP("invoicedb")


@server.tool
def get_invoice(invoice_id: int) -> dict[str, object]:
    """Retrieve invoice details including sensitive financial accounts."""
    return {
        "invoice_id": invoice_id,
        "customer_name": "Acme Corp",
        "customer_ssn": "000-12-3456",
        "bank_routing_number": "021000021",
        "bank_account_number": "987654321012",
        "invoice_total": 1840.50,
        "deal_margin": "34.5%",
        "salary_band": "Tier-4",
        "x-envoy-upstream-service-time": "12ms",
        "connection": "keep-alive",
        "debug_trace": "db-node-04.internal",
    }


@server.tool
def compare_total(account: str, total: float) -> dict[str, object]:
    """Verify total against account (expects decrypted plaintext account)."""
    return {
        "matched": True,
        "verified_account": account,
        "total": total,
    }


@server.tool
def compare_routing(routing_a: str, routing_b: str) -> dict[str, object]:
    """Compare two routing numbers for equality (expects decrypted plaintext routing numbers)."""
    return {
        "matched": routing_a == routing_b,
        "routing_a_len": len(routing_a),
    }


@server.tool
def get_vendor_details(vendor_id: int) -> dict[str, object]:
    """Retrieve vendor corporate details."""
    return {
        "vendor_id": vendor_id,
        "vendor_name": "Apex Cloud Systems",
        "contact_email": "billing@apexcloud.example.com",
        "bank_account": "112233445566",
        "routing_number": "021000021",
        "deal_margin": "28.0%",
        "salary_band": "Executive",
        "internal_row_id": "row_991823",
        "_links": {"self": "/vendors/991823"},
    }


@server.tool
def delete_invoice(invoice_id: int) -> str:
    """Delete invoice by ID (destructive operation)."""
    return f"Deleted invoice {invoice_id}"


if __name__ == "__main__":
    server.run(transport="stdio")
