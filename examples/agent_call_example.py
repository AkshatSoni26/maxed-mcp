"""Example: what an agent gets back when it calls the maxed-mcp tools.

An MCP client (Claude, or any agent framework that speaks MCP) discovers these
tools from the running server and calls them by name with JSON arguments. Over
the wire a call looks like:

    {"method": "tools/call",
     "params": {"name": "money_allocate",
                "arguments": {"minor_units": 100, "currency": "USD", "parts": 3}}}

and the tool returns the JSON object shown below. This script calls the same
tool functions in-process so you can see the shapes without wiring up a client.

Run:  python examples/agent_call_example.py
      (install the Python backends first for the parser/classifier tools:
       pip install "maxed-mcp[suite]")
"""

from __future__ import annotations

import json

from maxed_mcp import server, hmac_verify


def show(title: str, payload: object) -> None:
    print(f"\n=== {title} ===")
    print(json.dumps(payload, indent=2))


def main() -> None:
    # 0. Discover what is available on this host.
    caps = server.list_capabilities()
    ready = [t["name"] for t in caps["tools"] if t["available"]]
    print("Tools ready on this host:", ", ".join(ready))

    # 1. Parse a messy CSV bank statement into normalized transactions.
    csv = "Date,Description,Amount\n01/05/2024,Coffee Shop,-42.00\n01/06/2024,Payroll,1500.00\n"
    show("normalize_bank_statement", server.normalize_bank_statement(csv))

    # 2. Classify a document by its text.
    invoice = (
        "INVOICE\nInvoice Number: 1043\nBill To: Acme LLC\n"
        "Due Date: 2026-06-01\nSubtotal: 500.00\nTotal Due: 540.00\n"
    )
    show("classify_document", server.classify_document(invoice))

    # 3. Exact money math: split a bill three ways with no lost cents...
    show("money_allocate (split $1.00 three ways)", server.money_allocate(100, "USD", parts=3))
    # ...and apply an 8.25% tax to $19.99.
    show("money_apply_rate (8.25% tax on $19.99)", server.money_apply_rate(1999, "USD", 0.0825))

    # 4. Verify a webhook signature before acting on it.
    body = '{"event":"invoice.paid"}'
    sig = hmac_verify.sign("stripe", "whsec_demo", body, timestamp=1000)
    show(
        "verify_webhook_hmac (stripe)",
        server.verify_webhook_hmac("stripe", "whsec_demo", body, sig, timestamp=1000),
    )

    # 5. Validate a document against the open workpaper spec (needs a
    #    cpa-workpaper-spec checkout via CPA_WORKPAPER_SPEC_DIR).
    show(
        "validate_workpaper (deliberately invalid)",
        server.validate_workpaper({"not": "an engagement"}, "engagement"),
    )


if __name__ == "__main__":
    main()
