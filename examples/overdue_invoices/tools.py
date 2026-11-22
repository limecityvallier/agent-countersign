"""Synthetic accounts-receivable tools for the demo. No real data."""

from __future__ import annotations

import sqlite3
from datetime import date, timedelta
from pathlib import Path

from agent_countersign import Gateway

_SEED = [
    # id, name, email, phone, invoice, amount, days overdue
    (1, "Harbor Plumbing Co.", "billing@harborplumbing.example", "555-201-3344", "INV-1042", 1840.00, 47),
    (2, "Maple Street Dental", "office@maplestreetdental.example", "555-877-1200", "INV-1057", 620.50, 18),
    (3, "Riverside Bakery", "owner@riversidebakery.example", "555-430-9981", "INV-1061", 95.00, 5),
    (4, "Northgate Fitness", "accounts@northgatefit.example", "555-612-0045", "INV-1070", 310.00, 0),
]


def make_business_db(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(str(path), check_same_thread=False)
    db.executescript("""
        DROP TABLE IF EXISTS customers; DROP TABLE IF EXISTS invoices; DROP TABLE IF EXISTS outbox;
        CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT);
        CREATE TABLE invoices (number TEXT PRIMARY KEY, customer_id INTEGER, amount REAL, due TEXT, paid INTEGER);
        CREATE TABLE outbox (id INTEGER PRIMARY KEY, kind TEXT, customer_id INTEGER, detail TEXT);
    """)
    today = date.today()
    for cid, name, email, phone, inv, amount, overdue in _SEED:
        db.execute("INSERT INTO customers VALUES (?,?,?,?)", (cid, name, email, phone))
        db.execute("INSERT INTO invoices VALUES (?,?,?,?,0)",
                   (inv, cid, amount, (today - timedelta(days=overdue)).isoformat()))
    db.commit()
    return db


def register_tools(gw: Gateway, db: sqlite3.Connection) -> None:
    @gw.tool()
    def list_overdue_invoices(min_days: int = 1) -> list[dict]:
        """List unpaid invoices at least `min_days` past due, oldest first."""
        cutoff = (date.today() - timedelta(days=min_days)).isoformat()
        rows = db.execute(
            "SELECT i.number, i.customer_id, c.name, i.amount, i.due FROM invoices i "
            "JOIN customers c ON c.id = i.customer_id WHERE i.paid = 0 AND i.due <= ? ORDER BY i.due",
            (cutoff,)).fetchall()
        return [{"invoice": r[0], "customer_id": r[1], "customer": r[2], "amount": r[3], "due": r[4]}
                for r in rows]

    @gw.tool()
    def get_customer(customer_id: int) -> dict:
        """Get a customer's details."""
        r = db.execute("SELECT id, name, email, phone FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not r:
            raise ValueError(f"No customer {customer_id}")
        return {"id": r[0], "name": r[1], "email": r[2], "phone": r[3]}

    @gw.tool(cost_usd=0.01)
    def send_email(customer_id: int, subject: str, body: str) -> str:
        """Send an email to a customer. The address is looked up here, so the model never needs it."""
        email = db.execute("SELECT email FROM customers WHERE id = ?", (customer_id,)).fetchone()[0]
        db.execute("INSERT INTO outbox (kind, customer_id, detail) VALUES ('email', ?, ?)",
                   (customer_id, f"To {email}: {subject}"))
        db.commit()
        return f"Email queued to customer {customer_id}."

    @gw.tool(cost_usd=0.02)
    def issue_refund(customer_id: int, amount: float) -> str:
        """Issue a refund to a customer."""
        db.execute("INSERT INTO outbox (kind, customer_id, detail) VALUES ('refund', ?, ?)",
                   (customer_id, f"${amount:.2f}"))
        db.commit()
        return f"Refund of ${amount:.2f} issued to customer {customer_id}."
