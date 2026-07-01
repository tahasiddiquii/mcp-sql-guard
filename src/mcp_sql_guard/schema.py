"""The demo warehouse.

A small synthetic DuckDB database, created in memory from fixed rows so the whole
thing runs offline and deterministically. `TABLE_COLUMNS` drives `SELECT *`
expansion during PII analysis, so masking is correct even when a query does not
name its columns.
"""

from __future__ import annotations

import duckdb

TABLE_COLUMNS: dict[str, list[str]] = {
    "customers": ["id", "name", "email", "phone", "region", "signup_date"],
    "orders": ["id", "customer_id", "product", "amount", "region", "order_date"],
    "products": ["sku", "name", "category", "price"],
}

_CUSTOMERS = [
    (1, "Dana Lee", "dana.lee@example.com", "415-555-0142", "US", "2026-01-05"),
    (2, "Sam Ortiz", "sam.ortiz@example.com", "628-555-0175", "US", "2026-02-11"),
    (3, "Lena Fischer", "lena.fischer@example.de", "+49-30-5550199", "EU", "2026-02-20"),
    (4, "Omar Haddad", "omar.haddad@example.com", "212-555-0188", "US", "2026-03-02"),
    (5, "Yuki Tanaka", "yuki.tanaka@example.jp", "+81-3-5550123", "EU", "2026-03-15"),
]

_ORDERS = [
    (101, 1, "Standard Plan", 49.0, "US", "2026-04-01"),
    (102, 1, "Add-on Seats", 120.0, "US", "2026-05-01"),
    (103, 2, "Standard Plan", 49.0, "US", "2026-04-12"),
    (104, 3, "Enterprise Plan", 900.0, "EU", "2026-05-09"),
    (105, 4, "Standard Plan", 49.0, "US", "2026-05-20"),
    (106, 5, "Enterprise Plan", 900.0, "EU", "2026-06-01"),
]

_PRODUCTS = [
    ("STD", "Standard Plan", "subscription", 49.0),
    ("ADD", "Add-on Seats", "subscription", 120.0),
    ("ENT", "Enterprise Plan", "subscription", 900.0),
]


def build_warehouse() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    con.execute("CREATE TABLE customers(id INTEGER, name TEXT, email TEXT, phone TEXT, region TEXT, signup_date TEXT)")
    con.execute("CREATE TABLE orders(id INTEGER, customer_id INTEGER, product TEXT, amount DOUBLE, region TEXT, order_date TEXT)")
    con.execute("CREATE TABLE products(sku TEXT, name TEXT, category TEXT, price DOUBLE)")
    con.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?)", _CUSTOMERS)
    con.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)", _ORDERS)
    con.executemany("INSERT INTO products VALUES (?, ?, ?, ?)", _PRODUCTS)
    return con
