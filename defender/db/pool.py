from contextlib import closing

import psycopg
from psycopg.rows import tuple_row


def connect(database_url: str):
    """Create an autocommit psycopg connection."""
    return psycopg.connect(database_url, autocommit=True, row_factory=tuple_row)


def with_conn(database_url: str, fn):
    """Run a function with a DB connection and ensure it closes."""
    with closing(connect(database_url)) as conn:
        return fn(conn)
