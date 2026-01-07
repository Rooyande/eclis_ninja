from __future__ import annotations

from typing import Optional, List, Tuple
from defender.db.pool import with_conn


def init_management_schema(database_url: str) -> None:
    def _run(conn):
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS management_groups (
            mg_chat_id BIGINT PRIMARY KEY,
            owner_user_id BIGINT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now()
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS mg_subgroups (
            mg_chat_id BIGINT NOT NULL,
            subgroup_chat_id BIGINT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now(),
            PRIMARY KEY (mg_chat_id, subgroup_chat_id)
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS mg_settings (
            mg_chat_id BIGINT PRIMARY KEY,
            add_member_mode TEXT NOT NULL DEFAULT 'ask'  -- ask | all
        );
        """)

        conn.commit()

    with_conn(database_url, _run)


def set_management_group(database_url: str, mg_chat_id: int, owner_user_id: int) -> None:
    def _run(conn):
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO management_groups (mg_chat_id, owner_user_id)
            VALUES (%s, %s)
            ON CONFLICT (mg_chat_id) DO UPDATE SET owner_user_id = EXCLUDED.owner_user_id
            """,
            (mg_chat_id, owner_user_id),
        )
        cur.execute(
            """
            INSERT INTO mg_settings (mg_chat_id)
            VALUES (%s)
            ON CONFLICT (mg_chat_id) DO NOTHING
            """,
            (mg_chat_id,),
        )
        conn.commit()

    with_conn(database_url, _run)


def get_management_group_owner(database_url: str, mg_chat_id: int) -> Optional[int]:
    def _run(conn):
        cur = conn.cursor()
        cur.execute("SELECT owner_user_id FROM management_groups WHERE mg_chat_id = %s", (mg_chat_id,))
        row = cur.fetchone()
        return int(row[0]) if row else None

    return with_conn(database_url, _run)


def add_subgroup(database_url: str, mg_chat_id: int, subgroup_chat_id: int) -> None:
    def _run(conn):
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO mg_subgroups (mg_chat_id, subgroup_chat_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (mg_chat_id, subgroup_chat_id),
        )
        conn.commit()

    with_conn(database_url, _run)


def list_subgroups(database_url: str, mg_chat_id: int) -> List[int]:
    def _run(conn):
        cur = conn.cursor()
        cur.execute(
            "SELECT subgroup_chat_id FROM mg_subgroups WHERE mg_chat_id=%s ORDER BY created_at DESC",
            (mg_chat_id,),
        )
        return [int(x[0]) for x in cur.fetchall()]

    return with_conn(database_url, _run)


def set_add_member_mode(database_url: str, mg_chat_id: int, mode: str) -> None:
    if mode not in ("ask", "all"):
        raise ValueError("bad_mode")

    def _run(conn):
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO mg_settings (mg_chat_id, add_member_mode)
            VALUES (%s, %s)
            ON CONFLICT (mg_chat_id) DO UPDATE SET add_member_mode=EXCLUDED.add_member_mode
            """,
            (mg_chat_id, mode),
        )
        conn.commit()

    with_conn(database_url, _run)


def get_add_member_mode(database_url: str, mg_chat_id: int) -> str:
    def _run(conn):
        cur = conn.cursor()
        cur.execute("SELECT add_member_mode FROM mg_settings WHERE mg_chat_id=%s", (mg_chat_id,))
        row = cur.fetchone()
        return str(row[0]) if row else "ask"

    return with_conn(database_url, _run)
