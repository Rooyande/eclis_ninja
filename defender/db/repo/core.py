from __future__ import annotations

from typing import Iterable

from defender.db.pool import with_conn


def init_schema(database_url: str) -> None:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS allowed_members (
                    user_id BIGINT PRIMARY KEY,
                    last_known_username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS protected_chats (
                    chat_id BIGINT PRIMARY KEY
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS global_banned (
                    user_id BIGINT PRIMARY KEY
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_users (
                    chat_id BIGINT,
                    user_id BIGINT,
                    last_seen TIMESTAMPTZ DEFAULT NOW(),
                    PRIMARY KEY (chat_id, user_id)
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS join_logs (
                    id BIGSERIAL PRIMARY KEY,
                    chat_id BIGINT NOT NULL,
                    chat_title TEXT,
                    user_id BIGINT NOT NULL,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    joined_at TIMESTAMPTZ DEFAULT NOW(),
                    action_taken TEXT
                );
                """
            )
    with_conn(database_url, _run)


def upsert_allowed_member(
    database_url: str,
    user_id: int,
    username: str | None,
    first_name: str | None,
    last_name: str | None,
) -> None:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO allowed_members(user_id, last_known_username, first_name, last_name, updated_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON CONFLICT (user_id)
                DO UPDATE SET
                    last_known_username = EXCLUDED.last_known_username,
                    first_name = EXCLUDED.first_name,
                    last_name = EXCLUDED.last_name,
                    updated_at = NOW();
                """,
                (user_id, username, first_name, last_name),
            )
    with_conn(database_url, _run)


def remove_allowed_member(database_url: str, user_id: int) -> None:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM allowed_members WHERE user_id=%s", (user_id,))
    with_conn(database_url, _run)


def is_allowed_member(database_url: str, user_id: int) -> bool:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM allowed_members WHERE user_id=%s", (user_id,))
            return cur.fetchone() is not None
    return bool(with_conn(database_url, _run))


def list_allowed_members(database_url: str) -> list[tuple[int, str | None]]:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute("SELECT user_id, last_known_username FROM allowed_members ORDER BY user_id")
            return [(int(r[0]), r[1]) for r in cur.fetchall()]
    return with_conn(database_url, _run)


def add_protected_chat(database_url: str, chat_id: int) -> None:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO protected_chats(chat_id) VALUES (%s) ON CONFLICT DO NOTHING",
                (chat_id,),
            )
    with_conn(database_url, _run)


def remove_protected_chat(database_url: str, chat_id: int) -> None:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM protected_chats WHERE chat_id=%s", (chat_id,))
    with_conn(database_url, _run)


def is_protected_chat(database_url: str, chat_id: int) -> bool:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM protected_chats WHERE chat_id=%s", (chat_id,))
            return cur.fetchone() is not None
    return bool(with_conn(database_url, _run))


def list_protected_chats(database_url: str) -> list[int]:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute("SELECT chat_id FROM protected_chats ORDER BY chat_id")
            return [int(r[0]) for r in cur.fetchall()]
    return with_conn(database_url, _run)


def add_global_ban(database_url: str, user_id: int) -> None:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO global_banned(user_id) VALUES (%s) ON CONFLICT DO NOTHING",
                (user_id,),
            )
    with_conn(database_url, _run)


def remove_global_ban(database_url: str, user_id: int) -> None:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM global_banned WHERE user_id=%s", (user_id,))
    with_conn(database_url, _run)


def is_globally_banned(database_url: str, user_id: int) -> bool:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM global_banned WHERE user_id=%s", (user_id,))
            return cur.fetchone() is not None
    return bool(with_conn(database_url, _run))


def mark_seen(database_url: str, chat_id: int, user_id: int) -> None:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO seen_users(chat_id, user_id, last_seen)
                VALUES (%s, %s, NOW())
                ON CONFLICT (chat_id, user_id)
                DO UPDATE SET last_seen = NOW()
                """,
                (chat_id, user_id),
            )
    with_conn(database_url, _run)


def get_seen_users(database_url: str, chat_id: int, limit: int = 5000) -> list[int]:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id FROM seen_users WHERE chat_id=%s ORDER BY last_seen DESC LIMIT %s",
                (chat_id, limit),
            )
            return [int(r[0]) for r in cur.fetchall()]
    return with_conn(database_url, _run)


def log_join_event(
    database_url: str,
    chat_id: int,
    chat_title: str | None,
    user_id: int,
    username: str | None,
    first_name: str | None,
    last_name: str | None,
    action_taken: str | None,
) -> None:
    def _run(conn):
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO join_logs(chat_id, chat_title, user_id, username, first_name, last_name, action_taken)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (chat_id, chat_title, user_id, username, first_name, last_name, action_taken),
            )
    with_conn(database_url, _run)
