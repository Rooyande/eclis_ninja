from __future__ import annotations

import math
from typing import Iterable, List, Tuple, Optional

from telegram import InlineKeyboardButton, InlineKeyboardMarkup


PAGE_SIZE = 50


def _nav_row(prefix: str, page: int, total_pages: int) -> list[InlineKeyboardButton]:
    buttons = []
    if page > 0:
        buttons.append(InlineKeyboardButton("⬅️ قبلی", callback_data=f"{prefix}:{page-1}"))
    if page < total_pages - 1:
        buttons.append(InlineKeyboardButton("بعدی ➡️", callback_data=f"{prefix}:{page+1}"))
    return buttons


def build_members_page(members: List[Tuple[int, Optional[str]]], page: int):
    """
    members: list of (user_id, last_known_username)
    """
    total = len(members)
    if total == 0:
        text = "لیست اعضا خالی است."
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("بازگشت به پنل", callback_data="sa:panel")]])
        return text, kb

    total_pages = max(1, math.ceil(total / PAGE_SIZE))
    page = max(0, min(page, total_pages - 1))

    start = page * PAGE_SIZE
    end = min(total, start + PAGE_SIZE)
    chunk = members[start:end]

    lines = [f"اعضای مجاز (صفحه {page+1}/{total_pages})", ""]
    rows = []
    for i, (uid, uname) in enumerate(chunk, start=start + 1):
        label = f"{i}. {uname if uname else uid}"
        rows.append([InlineKeyboardButton(label, callback_data=f"sa:member:{uid}:{page}")])
        # متن هم داشته باشیم (برای اسکرول/کپی)
        lines.append(f"{i}. {('@'+uname) if uname else ''}  {uid}".strip())

    nav = _nav_row("sa:list_members", page, total_pages)
    if nav:
        rows.append(nav)

    rows.append([InlineKeyboardButton("بازگشت به پنل", callback_data="sa:panel")])
    text = "\n".join(lines)
    return text, InlineKeyboardMarkup(rows)


def build_chats_page(chats: List[int], page: int):
    total = len(chats)
    if total == 0:
        text = "لیست گروه‌ها خالی است."
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("بازگشت به پنل", callback_data="sa:panel")]])
        return text, kb

    total_pages = max(1, math.ceil(total / PAGE_SIZE))
    page = max(0, min(page, total_pages - 1))

    start = page * PAGE_SIZE
    end = min(total, start + PAGE_SIZE)
    chunk = chats[start:end]

    lines = [f"گروه‌های محافظت‌شده (صفحه {page+1}/{total_pages})", ""]
    rows = []
    for i, chat_id in enumerate(chunk, start=start + 1):
        label = f"{i}. {chat_id}"
        rows.append([InlineKeyboardButton(label, callback_data=f"sa:chat:{chat_id}:{page}")])
        lines.append(label)

    nav = _nav_row("sa:list_chats", page, total_pages)
    if nav:
        rows.append(nav)

    rows.append([InlineKeyboardButton("بازگشت به پنل", callback_data="sa:panel")])
    text = "\n".join(lines)
    return text, InlineKeyboardMarkup(rows)
