from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional, List, Tuple, Dict

from telegram import Update
from telegram.constants import ChatType
from telegram.ext import (
    Application,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from config import Config
from defender.db.pool import with_conn

from defender.db.repo.core import (
    add_global_ban,
    remove_global_ban,
    is_globally_banned,
    is_allowed_member,
    upsert_allowed_member,
    log_join_event,
)

from defender.db.repo.management import (
    init_management_schema,
    set_management_group,
    get_management_group_owner,
    add_subgroup,
    list_subgroups,
    set_add_member_mode,
    get_add_member_mode,
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("defender.bot")


# ---------------- misc ----------------
RAID_WINDOW_SECONDS = 30
RAID_THRESHOLD_JOINS = 10
join_events: dict[int, list[float]] = {}
raid_notified_chats: set[int] = set()

# rate-limit notifications per (chat,user)
BAN_NOTIFY_COOLDOWN = 30 * 60
_last_notified: dict[tuple[int, int], float] = {}


# ---------------- roles & context ----------------
def normalize_fa(s: str) -> str:
    if not s:
        return ""
    return (
        s.replace("ي", "ی")
        .replace("ك", "ک")
        .replace("\u200c", " ")
        .strip()
    )


def pv_only(update: Update) -> bool:
    return update.effective_chat is not None and update.effective_chat.type == ChatType.PRIVATE


def is_master(cfg: Config, user_id: int) -> bool:
    # "ارباب‌ها" = ADMINS
    return user_id in cfg.admin_ids


def get_hq_chat_id() -> Optional[int]:
    raw = (os.getenv("ECLIS_HQ_CHAT_ID", "") or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except Exception:
        return None


def mention_masters(cfg: Config) -> str:
    # mention by id is not real mention; but acceptable as "id:123"
    # you can later store usernames. for now, keep readable.
    return " ".join([f"[{uid}]" for uid in sorted(cfg.admin_ids)])


# ---------------- DB helpers (direct SQL to avoid editing other modules) ----------------
def init_extra_schema(database_url: str) -> None:
    """Extra tables for UX/permissions without changing other modules."""
    def _run(conn):
        cur = conn.cursor()
        # store per-MG admins with simple permission flags (extend later)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS mg_admins (
            mg_chat_id BIGINT NOT NULL,
            user_id BIGINT NOT NULL,
            can_add_member BOOLEAN NOT NULL DEFAULT TRUE,
            can_remove_member BOOLEAN NOT NULL DEFAULT TRUE,
            can_view_subs BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ DEFAULT now(),
            PRIMARY KEY (mg_chat_id, user_id)
        );
        """)
        conn.commit()
    with_conn(database_url, _run)


def db_ready(cfg: Config) -> bool:
    return bool(cfg.database_url and not cfg.database_url.strip().startswith("<"))


def is_mg_chat(database_url: str, chat_id: int) -> bool:
    def _run(conn):
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM management_groups WHERE mg_chat_id=%s", (chat_id,))
        return cur.fetchone() is not None
    return bool(with_conn(database_url, _run))


def list_management_groups(database_url: str) -> list[tuple[int, int]]:
    """Returns: [(mg_chat_id, owner_user_id), ...]"""
    def _run(conn):
        cur = conn.cursor()
        cur.execute("SELECT mg_chat_id, owner_user_id FROM management_groups ORDER BY created_at DESC")
        return [(int(r[0]), int(r[1])) for r in cur.fetchall()]
    return with_conn(database_url, _run)


def is_subgroup_chat(database_url: str, chat_id: int) -> bool:
    def _run(conn):
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM mg_subgroups WHERE subgroup_chat_id=%s", (chat_id,))
        return cur.fetchone() is not None
    return bool(with_conn(database_url, _run))


def find_mg_for_subgroup(database_url: str, subgroup_chat_id: int) -> Optional[int]:
    def _run(conn):
        cur = conn.cursor()
        cur.execute("SELECT mg_chat_id FROM mg_subgroups WHERE subgroup_chat_id=%s LIMIT 1", (subgroup_chat_id,))
        row = cur.fetchone()
        return int(row[0]) if row else None
    return with_conn(database_url, _run)


def can_mg_admin(database_url: str, mg_chat_id: int, user_id: int, perm: str) -> bool:
    # owner always yes
    owner = get_management_group_owner(database_url, mg_chat_id)
    if owner == user_id:
        return True

    col = {
        "add_member": "can_add_member",
        "remove_member": "can_remove_member",
        "view_subs": "can_view_subs",
    }.get(perm)
    if not col:
        return False

    def _run(conn):
        cur = conn.cursor()
        cur.execute(f"SELECT {col} FROM mg_admins WHERE mg_chat_id=%s AND user_id=%s", (mg_chat_id, user_id))
        row = cur.fetchone()
        return bool(row[0]) if row else False
    return bool(with_conn(database_url, _run))


# ---------------- UX: clean help by role ----------------
def help_master() -> str:
    return (
        "راهنما (ارباب)\n\n"
        "ثبت و مدیریت گروه‌های مدیریتی:\n"
        "• ثبت گروه مدیریتی  (داخل همان گروه)\n"
        "• /mg_register  (داخل همان گروه)\n"
        "• /mg_set_owner <mg_chat_id> <owner_user_id>\n"
        "• لیست گروه‌های مدیریتی  |  /mg_list\n"
        "• نمایش زیرمجموعه <شماره>  |  /mg_subs <index>\n\n"
        "زیرگروه‌ها (با تایید HQ):\n"
        "• افزودن زیرگروه <شماره MG> <chat_id>  |  /sub_add <mg_index> <sub_chat_id>\n"
        "• حذف زیرگروه <شماره MG> <chat_id>  |  /sub_remove <mg_index> <sub_chat_id>\n\n"
        "امن‌سازی و کنترل:\n"
        "• ایمن سازی گروه  |  /safe_scan   (داخل زیرگروه)\n"
        "• /ban <user_id>\n"
        "• /unban <user_id>\n"
    )


def help_mg_owner() -> str:
    return (
        "راهنما (Owner گروه مدیریتی)\n\n"
        "• زیرگروه‌های من  |  /my_subs\n"
        "• ایمن سازی گروه  |  /safe_scan   (داخل زیرگروه)\n\n"
        "نکته: افزودن/حذف زیرگروه باید درخواست شود تا ارباب‌ها تایید کنند."
    )


def help_unknown() -> str:
    return "شما دسترسی لازم را ندارید."


# ---------------- join tracking ----------------
def register_join(chat_id: int) -> int:
    now = time.time()
    q = join_events.setdefault(chat_id, [])
    q.append(now)
    cutoff = now - RAID_WINDOW_SECONDS
    while q and q[0] < cutoff:
        q.pop(0)
    return len(q)


# ---------------- init ----------------
async def init_db(cfg: Config) -> None:
    if not db_ready(cfg):
        log.warning("DATABASE_URL missing/invalid. DB features disabled.")
        return

    await asyncio.to_thread(init_management_schema, cfg.database_url)
    await asyncio.to_thread(init_extra_schema, cfg.database_url)

    # core schema:
    from defender.db.repo.core import init_schema
    await asyncio.to_thread(init_schema, cfg.database_url)

    log.info("Database init ok.")


# ---------------- reporting ----------------
async def send_hq(cfg: Config, context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    hq = get_hq_chat_id()
    if not hq:
        return
    try:
        await context.bot.send_message(hq, text)
    except Exception:
        pass


async def send_to_mg(cfg: Config, context: ContextTypes.DEFAULT_TYPE, mg_chat_id: int, text: str) -> None:
    try:
        await context.bot.send_message(mg_chat_id, text)
    except Exception:
        pass


# ---------------- protection logic ----------------
async def is_chat_protected(cfg: Config, chat_id: int) -> bool:
    # Protected = any subgroup registered in mg_subgroups
    if not db_ready(cfg):
        return False
    return await asyncio.to_thread(is_subgroup_chat, cfg.database_url, chat_id)


async def enforce_user(cfg: Config, context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int, reason: str):
    """If user is globally banned -> ban.
       Else if not allowed -> ban (strict mode for now)."""
    if not db_ready(cfg):
        return
    if user_id == context.bot.id:
        return

    try:
        # already banned?
        try:
            m = await context.bot.get_chat_member(chat_id, user_id)
            if m.status == "kicked":
                return
        except Exception:
            pass

        if await asyncio.to_thread(is_globally_banned, cfg.database_url, user_id):
            await context.bot.ban_chat_member(chat_id, user_id)
            mg = await asyncio.to_thread(find_mg_for_subgroup, cfg.database_url, chat_id)
            if mg:
                await send_to_mg(cfg, context, mg, f"⛔️ BAN(global)\nuser: {user_id}\nchat: {chat_id}\nreason: {reason}")
            await send_hq(cfg, context, f"⛔️ BAN(global)\nuser: {user_id}\nchat: {chat_id}\nreason: {reason}")
            return

        if not await asyncio.to_thread(is_allowed_member, cfg.database_url, user_id):
            await context.bot.ban_chat_member(chat_id, user_id)

            mg = await asyncio.to_thread(find_mg_for_subgroup, cfg.database_url, chat_id)
            if mg:
                await send_to_mg(cfg, context, mg, f"⛔️ BAN(not-allowed)\nuser: {user_id}\nchat: {chat_id}\nreason: {reason}")
            await send_hq(cfg, context, f"⛔️ BAN(not-allowed)\nuser: {user_id}\nchat: {chat_id}\nreason: {reason}")

            await asyncio.to_thread(log_join_event, cfg.database_url, chat_id, None, user_id, None, None, None, "banned")

    except Exception as e:
        log.warning("enforce failed chat=%s user=%s err=%s", chat_id, user_id, e)


# ---------------- command parsing (Persian text without slash) ----------------
def parse_farsi(text: str) -> tuple[str, list[str]] | None:
    t = normalize_fa(text)

    # Master / PV and group
    if t in ("راهنما", "کمک", "help"):
        return ("help", [])

    if t == "ثبت گروه مدیریتی":
        return ("mg_register_here", [])

    if t == "لیست گروه‌های مدیریتی":
        return ("mg_list", [])

    if t.startswith("نمایش زیرمجموعه "):
        return ("mg_subs", t.replace("نمایش زیرمجموعه", "").strip().split())

    if t.startswith("افزودن زیرگروه "):
        return ("sub_add", t.replace("افزودن زیرگروه", "").strip().split())

    if t.startswith("حذف زیرگروه "):
        return ("sub_remove", t.replace("حذف زیرگروه", "").strip().split())

    if t.startswith("بن "):
        return ("ban", t.replace("بن", "").strip().split())

    if t.startswith("آنبن "):
        return ("unban", t.replace("آنبن", "").strip().split())

    # MG owner
    if t in ("زیرگروه‌های من", "زیرگروه های من"):
        return ("my_subs", [])

    # subgroup
    if t in ("ایمن سازی گروه", "ایمن‌سازی گروه"):
        return ("safe_scan", [])

    return None


# ---------------- guards ----------------
def user_id(update: Update) -> Optional[int]:
    if not update.effective_user:
        return None
    return update.effective_user.id


async def guard_master(cfg: Config, update: Update) -> bool:
    uid = user_id(update)
    if uid is None:
        return False
    return is_master(cfg, uid)


async def guard_mg_owner_or_admin(cfg: Config, update: Update, perm: str) -> bool:
    if not db_ready(cfg):
        return False

    uid = user_id(update)
    chat = update.effective_chat
    if uid is None or chat is None:
        return False

    # masters always yes
    if is_master(cfg, uid):
        return True

    # inside MG: check permission
    if chat.type in (ChatType.GROUP, ChatType.SUPERGROUP) and await asyncio.to_thread(is_mg_chat, cfg.database_url, chat.id):
        return await asyncio.to_thread(can_mg_admin, cfg.database_url, chat.id, uid, perm)

    # PV: if user is owner/admin of some mg, allow only "view_subs" in PV
    # keep simple for now: only /my_subs allowed in PV for owner/admin
    return False


# ---------------- commands: help ----------------
async def cmd_help(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = user_id(update)
    if uid is None or update.effective_message is None:
        return

    if is_master(cfg, uid):
        await update.effective_message.reply_text(help_master())
        return

    # MG owner/admin help in PV:
    if db_ready(cfg):
        # Find if user is owner of any MG
        def _is_owner_any(conn):
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM management_groups WHERE owner_user_id=%s LIMIT 1", (uid,))
            return cur.fetchone() is not None
        try:
            is_owner = bool(with_conn(cfg.database_url, _is_owner_any))
        except Exception:
            is_owner = False
        if is_owner:
            await update.effective_message.reply_text(help_mg_owner())
            return

    await update.effective_message.reply_text(help_unknown())


# ---------------- commands: mg register here (owner is NOT the registrar) ----------------
async def cmd_mg_register_here(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # must be in group/supergroup; only master
    if not await guard_master(cfg, update):
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return

    chat = update.effective_chat
    if not chat or chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        await update.effective_message.reply_text("این دستور فقط داخل یک گروه قابل اجراست.")
        return

    # ask for owner id
    context.chat_data["pending_mg_register"] = {"mg_chat_id": chat.id}
    await update.effective_message.reply_text(
        "ثبت گروه مدیریتی\n\n"
        "لطفاً آیدی عددی Owner این MG را ارسال کن.\n"
        "مثال: 123456789\n\n"
        "لغو: /cancel"
    )


async def cmd_mg_set_owner(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # /mg_set_owner <mg_chat_id> <owner_user_id>
    if not await guard_master(cfg, update):
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return
    if not context.args or len(context.args) != 2:
        await update.effective_message.reply_text("Usage: /mg_set_owner <mg_chat_id> <owner_user_id>")
        return

    mg_raw, owner_raw = context.args[0], context.args[1]
    if not mg_raw.lstrip("-").isdigit() or not owner_raw.isdigit():
        await update.effective_message.reply_text("فرمت عددی اشتباه است.")
        return

    mg_id = int(mg_raw)
    owner_id = int(owner_raw)
    await asyncio.to_thread(set_management_group, cfg.database_url, mg_id, owner_id)

    await update.effective_message.reply_text(f"✅ Owner ست شد.\nMG: {mg_id}\nOwner: {owner_id}")
    await send_hq(cfg, context, f"MG owner set\nmg: {mg_id}\nowner: {owner_id}\nby: {update.effective_user.id}")


async def cmd_cancel(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.chat_data.pop("pending_mg_register", None)
    context.chat_data.pop("pending_sub_request", None)
    await update.effective_message.reply_text("لغو شد.")


# ---------------- mg list / subs with titles ----------------
@dataclass
class MgRow:
    mg_chat_id: int
    owner_user_id: int
    title: str


async def resolve_chat_title(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> str:
    try:
        ch = await context.bot.get_chat(chat_id)
        if getattr(ch, "title", None):
            return str(ch.title)
        return str(chat_id)
    except Exception:
        return str(chat_id)


async def cmd_mg_list(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = user_id(update)
    if uid is None or update.effective_message is None:
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return

    if not is_master(cfg, uid):
        await update.effective_message.reply_text("دسترسی ندارید.")
        return

    rows = await asyncio.to_thread(list_management_groups, cfg.database_url)
    if not rows:
        await update.effective_message.reply_text("هیچ گروه مدیریتی ثبت نشده.")
        return

    # pretty list with index + title + id + owner
    mg_rows: list[MgRow] = []
    for mg_id, owner_id in rows:
        title = await resolve_chat_title(context, mg_id)
        mg_rows.append(MgRow(mg_id, owner_id, title))

    context.user_data["mg_list_cache"] = [(r.mg_chat_id, r.owner_user_id) for r in mg_rows]

    lines = []
    for i, r in enumerate(mg_rows, start=1):
        lines.append(f"{i}) {r.title}\n   MG_ID: {r.mg_chat_id}\n   Owner: {r.owner_user_id}")
    await update.effective_message.reply_text("لیست گروه‌های مدیریتی:\n\n" + "\n\n".join(lines) + "\n\nنمایش زیرمجموعه: نمایش زیرمجموعه 1")


async def cmd_mg_subs(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = user_id(update)
    if uid is None or update.effective_message is None:
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return
    if not is_master(cfg, uid):
        await update.effective_message.reply_text("دسترسی ندارید.")
        return
    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        await update.effective_message.reply_text("Usage: /mg_subs <index>\nمثال: نمایش زیرمجموعه 1")
        return

    idx = int(context.args[0])
    cache = context.user_data.get("mg_list_cache") or []
    if idx < 1 or idx > len(cache):
        await update.effective_message.reply_text("شماره نامعتبر است. اول «لیست گروه‌های مدیریتی» را بگیر.")
        return

    mg_chat_id = int(cache[idx - 1][0])
    subs = await asyncio.to_thread(list_subgroups, cfg.database_url, mg_chat_id)
    mg_title = await resolve_chat_title(context, mg_chat_id)

    if not subs:
        await update.effective_message.reply_text(f"زیرمجموعه‌ای برای این MG ثبت نشده.\n\n{mg_title}\n{mg_chat_id}")
        return

    lines = []
    for i, sub_id in enumerate(subs, start=1):
        sub_title = await resolve_chat_title(context, sub_id)
        lines.append(f"{i}) {sub_title}\n   SUB_ID: {sub_id}")

    await update.effective_message.reply_text(
        f"زیرمجموعه‌ها:\n\nMG: {mg_title}\nMG_ID: {mg_chat_id}\n\n" + "\n\n".join(lines)
    )


async def cmd_my_subs(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # owner/admin can view in MG or PV
    uid = user_id(update)
    if uid is None or update.effective_message is None:
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return

    # masters: just show their mg list flow
    if is_master(cfg, uid):
        await cmd_mg_list(cfg, update, context)
        return

    # find mg where user is owner
    def _find_owned(conn):
        cur = conn.cursor()
        cur.execute("SELECT mg_chat_id FROM management_groups WHERE owner_user_id=%s ORDER BY created_at DESC", (uid,))
        return [int(r[0]) for r in cur.fetchall()]

    owned = with_conn(cfg.database_url, _find_owned)
    if not owned:
        await update.effective_message.reply_text("شما Owner هیچ گروه مدیریتی نیستید.")
        return

    mg_id = owned[0]
    subs = await asyncio.to_thread(list_subgroups, cfg.database_url, mg_id)
    mg_title = await resolve_chat_title(context, mg_id)

    if not subs:
        await update.effective_message.reply_text(f"زیرمجموعه‌ای ثبت نشده.\nMG: {mg_title}\n{mg_id}")
        return

    lines = []
    for i, sub_id in enumerate(subs, start=1):
        sub_title = await resolve_chat_title(context, sub_id)
        lines.append(f"{i}) {sub_title}\n   SUB_ID: {sub_id}")

    await update.effective_message.reply_text(f"زیرگروه‌های شما:\n\nMG: {mg_title}\nMG_ID: {mg_id}\n\n" + "\n\n".join(lines))


# ---------------- subgroup add/remove -> request HQ for approval ----------------
async def cmd_sub_add(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard_master(cfg, update):
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return
    if not context.args or len(context.args) != 2:
        await update.effective_message.reply_text("Usage: /sub_add <mg_index> <subgroup_chat_id>\nمثال: افزودن زیرگروه 1 -100...")
        return
    if not context.args[0].isdigit() or not context.args[1].lstrip("-").isdigit():
        await update.effective_message.reply_text("فرمت ورودی اشتباه است.")
        return

    idx = int(context.args[0])
    sub_id = int(context.args[1])

    cache = context.user_data.get("mg_list_cache") or []
    if idx < 1 or idx > len(cache):
        await update.effective_message.reply_text("شماره MG نامعتبر است. اول «لیست گروه‌های مدیریتی» را بگیر.")
        return

    mg_id = int(cache[idx - 1][0])
    mg_title = await resolve_chat_title(context, mg_id)
    sub_title = await resolve_chat_title(context, sub_id)

    # store pending request in user_data (simple)
    context.user_data["pending_sub_request"] = {"action": "add", "mg_id": mg_id, "sub_id": sub_id}

    await update.effective_message.reply_text(
        "درخواست ثبت زیرگروه ایجاد شد.\n\n"
        f"MG: {mg_title}\n{mg_id}\n\n"
        f"SUB: {sub_title}\n{sub_id}\n\n"
        "برای ارسال درخواست به HQ و تایید ارباب‌ها:\n"
        "/confirm\n"
        "لغو: /cancel"
    )


async def cmd_sub_remove(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard_master(cfg, update):
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return
    if not context.args or len(context.args) != 2:
        await update.effective_message.reply_text("Usage: /sub_remove <mg_index> <subgroup_chat_id>\nمثال: حذف زیرگروه 1 -100...")
        return
    if not context.args[0].isdigit() or not context.args[1].lstrip("-").isdigit():
        await update.effective_message.reply_text("فرمت ورودی اشتباه است.")
        return

    idx = int(context.args[0])
    sub_id = int(context.args[1])

    cache = context.user_data.get("mg_list_cache") or []
    if idx < 1 or idx > len(cache):
        await update.effective_message.reply_text("شماره MG نامعتبر است. اول «لیست گروه‌های مدیریتی» را بگیر.")
        return

    mg_id = int(cache[idx - 1][0])
    mg_title = await resolve_chat_title(context, mg_id)
    sub_title = await resolve_chat_title(context, sub_id)

    context.user_data["pending_sub_request"] = {"action": "remove", "mg_id": mg_id, "sub_id": sub_id}

    await update.effective_message.reply_text(
        "درخواست حذف زیرگروه ایجاد شد.\n\n"
        f"MG: {mg_title}\n{mg_id}\n\n"
        f"SUB: {sub_title}\n{sub_id}\n\n"
        "برای ارسال درخواست به HQ و تایید ارباب‌ها:\n"
        "/confirm\n"
        "لغو: /cancel"
    )


async def cmd_confirm(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard_master(cfg, update):
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return

    req = context.user_data.get("pending_sub_request")
    if not req:
        await update.effective_message.reply_text("درخواستی برای تایید وجود ندارد.")
        return

    hq = get_hq_chat_id()
    if not hq:
        await update.effective_message.reply_text("ECLIS_HQ_CHAT_ID تنظیم نشده. فعلاً مستقیم اعمال می‌کنم.")

        # fallback: apply directly
        if req["action"] == "add":
            await asyncio.to_thread(add_subgroup, cfg.database_url, req["mg_id"], req["sub_id"])
            await update.effective_message.reply_text("✅ زیرگروه ثبت شد.")
        else:
            # direct remove:
            def _rm(conn):
                cur = conn.cursor()
                cur.execute("DELETE FROM mg_subgroups WHERE mg_chat_id=%s AND subgroup_chat_id=%s", (req["mg_id"], req["sub_id"]))
                conn.commit()
            await asyncio.to_thread(with_conn, cfg.database_url, _rm)
            await update.effective_message.reply_text("✅ زیرگروه حذف شد.")
        context.user_data.pop("pending_sub_request", None)
        return

    # send to HQ for human approval (text-only for now)
    action = req["action"]
    mg_id = int(req["mg_id"])
    sub_id = int(req["sub_id"])

    mg_title = await resolve_chat_title(context, mg_id)
    sub_title = await resolve_chat_title(context, sub_id)

    by = update.effective_user.id if update.effective_user else 0
    text = (
        "درخواست تایید (زیرگروه)\n\n"
        f"Action: {action}\n"
        f"MG: {mg_title}\nMG_ID: {mg_id}\n\n"
        f"SUB: {sub_title}\nSUB_ID: {sub_id}\n\n"
        f"Requested by: {by}\n"
        f"Masters: {mention_masters(cfg)}\n\n"
        "برای اعمال دستی توسط ارباب‌ها:\n"
        f"/hq_apply_{action} {mg_id} {sub_id}"
    )
    await send_hq(cfg, context, text)
    await update.effective_message.reply_text("ارسال شد به HQ برای تایید ارباب‌ها.")
    context.user_data.pop("pending_sub_request", None)


# HQ apply commands (masters only) - run anywhere (PV recommended)
async def cmd_hq_apply_add(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard_master(cfg, update):
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return
    if not context.args or len(context.args) != 2:
        await update.effective_message.reply_text("Usage: /hq_apply_add <mg_id> <sub_id>")
        return
    mg_id = int(context.args[0])
    sub_id = int(context.args[1])
    await asyncio.to_thread(add_subgroup, cfg.database_url, mg_id, sub_id)
    await update.effective_message.reply_text("✅ انجام شد: زیرگروه اضافه شد.")


async def cmd_hq_apply_remove(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard_master(cfg, update):
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return
    if not context.args or len(context.args) != 2:
        await update.effective_message.reply_text("Usage: /hq_apply_remove <mg_id> <sub_id>")
        return
    mg_id = int(context.args[0])
    sub_id = int(context.args[1])

    def _rm(conn):
        cur = conn.cursor()
        cur.execute("DELETE FROM mg_subgroups WHERE mg_chat_id=%s AND subgroup_chat_id=%s", (mg_id, sub_id))
        conn.commit()

    await asyncio.to_thread(with_conn, cfg.database_url, _rm)
    await update.effective_message.reply_text("✅ انجام شد: زیرگروه حذف شد.")


# ---------------- global ban/unban (masters) ----------------
async def cmd_ban(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard_master(cfg, update):
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return
    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        await update.effective_message.reply_text("Usage: /ban <user_id>")
        return
    target = int(context.args[0])

    await asyncio.to_thread(add_global_ban, cfg.database_url, target)

    # ban from all subgroups
    def _all_subs(conn):
        cur = conn.cursor()
        cur.execute("SELECT subgroup_chat_id FROM mg_subgroups")
        return [int(r[0]) for r in cur.fetchall()]

    subs = with_conn(cfg.database_url, _all_subs)
    ok, fail = 0, 0
    for chat_id in subs:
        try:
            await context.bot.ban_chat_member(chat_id, target)
            ok += 1
        except Exception:
            fail += 1

    await update.effective_message.reply_text(f"⛔️ بن سراسری ثبت شد.\nOK: {ok}\nFAIL: {fail}")
    await send_hq(cfg, context, f"GLOBAL BAN\nuser: {target}\nby: {update.effective_user.id}\nOK:{ok} FAIL:{fail}")


async def cmd_unban(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await guard_master(cfg, update):
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return
    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        await update.effective_message.reply_text("Usage: /unban <user_id>")
        return
    target = int(context.args[0])

    await asyncio.to_thread(remove_global_ban, cfg.database_url, target)
    # allow again so it doesn't re-ban
    await asyncio.to_thread(upsert_allowed_member, cfg.database_url, target, None, None, None)

    def _all_subs(conn):
        cur = conn.cursor()
        cur.execute("SELECT subgroup_chat_id FROM mg_subgroups")
        return [int(r[0]) for r in cur.fetchall()]

    subs = with_conn(cfg.database_url, _all_subs)
    ok, fail = 0, 0
    for chat_id in subs:
        try:
            await context.bot.unban_chat_member(chat_id, target, only_if_banned=False)
            ok += 1
        except Exception:
            fail += 1

    await update.effective_message.reply_text(f"✅ آنبن سراسری انجام شد.\nOK: {ok}\nFAIL: {fail}")
    await send_hq(cfg, context, f"GLOBAL UNBAN\nuser: {target}\nby: {update.effective_user.id}\nOK:{ok} FAIL:{fail}")


# ---------------- safe scan (50-50) ----------------
async def cmd_safe_scan(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Inside subgroup: add existing members to allowed_members in batches.
       Telegram API cannot list all members in large groups without admin privileges; this is limited.
       We implement a safe minimal version: it explains limitation and can register known users via recent messages.
       (Full member enumeration requires admin rights + external export or bot tracking join events.)"""
    chat = update.effective_chat
    uid = user_id(update)
    if not chat or uid is None or update.effective_message is None:
        return
    if not db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return
    if chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        await update.effective_message.reply_text("این دستور فقط داخل گروه/سوپرگروه اجرا می‌شود.")
        return

    # master always allowed; otherwise only MG owner/admin (view_subs is enough for now)
    mg_id = await asyncio.to_thread(find_mg_for_subgroup, cfg.database_url, chat.id)
    if not mg_id:
        await update.effective_message.reply_text("این گروه به عنوان زیرگروه ثبت نشده.")
        return
    if not (is_master(cfg, uid) or await asyncio.to_thread(can_mg_admin, cfg.database_url, mg_id, uid, "add_member")):
        await update.effective_message.reply_text("دسترسی ندارید.")
        return

    await update.effective_message.reply_text(
        "ایمن‌سازی گروه (نسخه فعلی)\n\n"
        "تلگرام API لیست کامل اعضای گروه‌های بزرگ را مستقیم به بات نمی‌دهد.\n"
        "برای ایمن‌سازی واقعی باید بات از لحظه عضویت/پیام‌ها کاربران را ثبت کند.\n\n"
        "از این به بعد هر عضو جدید که وارد شود، اگر در allowed_members نباشد بن می‌شود.\n"
        "اگر می‌خواهی یک کاربر را ایمن کنی:\n"
        "• افزودن عضو <user_id>\n"
        "یا\n"
        "• /add_member <user_id>\n"
    )


# ---------------- message router for Persian text commands ----------------
async def on_farsi_text(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.effective_message or not update.effective_message.text:
        return

    parsed = parse_farsi(update.effective_message.text)
    if not parsed:
        # handle pending mg register owner input
        if "pending_mg_register" in context.chat_data:
            await handle_pending_mg_owner(cfg, update, context)
        return

    cmd, args = parsed
    # emulate args
    old = getattr(context, "args", None)
    context.args = args
    try:
        if cmd == "help":
            await cmd_help(cfg, update, context)
        elif cmd == "mg_register_here":
            await cmd_mg_register_here(cfg, update, context)
        elif cmd == "mg_list":
            await cmd_mg_list(cfg, update, context)
        elif cmd == "mg_subs":
            await cmd_mg_subs(cfg, update, context)
        elif cmd == "sub_add":
            await cmd_sub_add(cfg, update, context)
        elif cmd == "sub_remove":
            await cmd_sub_remove(cfg, update, context)
        elif cmd == "ban":
            await cmd_ban(cfg, update, context)
        elif cmd == "unban":
            await cmd_unban(cfg, update, context)
        elif cmd == "my_subs":
            await cmd_my_subs(cfg, update, context)
        elif cmd == "safe_scan":
            await cmd_safe_scan(cfg, update, context)
    finally:
        context.args = old


async def handle_pending_mg_owner(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    """After 'ثبت گروه مدیریتی' the next text should be owner id."""
    if not await guard_master(cfg, update):
        context.chat_data.pop("pending_mg_register", None)
        return
    if not db_ready(cfg):
        context.chat_data.pop("pending_mg_register", None)
        return

    msg = update.effective_message
    if not msg or not msg.text:
        return
    t = msg.text.strip()
    if not t.isdigit():
        await msg.reply_text("لطفاً فقط آیدی عددی Owner را بفرست. مثال: 123456\nلغو: /cancel")
        return

    owner_id = int(t)
    mg_chat_id = int(context.chat_data["pending_mg_register"]["mg_chat_id"])

    await asyncio.to_thread(set_management_group, cfg.database_url, mg_chat_id, owner_id)
    context.chat_data.pop("pending_mg_register", None)

    await msg.reply_text(f"✅ گروه مدیریتی ثبت شد.\nMG_ID: {mg_chat_id}\nOwner: {owner_id}")
    await send_hq(cfg, context, f"MG REGISTERED\nmg: {mg_chat_id}\nowner: {owner_id}\nby: {update.effective_user.id}")


# ---------------- event handlers ----------------
async def on_new_members_message(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    msg = update.effective_message
    if not chat or not msg:
        return
    if chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    if not await is_chat_protected(cfg, chat.id):
        return
    if not msg.new_chat_members:
        return

    cnt = register_join(chat.id)
    if cnt >= RAID_THRESHOLD_JOINS and chat.id not in raid_notified_chats:
        raid_notified_chats.add(chat.id)
        mg = await asyncio.to_thread(find_mg_for_subgroup, cfg.database_url, chat.id)
        if mg:
            await send_to_mg(cfg, context, mg, f"⚠️ احتمال raid: {cnt} join در {RAID_WINDOW_SECONDS}s\nchat: {chat.id}")
        await send_hq(cfg, context, f"⚠️ RAID?\nchat: {chat.id}\ncount: {cnt}")

    for u in msg.new_chat_members:
        await enforce_user(cfg, context, chat.id, u.id, reason="new_chat_members")


async def on_chat_member(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if not chat or chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    if not await is_chat_protected(cfg, chat.id):
        return

    cmu = update.chat_member
    if not cmu:
        return

    old = cmu.old_chat_member
    new = cmu.new_chat_member
    if not (old.status in ("left", "kicked") and new.status in ("member", "restricted")):
        return

    cnt = register_join(chat.id)
    if cnt >= RAID_THRESHOLD_JOINS and chat.id not in raid_notified_chats:
        raid_notified_chats.add(chat.id)
        mg = await asyncio.to_thread(find_mg_for_subgroup, cfg.database_url, chat.id)
        if mg:
            await send_to_mg(cfg, context, mg, f"⚠️ احتمال raid: {cnt} join در {RAID_WINDOW_SECONDS}s\nchat: {chat.id}")
        await send_hq(cfg, context, f"⚠️ RAID?\nchat: {chat.id}\ncount: {cnt}")

    await enforce_user(cfg, context, chat.id, new.user.id, reason="chat_member")


# ---------------- error handler ----------------
async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.exception("Unhandled error: %s", context.error)


# ---------------- app build ----------------
def build_application(cfg: Config) -> Application:
    app = Application.builder().token(cfg.bot_token).build()

    # Persian text router (no slash)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: on_farsi_text(cfg, u, c)), group=0)

    # command handlers (English)
    app.add_handler(CommandHandler("help", lambda u, c: cmd_help(cfg, u, c)))
    app.add_handler(CommandHandler("cancel", lambda u, c: cmd_cancel(cfg, u, c)))

    app.add_handler(CommandHandler("mg_register", lambda u, c: cmd_mg_register_here(cfg, u, c)))
    app.add_handler(CommandHandler("mg_set_owner", lambda u, c: cmd_mg_set_owner(cfg, u, c)))
    app.add_handler(CommandHandler("mg_list", lambda u, c: cmd_mg_list(cfg, u, c)))
    app.add_handler(CommandHandler("mg_subs", lambda u, c: cmd_mg_subs(cfg, u, c)))
    app.add_handler(CommandHandler("my_subs", lambda u, c: cmd_my_subs(cfg, u, c)))

    app.add_handler(CommandHandler("sub_add", lambda u, c: cmd_sub_add(cfg, u, c)))
    app.add_handler(CommandHandler("sub_remove", lambda u, c: cmd_sub_remove(cfg, u, c)))
    app.add_handler(CommandHandler("confirm", lambda u, c: cmd_confirm(cfg, u, c)))

    # HQ apply commands (masters)
    app.add_handler(CommandHandler("hq_apply_add", lambda u, c: cmd_hq_apply_add(cfg, u, c)))
    app.add_handler(CommandHandler("hq_apply_remove", lambda u, c: cmd_hq_apply_remove(cfg, u, c)))

    app.add_handler(CommandHandler("ban", lambda u, c: cmd_ban(cfg, u, c)))
    app.add_handler(CommandHandler("unban", lambda u, c: cmd_unban(cfg, u, c)))

    app.add_handler(CommandHandler("safe_scan", lambda u, c: cmd_safe_scan(cfg, u, c)))

    # join detection
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, lambda u, c: on_new_members_message(cfg, u, c)))
    app.add_handler(ChatMemberHandler(lambda u, c: on_chat_member(cfg, u, c), ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(ChatMemberHandler(lambda u, c: on_chat_member(cfg, u, c), ChatMemberHandler.MY_CHAT_MEMBER))

    app.add_error_handler(on_error)

    async def _post_init(application: Application):
        await init_db(cfg)

        if cfg.run_mode == "server":
            webhook_url = f"{cfg.public_base_url}{cfg.webhook_path}"
            await application.bot.set_webhook(url=webhook_url, drop_pending_updates=True)
            log.info("Webhook set: %s", webhook_url)

    app.post_init = _post_init
    return app


def run_local_polling(app: Application) -> None:
    log.info("Starting in LOCAL mode (polling)")
    app.run_polling(drop_pending_updates=True)


# ---------------- minimal webhook server ----------------
class WebhookHandler(BaseHTTPRequestHandler):
    loop: asyncio.AbstractEventLoop | None = None
    application: Application | None = None
    webhook_path: str = "/"

    def _send(self, code=200, body=b"OK"):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        if self.path == "/":
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/":
            return self._send(200, b"OK")
        return self._send(404, b"Not Found")

    def do_POST(self):
        if self.path != self.webhook_path:
            return self._send(404, b"Not Found")

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)

        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return self._send(400, b"Bad JSON")

        if not self.loop or not self.application:
            return self._send(503, b"App not ready")

        try:
            update = Update.de_json(data, self.application.bot)
        except Exception:
            return self._send(400, b"Bad Update")

        asyncio.run_coroutine_threadsafe(self.application.process_update(update), self.loop)
        return self._send(200, b"OK")


def run_server_webhook(app: Application, cfg: Config) -> None:
    log.info("Starting in SERVER mode (webhook)")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _startup():
        await app.initialize()
        await app.start()
        log.info("Application started")

    loop.run_until_complete(_startup())

    WebhookHandler.loop = loop
    WebhookHandler.application = app
    WebhookHandler.webhook_path = cfg.webhook_path

    server = HTTPServer(("0.0.0.0", cfg.port), WebhookHandler)
    log.info("Listening on 0.0.0.0:%s (health: / , webhook: %s)", cfg.port, cfg.webhook_path)

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        loop.run_forever()
    finally:
        try:
            server.shutdown()
        except Exception:
            pass
        try:
            loop.run_until_complete(app.stop())
            loop.run_until_complete(app.shutdown())
        except Exception:
            pass
        loop.close()
