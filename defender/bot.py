from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

from telegram import Update
from telegram.ext import (
    Application,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from telegram.request import HTTPXRequest

from config import Config

from defender.db.pool import with_conn
from defender.db.repo.core import (
    add_global_ban,
    add_protected_chat,
    get_seen_users,
    init_schema,
    is_allowed_member,
    is_globally_banned,
    is_protected_chat,
    log_join_event,
    mark_seen,
    remove_allowed_member,
    remove_global_ban,
    remove_protected_chat,
    upsert_allowed_member,
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

# -----------------------------
# Bot settings (Root MG storage)
# -----------------------------
BOT_SETTINGS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS bot_settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
"""

def _db_ready(cfg: Config) -> bool:
    return bool(cfg.database_url and cfg.database_url.strip() and not cfg.database_url.strip().startswith("<"))


def db_set_setting(database_url: str, key: str, value: str) -> None:
    def _run(conn):
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO bot_settings(key, value) VALUES (%s, %s) "
            "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            (key, value),
        )
    with_conn(database_url, _run)


def db_get_setting(database_url: str, key: str) -> Optional[str]:
    def _run(conn):
        cur = conn.cursor()
        cur.execute("SELECT value FROM bot_settings WHERE key=%s", (key,))
        row = cur.fetchone()
        return str(row[0]) if row else None
    return with_conn(database_url, _run)


def db_list_management_groups(database_url: str) -> list[tuple[int, int]]:
    # returns [(mg_chat_id, owner_user_id), ...]
    def _run(conn):
        cur = conn.cursor()
        cur.execute("SELECT mg_chat_id, owner_user_id FROM management_groups ORDER BY created_at DESC")
        return [(int(r[0]), int(r[1])) for r in cur.fetchall()]
    return with_conn(database_url, _run)


# ---------------- guards ----------------
def is_superadmin(cfg: Config, user_id: int) -> bool:
    return user_id in cfg.admin_ids


def pv_only(update: Update) -> bool:
    return update.effective_chat is not None and update.effective_chat.type == "private"


async def superadmin_guard(cfg: Config, update: Update) -> bool:
    u = update.effective_user
    if not u:
        return False
    return is_superadmin(cfg, u.id)


async def mg_owner_guard(cfg: Config, update: Update) -> bool:
    # must be in group/supergroup and be the mg owner of that chat
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return False
    if chat.type not in ("group", "supergroup"):
        return False
    if not _db_ready(cfg):
        return False
    owner = await asyncio.to_thread(get_management_group_owner, cfg.database_url, chat.id)
    return owner == user.id


# ---------------- Persian text parsing (no slash) ----------------
def normalize_fa(s: str) -> str:
    return (
        (s or "")
        .replace("ي", "ی")
        .replace("ك", "ک")
        .replace("\u200c", " ")
        .strip()
    )


def parse_fa_command(text: str) -> tuple[str, list[str]] | None:
    """
    فارسی بدون اسلش (PV و گروه):
      راهنما
      ثبت گروه مدیریتی
      حذف گروه مدیریتی
      ثبت گروه مدیریتی اکلیس
      گروه‌های مدیریتی
      نمایش زیرمجموعه <شماره|mg_chat_id>
      زیرمجموعه‌ها
      افزودن زیرگروه <id>
      تایید زیرگروه
      لغو
      بن <user_id|@username>
      آنبن <user_id>
    """
    t = normalize_fa(text)

    # exact
    exact = {
        "راهنما": ("help", []),
        "زیرمجموعه‌ها": ("subgroups_self", []),
        "گروه‌های مدیریتی": ("mg_list", []),
        "تایید زیرگروه": ("confirm_add_group", []),
        "لغو": ("cancel", []),
        "ثبت گروه مدیریتی": ("register_mg", []),
        "حذف گروه مدیریتی": ("remove_mg", []),
        "ثبت گروه مدیریتی اکلیس": ("register_root_mg", []),
    }
    if t in exact:
        return exact[t]

    # prefix commands with args
    prefixes = {
        "نمایش زیرمجموعه": "mg_subgroups",
        "افزودن زیرگروه": "add_group",
        "بن": "ban",
        "آنبن": "unban",
    }
    for p, key in prefixes.items():
        if t.startswith(p + " "):
            rest = t[len(p):].strip()
            args = rest.split() if rest else []
            return key, args

    return None


# ---------------- anti-raid settings (keep minimal) ----------------
RAID_WINDOW_SECONDS = 30
RAID_THRESHOLD_JOINS = 10
join_events: dict[int, list[float]] = {}
raid_notified_chats: set[int] = set()

BAN_NOTIFY_COOLDOWN = 30 * 60
_last_notified: dict[tuple[int, int], float] = {}


def register_join(chat_id: int) -> int:
    now = time.time()
    q = join_events.setdefault(chat_id, [])
    q.append(now)
    cutoff = now - RAID_WINDOW_SECONDS
    while q and q[0] < cutoff:
        q.pop(0)
    return len(q)


# ---------------- DB init ----------------
async def init_db(cfg: Config) -> None:
    if not _db_ready(cfg):
        logging.warning("DATABASE_URL not set; DB features disabled.")
        return

    def _run_init():
        init_schema(cfg.database_url)
        init_management_schema(cfg.database_url)
        # ensure bot_settings exists
        with_conn(cfg.database_url, lambda conn: conn.cursor().execute(BOT_SETTINGS_TABLE_SQL))

    await asyncio.to_thread(_run_init)
    logging.info("DB init ok (core + management + bot_settings).")


# ---------------- user resolution ----------------
async def resolve_user_ref(
    context: ContextTypes.DEFAULT_TYPE,
    ref: str
) -> tuple[int, str | None, str | None, str | None]:
    ref = (ref or "").strip()
    if ref.isdigit():
        return int(ref), None, None, None
    if ref.startswith("@"):
        chat = await context.bot.get_chat(ref)
        return int(chat.id), getattr(chat, "username", None), getattr(chat, "first_name", None), getattr(chat, "last_name", None)
    raise ValueError("bad_ref")


# ---------------- HELP output (role-based) ----------------
def help_for_superadmins() -> str:
    return (
        "راهنما (سوپرادمین):\n"
        "\n"
        "داخل PV:\n"
        "  /help یا راهنما\n"
        "  /mg_list یا گروه‌های مدیریتی\n"
        "  /mg_subgroups <شماره|mg_chat_id> یا نمایش زیرمجموعه <...>\n"
        "\n"
        "داخل هر گروهی که می‌خواهی MG شود:\n"
        "  /register_mg یا ثبت گروه مدیریتی\n"
        "  /remove_mg یا حذف گروه مدیریتی\n"
        "\n"
        "داخل گروه Root (اکلیس) که فقط برای Ownerهای اصلی است:\n"
        "  /register_root_mg یا ثبت گروه مدیریتی اکلیس\n"
        "\n"
        "مدیریت زیرگروه‌ها (داخل خود MG، فقط Owner همان MG):\n"
        "  /add_group <subgroup_chat_id> یا افزودن زیرگروه <id>\n"
        "  /confirm_add_group یا تایید زیرگروه\n"
        "  /cancel یا لغو\n"
        "\n"
        "بن سراسری:\n"
        "  /ban <user_id|@username> یا بن <...>\n"
        "  /unban <user_id> یا آنبن <...>\n"
    )


def help_for_mg_owner(mg_chat_id: int) -> str:
    return (
        "راهنما (Owner گروه مدیریتی):\n"
        f"\nMG: {mg_chat_id}\n"
        "\n"
        "داخل گروه MG:\n"
        "  /add_group <subgroup_chat_id>\n"
        "  /confirm_add_group\n"
        "  /cancel\n"
        "  /addmode <ask|all>\n"
        "  /subgroups (نمایش زیرگروه‌های همین MG)\n"
        "\n"
        "داخل PV:\n"
        "  راهنما\n"
        "  زیرمجموعه‌ها (فقط زیرگروه‌های MG خودت)\n"
    )


def help_for_unknown() -> str:
    return "شما دسترسی ادمین/اونر ندارید."


# ---------------- commands ----------------
async def cmd_help(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    chat = update.effective_chat

    if not user:
        return

    # superadmins: always full help, but only show in PV (طبق خواسته تو)
    if is_superadmin(cfg, user.id):
        if pv_only(update):
            await update.effective_message.reply_text(help_for_superadmins())
        else:
            await update.effective_message.reply_text("برای دیدن راهنما، در PV به بات پیام بده: راهنما")
        return

    # mg owner: help in PV + in their MG group
    if _db_ready(cfg):
        if chat and chat.type in ("group", "supergroup"):
            owner = await asyncio.to_thread(get_management_group_owner, cfg.database_url, chat.id)
            if owner == user.id:
                await update.effective_message.reply_text(help_for_mg_owner(chat.id))
                return

        if pv_only(update):
            # try to find if this user is owner of any MG
            # (fast and simple: scan all MGs)
            groups = await asyncio.to_thread(db_list_management_groups, cfg.database_url)
            for mg_id, owner_id in groups:
                if owner_id == user.id:
                    await update.effective_message.reply_text(help_for_mg_owner(mg_id))
                    return

    await update.effective_message.reply_text(help_for_unknown())


async def cmd_register_mg(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # must be in a group; only superadmins can register
    if not await superadmin_guard(cfg, update):
        return
    if not _db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست/خراب است.")
        return

    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user or chat.type not in ("group", "supergroup"):
        await update.effective_message.reply_text("این دستور باید داخل همان گروهی که می‌خواهی MG شود اجرا شود.")
        return

    # confirmation flow (command-only, no inline)
    context.chat_data["pending_register_mg"] = {"mg_chat_id": chat.id, "owner_user_id": user.id}
    await update.effective_message.reply_text(
        "آیا مطمئنی این گروه به عنوان «گروه مدیریتی» ثبت شود؟\n"
        "برای تایید: بله\n"
        "برای لغو: لغو"
    )


async def cmd_remove_mg(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await superadmin_guard(cfg, update):
        return
    if not _db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست/خراب است.")
        return

    chat = update.effective_chat
    if not chat or chat.type not in ("group", "supergroup"):
        await update.effective_message.reply_text("این دستور باید داخل همان MG اجرا شود.")
        return

    def _run(conn):
        cur = conn.cursor()
        cur.execute("DELETE FROM mg_subgroups WHERE mg_chat_id=%s", (chat.id,))
        cur.execute("DELETE FROM mg_settings WHERE mg_chat_id=%s", (chat.id,))
        cur.execute("DELETE FROM management_groups WHERE mg_chat_id=%s", (chat.id,))
    await asyncio.to_thread(lambda: with_conn(cfg.database_url, _run))

    await update.effective_message.reply_text("✅ این گروه از حالت MG حذف شد.")


async def cmd_register_root_mg(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Root MG = special setting stored in bot_settings
    if not await superadmin_guard(cfg, update):
        return
    if not _db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست/خراب است.")
        return

    chat = update.effective_chat
    if not chat or chat.type not in ("group", "supergroup"):
        await update.effective_message.reply_text("این دستور باید داخل گروه اصلی اکلیس اجرا شود.")
        return

    # store root mg
    await asyncio.to_thread(db_set_setting, cfg.database_url, "root_mg_chat_id", str(chat.id))
    await update.effective_message.reply_text(f"✅ گروه مدیریتی اکلیس (Root) ثبت شد: {chat.id}")


async def cmd_mg_list(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not pv_only(update):
        return
    if not await superadmin_guard(cfg, update):
        return
    if not _db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست/خراب است.")
        return

    groups = await asyncio.to_thread(db_list_management_groups, cfg.database_url)
    if not groups:
        await update.effective_message.reply_text("هیچ گروه مدیریتی ثبت نشده.")
        return

    lines = []
    for i, (mg_id, owner_id) in enumerate(groups, start=1):
        lines.append(f"{i}) mg={mg_id}  owner={owner_id}")
    await update.effective_message.reply_text("لیست گروه‌های مدیریتی:\n" + "\n".join(lines))


async def cmd_mg_subgroups(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # superadmins in PV: can query any MG by index or mg_chat_id
    if not pv_only(update):
        return
    if not await superadmin_guard(cfg, update):
        return
    if not _db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست/خراب است.")
        return
    if not context.args or len(context.args) != 1:
        await update.effective_message.reply_text("Usage: /mg_subgroups <number|mg_chat_id>\nمثال: نمایش زیرمجموعه 1")
        return

    ref = context.args[0].strip()
    groups = await asyncio.to_thread(db_list_management_groups, cfg.database_url)

    mg_chat_id: Optional[int] = None
    if ref.isdigit():
        n = int(ref)
        if 1 <= n <= len(groups):
            mg_chat_id = groups[n - 1][0]
        else:
            # treat as mg_chat_id
            mg_chat_id = int(ref)
    elif ref.lstrip("-").isdigit():
        mg_chat_id = int(ref)

    if mg_chat_id is None:
        await update.effective_message.reply_text("ورودی نامعتبر است.")
        return

    subs = await asyncio.to_thread(list_subgroups, cfg.database_url, mg_chat_id)
    if not subs:
        await update.effective_message.reply_text(f"برای MG={mg_chat_id} هیچ زیرگروهی ثبت نشده.")
        return

    await update.effective_message.reply_text(f"زیرگروه‌های MG={mg_chat_id}:\n" + "\n".join(map(str, subs)))


async def cmd_subgroups_self(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # MG owner: in PV show own MG subgroups; in MG group show its subgroups
    user = update.effective_user
    if not user or not _db_ready(cfg):
        return

    # if in group and owner:
    chat = update.effective_chat
    if chat and chat.type in ("group", "supergroup"):
        owner = await asyncio.to_thread(get_management_group_owner, cfg.database_url, chat.id)
        if owner == user.id:
            subs = await asyncio.to_thread(list_subgroups, cfg.database_url, chat.id)
            if not subs:
                await update.effective_message.reply_text("هیچ زیرگروهی ثبت نشده.")
            else:
                await update.effective_message.reply_text("زیرگروه‌ها:\n" + "\n".join(map(str, subs)))
        return

    # PV: find user's MG
    if not pv_only(update):
        return

    groups = await asyncio.to_thread(db_list_management_groups, cfg.database_url)
    my_mg = None
    for mg_id, owner_id in groups:
        if owner_id == user.id:
            my_mg = mg_id
            break

    if not my_mg:
        await update.effective_message.reply_text("شما Owner هیچ گروه مدیریتی نیستید.")
        return

    subs = await asyncio.to_thread(list_subgroups, cfg.database_url, my_mg)
    if not subs:
        await update.effective_message.reply_text("هیچ زیرگروهی ثبت نشده.")
    else:
        await update.effective_message.reply_text(f"MG={my_mg}\nزیرگروه‌ها:\n" + "\n".join(map(str, subs)))


async def cmd_add_group(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await mg_owner_guard(cfg, update):
        return
    if not _db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست/خراب است.")
        return
    if not context.args or len(context.args) != 1:
        await update.effective_message.reply_text("Usage: /add_group <subgroup_chat_id>")
        return

    sub_raw = context.args[0]
    if not sub_raw.lstrip("-").isdigit():
        await update.effective_message.reply_text("آیدی زیرگروه باید عددی باشد (مثلاً -100...).")
        return

    subgroup_chat_id = int(sub_raw)
    context.chat_data["pending_add_group"] = subgroup_chat_id
    await update.effective_message.reply_text(
        f"زیرگروه پیشنهادی:\n{subgroup_chat_id}\n\n"
        f"تایید: /confirm_add_group یا تایید زیرگروه\n"
        f"لغو: /cancel یا لغو"
    )


async def cmd_confirm_add_group(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await mg_owner_guard(cfg, update):
        return
    if not _db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست/خراب است.")
        return

    pending = context.chat_data.get("pending_add_group")
    if not pending:
        await update.effective_message.reply_text("چیزی برای تایید وجود ندارد.")
        return

    mg_chat_id = update.effective_chat.id
    subgroup_chat_id = int(pending)
    await asyncio.to_thread(add_subgroup, cfg.database_url, mg_chat_id, subgroup_chat_id)
    context.chat_data.pop("pending_add_group", None)
    await update.effective_message.reply_text(f"✅ زیرگروه ثبت شد: {subgroup_chat_id}")


async def cmd_cancel(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.chat_data.pop("pending_add_group", None)
    context.chat_data.pop("pending_register_mg", None)
    await update.effective_message.reply_text("لغو شد.")


async def cmd_addmode(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await mg_owner_guard(cfg, update):
        return
    if not _db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست/خراب است.")
        return
    if not context.args or len(context.args) != 1:
        await update.effective_message.reply_text("Usage: /addmode <ask|all>")
        return

    mode = context.args[0].strip().lower()
    if mode not in ("ask", "all"):
        await update.effective_message.reply_text("فقط ask یا all مجاز است.")
        return

    mg_chat_id = update.effective_chat.id
    await asyncio.to_thread(set_add_member_mode, cfg.database_url, mg_chat_id, mode)
    await update.effective_message.reply_text(f"✅ حالت افزودن تنظیم شد: {mode}")


async def cmd_ban(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # global ban (superadmins only, PV)
    if not pv_only(update):
        return
    if not await superadmin_guard(cfg, update):
        return
    if not _db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست/خراب است.")
        return
    if not context.args or len(context.args) != 1:
        await update.effective_message.reply_text("Usage: /ban <user_id|@username>")
        return

    ref = context.args[0]
    try:
        user_id, username, first_name, last_name = await resolve_user_ref(context, ref)
    except Exception:
        await update.effective_message.reply_text("ورودی نامعتبر است. مثال: /ban 123456 یا /ban @username")
        return

    await asyncio.to_thread(remove_allowed_member, cfg.database_url, user_id)
    await asyncio.to_thread(add_global_ban, cfg.database_url, user_id)

    await update.effective_message.reply_text(f"✅ بن سراسری انجام شد: {user_id}")


async def cmd_unban(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # global unban (superadmins only, PV)
    if not pv_only(update):
        return
    if not await superadmin_guard(cfg, update):
        return
    if not _db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست/خراب است.")
        return
    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        await update.effective_message.reply_text("Usage: /unban <user_id>")
        return

    user_id = int(context.args[0])
    await asyncio.to_thread(remove_global_ban, cfg.database_url, user_id)
    # optional: re-allow so it won't be blocked by allowlist checks later if you use them
    await asyncio.to_thread(upsert_allowed_member, cfg.database_url, user_id, None, None, None)
    await update.effective_message.reply_text(f"✅ آنبن سراسری انجام شد: {user_id}")


# ---------------- confirmation by plain text (بله/لغو) ----------------
async def on_farsi_text(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg or not msg.text:
        return

    text = normalize_fa(msg.text)

    # handle pending mg registration confirmations only for superadmins
    if text in ("بله", "بلی"):
        pending = context.chat_data.get("pending_register_mg")
        if pending and update.effective_user and is_superadmin(cfg, update.effective_user.id) and _db_ready(cfg):
            mg_chat_id = int(pending["mg_chat_id"])
            owner_user_id = int(pending["owner_user_id"])
            await asyncio.to_thread(set_management_group, cfg.database_url, mg_chat_id, owner_user_id)
            context.chat_data.pop("pending_register_mg", None)
            await msg.reply_text(f"✅ MG ثبت شد.\nmg: {mg_chat_id}\nowner: {owner_user_id}")
            return

    if text == "لغو":
        if "pending_register_mg" in context.chat_data or "pending_add_group" in context.chat_data:
            await cmd_cancel(cfg, update, context)
            return

    # parse no-slash Persian commands
    parsed = parse_fa_command(text)
    if not parsed:
        return
    key, args = parsed

    old_args = getattr(context, "args", None)
    context.args = args
    try:
        if key == "help":
            await cmd_help(cfg, update, context)
        elif key == "register_mg":
            await cmd_register_mg(cfg, update, context)
        elif key == "remove_mg":
            await cmd_remove_mg(cfg, update, context)
        elif key == "register_root_mg":
            await cmd_register_root_mg(cfg, update, context)
        elif key == "mg_list":
            await cmd_mg_list(cfg, update, context)
        elif key == "mg_subgroups":
            await cmd_mg_subgroups(cfg, update, context)
        elif key == "subgroups_self":
            await cmd_subgroups_self(cfg, update, context)
        elif key == "add_group":
            await cmd_add_group(cfg, update, context)
        elif key == "confirm_add_group":
            await cmd_confirm_add_group(cfg, update, context)
        elif key == "cancel":
            await cmd_cancel(cfg, update, context)
        elif key == "addmode":
            await cmd_addmode(cfg, update, context)
        elif key == "ban":
            await cmd_ban(cfg, update, context)
        elif key == "unban":
            await cmd_unban(cfg, update, context)
    finally:
        context.args = old_args


# ---------------- enforcement hooks (optional) ----------------
async def enforce_user(cfg: Config, context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int, reason: str):
    if not _db_ready(cfg):
        return
    if user_id == context.bot.id:
        return

    await asyncio.to_thread(mark_seen, cfg.database_url, chat_id, user_id)

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
            return

        # If you want allowlist-only behavior in protected chats, keep this:
        if not await asyncio.to_thread(is_allowed_member, cfg.database_url, user_id):
            await context.bot.ban_chat_member(chat_id, user_id)
            await asyncio.to_thread(log_join_event, cfg.database_url, chat_id, None, user_id, None, None, None, "banned")

    except Exception as e:
        logging.warning(f"enforce failed reason={reason} chat={chat_id} user={user_id} err={e}")


async def on_new_members_message(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _db_ready(cfg):
        return
    chat = update.effective_chat
    msg = update.effective_message
    if not chat or not msg:
        return

    chat_id = chat.id
    if not await asyncio.to_thread(is_protected_chat, cfg.database_url, chat_id):
        return
    if not msg.new_chat_members:
        return

    cnt = register_join(chat_id)
    if cnt >= RAID_THRESHOLD_JOINS and chat_id not in raid_notified_chats:
        raid_notified_chats.add(chat_id)
        for admin_id in cfg.admin_ids:
            try:
                await context.bot.send_message(admin_id, f"⚠️ احتمال raid در گروه {chat_id}: join زیاد در {RAID_WINDOW_SECONDS}s")
            except Exception:
                pass

    for u in msg.new_chat_members:
        await enforce_user(cfg, context, chat_id, u.id, reason="new_chat_members")


async def on_chat_member(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _db_ready(cfg):
        return
    chat = update.effective_chat
    if not chat:
        return
    chat_id = chat.id
    if not await asyncio.to_thread(is_protected_chat, cfg.database_url, chat_id):
        return

    cmu = update.chat_member
    if not cmu:
        return

    old = cmu.old_chat_member
    new = cmu.new_chat_member

    if not (old.status in ("left", "kicked") and new.status in ("member", "restricted")):
        return

    cnt = register_join(chat_id)
    if cnt >= RAID_THRESHOLD_JOINS and chat_id not in raid_notified_chats:
        raid_notified_chats.add(chat_id)
        for admin_id in cfg.admin_ids:
            try:
                await context.bot.send_message(admin_id, f"⚠️ احتمال raid در گروه {chat_id}: {cnt} join در {RAID_WINDOW_SECONDS}s")
            except Exception:
                pass

    await enforce_user(cfg, context, chat_id, new.user.id, reason="chat_member")


async def periodic_enforce(cfg: Config, context: ContextTypes.DEFAULT_TYPE):
    # keep minimal: only if DB ready and you use protected_chats
    if not _db_ready(cfg):
        return
    bot = context.bot
    chats = await asyncio.to_thread(lambda: with_conn(cfg.database_url, lambda conn: [int(r[0]) for r in conn.cursor().execute("SELECT chat_id FROM protected_chats").fetchall()]))

    for chat_id in chats:
        try:
            admins = await bot.get_chat_administrators(chat_id)
            admin_ids = {a.user.id for a in admins}

            seen = await asyncio.to_thread(get_seen_users, cfg.database_url, chat_id, 5000)
            for user_id in seen:
                if user_id in admin_ids:
                    continue

                should_ban = await asyncio.to_thread(is_globally_banned, cfg.database_url, user_id) or (not await asyncio.to_thread(is_allowed_member, cfg.database_url, user_id))
                if not should_ban:
                    continue

                try:
                    m = await bot.get_chat_member(chat_id, user_id)
                    if m.status == "kicked":
                        continue
                except Exception:
                    pass

                try:
                    await bot.ban_chat_member(chat_id, user_id)

                    key = (chat_id, user_id)
                    now = time.time()
                    last = _last_notified.get(key, 0)
                    if now - last >= BAN_NOTIFY_COOLDOWN:
                        _last_notified[key] = now
                        for admin_id in cfg.admin_ids:
                            try:
                                await bot.send_message(admin_id, f"⛔️ periodic ban\nuser: {user_id}\nchat: {chat_id}")
                            except Exception:
                                pass
                except Exception as e:
                    logging.warning(f"periodic ban failed chat={chat_id} user={user_id} err={e}")

        except Exception as e:
            logging.warning(f"periodic scan failed chat={chat_id} err={e}")


# ---------------- app build ----------------
def build_application(cfg: Config) -> Application:
    # Increase timeouts to reduce startup failures on Render
    request = HTTPXRequest(connect_timeout=30.0, read_timeout=30.0, write_timeout=30.0, pool_timeout=30.0)

    app = Application.builder().token(cfg.bot_token).request(request).build()

    # text router (Persian no-slash + confirmations)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: on_farsi_text(cfg, u, c)), group=0)

    # help
    app.add_handler(CommandHandler("help", lambda u, c: cmd_help(cfg, u, c)))
    app.add_handler(CommandHandler("start", lambda u, c: cmd_help(cfg, u, c)))

    # superadmin-only
    app.add_handler(CommandHandler("register_mg", lambda u, c: cmd_register_mg(cfg, u, c)))
    app.add_handler(CommandHandler("remove_mg", lambda u, c: cmd_remove_mg(cfg, u, c)))
    app.add_handler(CommandHandler("register_root_mg", lambda u, c: cmd_register_root_mg(cfg, u, c)))
    app.add_handler(CommandHandler("mg_list", lambda u, c: cmd_mg_list(cfg, u, c)))
    app.add_handler(CommandHandler("mg_subgroups", lambda u, c: cmd_mg_subgroups(cfg, u, c)))
    app.add_handler(CommandHandler("ban", lambda u, c: cmd_ban(cfg, u, c)))
    app.add_handler(CommandHandler("unban", lambda u, c: cmd_unban(cfg, u, c)))

    # mg-owner commands (must be in MG group)
    app.add_handler(CommandHandler("add_group", lambda u, c: cmd_add_group(cfg, u, c)))
    app.add_handler(CommandHandler("confirm_add_group", lambda u, c: cmd_confirm_add_group(cfg, u, c)))
    app.add_handler(CommandHandler("cancel", lambda u, c: cmd_cancel(cfg, u, c)))
    app.add_handler(CommandHandler("addmode", lambda u, c: cmd_addmode(cfg, u, c)))
    app.add_handler(CommandHandler("subgroups", lambda u, c: cmd_subgroups_self(cfg, u, c)))

    # join detection (optional)
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, lambda u, c: on_new_members_message(cfg, u, c)))
    app.add_handler(ChatMemberHandler(lambda u, c: on_chat_member(cfg, u, c), ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(ChatMemberHandler(lambda u, c: on_chat_member(cfg, u, c), ChatMemberHandler.MY_CHAT_MEMBER))

    async def _post_init(application: Application):
        await init_db(cfg)
        application.job_queue.run_repeating(lambda c: periodic_enforce(cfg, c), interval=60, first=60)

        if cfg.run_mode == "server":
            # Your cfg should expose webhook_secret/public_base_url/port
            # webhook path must include leading slash for HTTPServer handler:
            webhook_path = f"/webhook/{cfg.webhook_secret}"
            webhook_url = f"{cfg.public_base_url}{webhook_path}"
            await application.bot.set_webhook(url=webhook_url, drop_pending_updates=True)
            logging.info(f"Webhook set: {webhook_url}")

    app.post_init = _post_init
    return app


def run_local_polling(app: Application) -> None:
    logging.info("Starting in LOCAL mode (polling)")
    app.run_polling(drop_pending_updates=True)


# ---------------- minimal webhook server (server mode) ----------------
class WebhookHandler(BaseHTTPRequestHandler):
    loop: asyncio.AbstractEventLoop | None = None
    application: Application | None = None
    webhook_path: str = "/"

    def _send(self, code=200, body=b"OK"):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

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
    logging.info("Starting in SERVER mode (webhook)")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def _startup():
        await app.initialize()
        await app.start()
        logging.info("Application started")

    loop.run_until_complete(_startup())

    WebhookHandler.loop = loop
    WebhookHandler.application = app
    WebhookHandler.webhook_path = f"/webhook/{cfg.webhook_secret}"

    server = HTTPServer(("0.0.0.0", cfg.port), WebhookHandler)
    logging.info(f"Listening on 0.0.0.0:{cfg.port} (health: / , webhook: {WebhookHandler.webhook_path})")

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
