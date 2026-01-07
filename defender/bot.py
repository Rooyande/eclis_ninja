# defender/bot.py
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Optional

from telegram import Update
from telegram.constants import ChatType
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)
from telegram.request import HTTPXRequest
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from config import Config

# Core DB repo (global allow/ban + protected chats)
from defender.db.repo.core import (
    add_global_ban,
    add_protected_chat,
    get_seen_users,
    init_schema,
    is_allowed_member,
    is_globally_banned,
    is_protected_chat,
    list_allowed_members,
    list_protected_chats,
    log_join_event,
    mark_seen,
    remove_allowed_member,
    remove_global_ban,
    remove_protected_chat,
    upsert_allowed_member,
)

# Management DB repo (management groups + subgroups + modes)
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
log = logging.getLogger(__name__)

# ----------------------------
# Anti-raid settings
# ----------------------------
RAID_WINDOW_SECONDS = 30
RAID_THRESHOLD_JOINS = 10
join_events: dict[int, list[float]] = {}
raid_notified_chats: set[int] = set()

BAN_NOTIFY_COOLDOWN = 30 * 60  # 30 min
_last_notified: dict[tuple[int, int], float] = {}  # (chat_id,user_id)->ts


# ----------------------------
# Helpers / Guards
# ----------------------------
def pv_only(update: Update) -> bool:
    return bool(update.effective_chat and update.effective_chat.type == ChatType.PRIVATE)


def is_db_ready(cfg: Config) -> bool:
    # اجازه بده اگر DATABASE_URL خالی یا placeholder بود، بات بالا بیاید ولی DB فیچرها غیرفعال شوند.
    return bool(cfg.database_url and not cfg.database_url.strip().startswith("<"))


def is_super_admin(cfg: Config, user_id: int) -> bool:
    return user_id in cfg.admin_ids


async def super_admin_guard(cfg: Config, update: Update) -> bool:
    return (
        pv_only(update)
        and update.effective_user is not None
        and is_super_admin(cfg, update.effective_user.id)
    )


async def mg_owner_guard(cfg: Config, update: Update) -> bool:
    """
    فقط داخل گروه مدیریتی (mg) و فقط کسی که owner همان mg است.
    """
    if not is_db_ready(cfg):
        return False
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return False
    if chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return False
    owner = await asyncio.to_thread(get_management_group_owner, cfg.database_url, chat.id)
    return owner == user.id


def normalize_fa(s: str) -> str:
    return (
        (s or "")
        .replace("ي", "ی")
        .replace("ك", "ک")
        .replace("\u200c", " ")
        .strip()
    )


async def resolve_user_ref(context: ContextTypes.DEFAULT_TYPE, ref: str) -> tuple[int, str | None, str | None, str | None]:
    ref = (ref or "").strip()
    if ref.isdigit():
        return int(ref), None, None, None
    if ref.startswith("@"):
        chat = await context.bot.get_chat(ref)
        return int(chat.id), getattr(chat, "username", None), getattr(chat, "first_name", None), getattr(chat, "last_name", None)
    raise ValueError("bad_ref")


def register_join(chat_id: int) -> int:
    now = time.time()
    q = join_events.setdefault(chat_id, [])
    q.append(now)
    cutoff = now - RAID_WINDOW_SECONDS
    while q and q[0] < cutoff:
        q.pop(0)
    return len(q)


# ----------------------------
# DB init
# ----------------------------
async def init_db(cfg: Config) -> None:
    if not is_db_ready(cfg):
        log.warning("DATABASE_URL is not set/invalid. DB features disabled.")
        return
    await asyncio.to_thread(init_schema, cfg.database_url)
    await asyncio.to_thread(init_management_schema, cfg.database_url)
    log.info("Database init ok.")


# ----------------------------
# Core enforcement
# ----------------------------
async def enforce_user(cfg: Config, context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int, reason: str):
    if user_id == context.bot.id:
        return
    if not is_db_ready(cfg):
        return

    await asyncio.to_thread(mark_seen, cfg.database_url, chat_id, user_id)

    try:
        # اگر قبلاً kick شده، دوباره اسپم نکن
        try:
            m = await context.bot.get_chat_member(chat_id, user_id)
            if m.status == "kicked":
                return
        except Exception:
            pass

        if await asyncio.to_thread(is_globally_banned, cfg.database_url, user_id):
            await context.bot.ban_chat_member(chat_id, user_id)
            return

        if not await asyncio.to_thread(is_allowed_member, cfg.database_url, user_id):
            await context.bot.ban_chat_member(chat_id, user_id)

            # notify super admins (PV)
            for admin_id in cfg.admin_ids:
                try:
                    await context.bot.send_message(admin_id, f"⛔️ BAN ({reason})\nuser: {user_id}\nchat: {chat_id}")
                except Exception:
                    pass

            await asyncio.to_thread(log_join_event, cfg.database_url, chat_id, None, user_id, None, None, None, "banned")
    except Exception as e:
        log.warning("enforce failed reason=%s chat=%s user=%s err=%s", reason, chat_id, user_id, e)


# ----------------------------
# UX: Help text by role
# ----------------------------
def help_for_super_admin() -> str:
    return (
        "پنل سوپرادمین:\n"
        "• تنظیم گروه مدیریتی (mg)\n"
        "• افزودن/حذف عضو مجاز\n"
        "• بن/آنبن سراسری\n"
        "• افزودن/حذف گروه محافظت‌شده\n"
        "• لیست اعضا / لیست گروه‌ها\n"
        "\n"
        "دستورها (PV):\n"
        "/panel\n"
        "/set_mg\n"
        "/add_member <user_id|@username>\n"
        "/remove_member <user_id>\n"
        "/ban <user_id>\n"
        "/unban <user_id>\n"
        "/add_chat <chat_id>\n"
        "/remove_chat <chat_id>\n"
        "/list_members\n"
        "/list_chats\n"
        "\n"
        "دستورهای فارسی (بدون اسلش در PV):\n"
        "پنل\n"
        "تنظیم گروه مدیریتی\n"
        "افزودن عضو 123 / افزودن عضو @username\n"
        "حذف عضو 123\n"
        "بن 123\n"
        "آنبن 123\n"
        "افزودن گروه -100...\n"
        "حذف گروه -100...\n"
        "لیست اعضا\n"
        "لیست گروه‌ها\n"
    )


def help_for_mg_owner() -> str:
    return (
        "پنل اونر گروه مدیریتی:\n"
        "• افزودن زیرگروه\n"
        "• لیست زیرگروه‌ها\n"
        "• حالت افزودن عضو (ask/all)\n"
        "\n"
        "دستورها (داخل MG):\n"
        "/panel\n"
        "/add_group\n"
        "/confirm_add_group\n"
        "/list_groups\n"
        "/addmode <ask|all>\n"
        "/cancel\n"
        "\n"
        "دستورهای فارسی (بدون اسلش داخل MG):\n"
        "پنل\n"
        "افزودن زیرگروه\n"
        "تایید زیرگروه\n"
        "لیست زیرگروه‌ها\n"
        "حالت افزودن ask  یا  حالت افزودن all\n"
        "لغو\n"
    )


# ----------------------------
# Inline Panels (buttons)
# ----------------------------
def kb_super_admin_panel() -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("تنظیم گروه مدیریتی", callback_data="sa:set_mg")],
        [InlineKeyboardButton("افزودن عضو مجاز", callback_data="sa:add_member"),
         InlineKeyboardButton("حذف عضو", callback_data="sa:remove_member")],
        [InlineKeyboardButton("بن سراسری", callback_data="sa:ban"),
         InlineKeyboardButton("آنبن سراسری", callback_data="sa:unban")],
        [InlineKeyboardButton("افزودن گروه محافظت", callback_data="sa:add_chat"),
         InlineKeyboardButton("حذف گروه محافظت", callback_data="sa:remove_chat")],
        [InlineKeyboardButton("لیست اعضا", callback_data="sa:list_members"),
         InlineKeyboardButton("لیست گروه‌ها", callback_data="sa:list_chats")],
    ]
    return InlineKeyboardMarkup(rows)


def kb_mg_owner_panel() -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("افزودن زیرگروه", callback_data="mg:add_group")],
        [InlineKeyboardButton("لیست زیرگروه‌ها", callback_data="mg:list_groups")],
        [InlineKeyboardButton("حالت افزودن: ask", callback_data="mg:addmode:ask"),
         InlineKeyboardButton("حالت افزودن: all", callback_data="mg:addmode:all")],
        [InlineKeyboardButton("لغو", callback_data="mg:cancel")],
    ]
    return InlineKeyboardMarkup(rows)


# ----------------------------
# Conversation States
# ----------------------------
SA_SET_MG_CHAT, SA_SET_MG_OWNER = 101, 102
SA_ADD_MEMBER_REF = 111
SA_REMOVE_MEMBER_ID = 112
SA_BAN_ID = 113
SA_UNBAN_ID = 114
SA_ADD_CHAT_ID = 115
SA_REMOVE_CHAT_ID = 116

MG_ADD_GROUP_ID = 201

CTX_PENDING = "pending_value"


# ----------------------------
# Super Admin: Panel and actions
# ----------------------------
async def cmd_panel(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # PV super admin panel
    if pv_only(update) and update.effective_user and is_super_admin(cfg, update.effective_user.id):
        await update.effective_message.reply_text("پنل سوپرادمین:", reply_markup=kb_super_admin_panel())
        return

    # MG owner panel (inside mg)
    if await mg_owner_guard(cfg, update):
        await update.effective_message.reply_text("پنل اونر گروه مدیریتی:", reply_markup=kb_mg_owner_panel())
        return

    # fallback
    await update.effective_message.reply_text("دسترسی پنل برای شما فعال نیست.")


async def cmd_start(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # در PV: کمک نقش‌محور
    if pv_only(update):
        if update.effective_user and is_super_admin(cfg, update.effective_user.id):
            await update.effective_message.reply_text(help_for_super_admin())
        else:
            await update.effective_message.reply_text("این بات فقط برای ادمین‌هاست.")
        return

    # در گروه: اگر اونر mg هست، کمک mg
    if await mg_owner_guard(cfg, update):
        await update.effective_message.reply_text(help_for_mg_owner())
        return


# ----------------------------
# Super Admin Conversations
# ----------------------------
async def sa_set_mg_start(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return ConversationHandler.END
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست؛ اول دیتابیس را درست کن.")
        return ConversationHandler.END
    await update.effective_message.reply_text("آیدی گروه مدیریتی (mg_chat_id) را بفرست. مثال: -100123...")
    return SA_SET_MG_CHAT


async def sa_set_mg_chat(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return ConversationHandler.END
    text = normalize_fa(update.effective_message.text)
    if not text.lstrip("-").isdigit():
        await update.effective_message.reply_text("آیدی باید عددی باشد. دوباره بفرست.")
        return SA_SET_MG_CHAT
    context.user_data[CTX_PENDING] = int(text)
    await update.effective_message.reply_text("حالا آیدی اونر (owner_user_id) را بفرست. مثال: 123456789")
    return SA_SET_MG_OWNER


async def sa_set_mg_owner(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return ConversationHandler.END
    text = normalize_fa(update.effective_message.text)
    if not text.isdigit():
        await update.effective_message.reply_text("آیدی اونر باید عددی باشد. دوباره بفرست.")
        return SA_SET_MG_OWNER

    mg_chat_id = int(context.user_data.get(CTX_PENDING))
    owner_id = int(text)

    await asyncio.to_thread(set_management_group, cfg.database_url, mg_chat_id, owner_id)
    context.user_data.pop(CTX_PENDING, None)

    await update.effective_message.reply_text(f"✅ گروه مدیریتی ثبت شد.\nmg: {mg_chat_id}\nowner: {owner_id}")
    return ConversationHandler.END


async def sa_add_member_start(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return ConversationHandler.END
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return ConversationHandler.END
    await update.effective_message.reply_text("یوزر را بده: عددی یا @username")
    return SA_ADD_MEMBER_REF


async def sa_add_member_ref(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    ref = normalize_fa(update.effective_message.text)
    try:
        user_id, username, first_name, last_name = await resolve_user_ref(context, ref)
    except Exception:
        await update.effective_message.reply_text("ورودی نامعتبر است. مثال: 123456 یا @username")
        return SA_ADD_MEMBER_REF

    await asyncio.to_thread(upsert_allowed_member, cfg.database_url, user_id, username, first_name, last_name)
    await update.effective_message.reply_text(f"✅ عضو مجاز شد: {user_id}  {('@'+username) if username else ''}".strip())
    return ConversationHandler.END


async def sa_remove_member_start(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return ConversationHandler.END
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return ConversationHandler.END
    await update.effective_message.reply_text("آیدی عددی کاربر را بده.")
    return SA_REMOVE_MEMBER_ID


async def sa_remove_member_id(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = normalize_fa(update.effective_message.text)
    if not text.isdigit():
        await update.effective_message.reply_text("فقط عدد. دوباره بفرست.")
        return SA_REMOVE_MEMBER_ID

    target = int(text)
    await asyncio.to_thread(remove_allowed_member, cfg.database_url, target)
    await asyncio.to_thread(add_global_ban, cfg.database_url, target)

    # ban from all protected chats
    chats = await asyncio.to_thread(list_protected_chats, cfg.database_url)
    for chat_id in chats:
        try:
            await context.bot.ban_chat_member(chat_id=chat_id, user_id=target)
        except Exception:
            pass

    await update.effective_message.reply_text(f"✅ حذف شد و بن سراسری شد: {target}")
    return ConversationHandler.END


async def sa_ban_start(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return ConversationHandler.END
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return ConversationHandler.END
    await update.effective_message.reply_text("آیدی عددی کاربر برای بن سراسری را بده.")
    return SA_BAN_ID


async def sa_ban_id(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = normalize_fa(update.effective_message.text)
    if not text.isdigit():
        await update.effective_message.reply_text("فقط عدد. دوباره بفرست.")
        return SA_BAN_ID
    target = int(text)

    await asyncio.to_thread(add_global_ban, cfg.database_url, target)

    chats = await asyncio.to_thread(list_protected_chats, cfg.database_url)
    ok, fail = 0, 0
    for chat_id in chats:
        try:
            await context.bot.ban_chat_member(chat_id=chat_id, user_id=target)
            ok += 1
        except Exception:
            fail += 1

    await update.effective_message.reply_text(f"✅ بن سراسری ثبت شد: {target}\nban_ok={ok}  ban_fail={fail}")
    return ConversationHandler.END


async def sa_unban_start(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return ConversationHandler.END
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return ConversationHandler.END
    await update.effective_message.reply_text("آیدی عددی کاربر برای آنبن سراسری را بده.")
    return SA_UNBAN_ID


async def sa_unban_id(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = normalize_fa(update.effective_message.text)
    if not text.isdigit():
        await update.effective_message.reply_text("فقط عدد. دوباره بفرست.")
        return SA_UNBAN_ID
    target = int(text)

    await asyncio.to_thread(remove_global_ban, cfg.database_url, target)
    await asyncio.to_thread(upsert_allowed_member, cfg.database_url, target, None, None, None)

    chats = await asyncio.to_thread(list_protected_chats, cfg.database_url)
    ok, fail = 0, 0
    for chat_id in chats:
        try:
            await context.bot.unban_chat_member(chat_id=chat_id, user_id=target, only_if_banned=False)
            ok += 1
        except Exception:
            fail += 1

    await update.effective_message.reply_text(f"✅ آنبن انجام شد: {target}\nunban_ok={ok}  unban_fail={fail}")
    return ConversationHandler.END


async def sa_add_chat_start(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return ConversationHandler.END
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return ConversationHandler.END
    await update.effective_message.reply_text("آیدی گروه برای محافظت را بده. مثال: -100...")
    return SA_ADD_CHAT_ID


async def sa_add_chat_id(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = normalize_fa(update.effective_message.text)
    if not text.lstrip("-").isdigit():
        await update.effective_message.reply_text("آیدی باید عددی باشد. دوباره بفرست.")
        return SA_ADD_CHAT_ID
    chat_id = int(text)
    await asyncio.to_thread(add_protected_chat, cfg.database_url, chat_id)
    await update.effective_message.reply_text(f"✅ گروه محافظت شد: {chat_id}")
    return ConversationHandler.END


async def sa_remove_chat_start(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return ConversationHandler.END
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return ConversationHandler.END
    await update.effective_message.reply_text("آیدی گروه برای حذف از محافظت را بده. مثال: -100...")
    return SA_REMOVE_CHAT_ID


async def sa_remove_chat_id(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = normalize_fa(update.effective_message.text)
    if not text.lstrip("-").isdigit():
        await update.effective_message.reply_text("آیدی باید عددی باشد. دوباره بفرست.")
        return SA_REMOVE_CHAT_ID
    chat_id = int(text)
    await asyncio.to_thread(remove_protected_chat, cfg.database_url, chat_id)
    await update.effective_message.reply_text(f"✅ از محافظت حذف شد: {chat_id}")
    return ConversationHandler.END


async def sa_list_members(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return

    members = await asyncio.to_thread(list_allowed_members, cfg.database_url)
    if not members:
        await update.effective_message.reply_text("هیچ عضو مجازی ثبت نشده.")
        return
    lines = []
    for uid, uname in members:
        lines.append(f"{uid}  {('@'+uname) if uname else ''}".rstrip())
    await update.effective_message.reply_text("لیست اعضای مجاز:\n" + "\n".join(lines))


async def sa_list_chats(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return

    chats = await asyncio.to_thread(list_protected_chats, cfg.database_url)
    if not chats:
        await update.effective_message.reply_text("هیچ گروه محافظت‌شده‌ای ثبت نشده.")
        return
    await update.effective_message.reply_text("لیست گروه‌های محافظت‌شده:\n" + "\n".join(map(str, chats)))


# ----------------------------
# MG Owner: subgroup management
# ----------------------------
async def mg_add_group_start(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await mg_owner_guard(cfg, update):
        return ConversationHandler.END
    await update.effective_message.reply_text("آیدی زیرگروه را بده. مثال: -100...")
    return MG_ADD_GROUP_ID


async def mg_add_group_id(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await mg_owner_guard(cfg, update):
        return ConversationHandler.END
    text = normalize_fa(update.effective_message.text)
    if not text.lstrip("-").isdigit():
        await update.effective_message.reply_text("آیدی باید عددی باشد. دوباره بفرست.")
        return MG_ADD_GROUP_ID

    subgroup_chat_id = int(text)
    mg_chat_id = update.effective_chat.id
    await asyncio.to_thread(add_subgroup, cfg.database_url, mg_chat_id, subgroup_chat_id)
    await update.effective_message.reply_text(f"✅ زیرگروه ثبت شد: {subgroup_chat_id}")
    return ConversationHandler.END


async def mg_list_groups(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await mg_owner_guard(cfg, update):
        return
    mg_chat_id = update.effective_chat.id
    groups = await asyncio.to_thread(list_subgroups, cfg.database_url, mg_chat_id)
    if not groups:
        await update.effective_message.reply_text("هیچ زیرگروهی ثبت نشده.")
        return
    await update.effective_message.reply_text("زیرگروه‌ها:\n" + "\n".join(map(str, groups)))


async def mg_set_addmode(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE, mode: str):
    if not await mg_owner_guard(cfg, update):
        return
    mode = (mode or "").strip().lower()
    if mode not in ("ask", "all"):
        await update.effective_message.reply_text("فقط ask یا all مجاز است.")
        return
    mg_chat_id = update.effective_chat.id
    await asyncio.to_thread(set_add_member_mode, cfg.database_url, mg_chat_id, mode)
    await update.effective_message.reply_text(f"✅ حالت افزودن تنظیم شد: {mode}")


# ----------------------------
# Button router
# ----------------------------
async def on_callback(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if not q:
        return
    await q.answer()

    data = q.data or ""

    # Super admin panel buttons (PV)
    if data.startswith("sa:"):
        if not (pv_only(update) and update.effective_user and is_super_admin(cfg, update.effective_user.id)):
            await q.edit_message_text("دسترسی ندارید.")
            return

        key = data.split(":", 1)[1]

        if key == "set_mg":
            await q.edit_message_text("برای تنظیم mg، دستور /set_mg را بزن یا بنویس: «تنظیم گروه مدیریتی»")
        elif key == "add_member":
            await q.edit_message_text("برای افزودن عضو، دستور /add_member را بزن یا بنویس: «افزودن عضو»")
        elif key == "remove_member":
            await q.edit_message_text("برای حذف عضو، دستور /remove_member را بزن یا بنویس: «حذف عضو»")
        elif key == "ban":
            await q.edit_message_text("برای بن سراسری، دستور /ban را بزن یا بنویس: «بن»")
        elif key == "unban":
            await q.edit_message_text("برای آنبن، دستور /unban را بزن یا بنویس: «آنبن»")
        elif key == "add_chat":
            await q.edit_message_text("برای افزودن گروه محافظت، دستور /add_chat را بزن یا بنویس: «افزودن گروه»")
        elif key == "remove_chat":
            await q.edit_message_text("برای حذف گروه محافظت، دستور /remove_chat را بزن یا بنویس: «حذف گروه»")
        elif key == "list_members":
            await sa_list_members(cfg, update, context)
        elif key == "list_chats":
            await sa_list_chats(cfg, update, context)
        return

    # MG owner buttons (inside mg)
    if data.startswith("mg:"):
        if not await mg_owner_guard(cfg, update):
            await q.edit_message_text("دسترسی ندارید.")
            return

        parts = data.split(":")
        action = parts[1]

        if action == "add_group":
            await q.edit_message_text("برای افزودن زیرگروه، دستور /add_group را بزن یا بنویس: «افزودن زیرگروه»")
        elif action == "list_groups":
            await mg_list_groups(cfg, update, context)
        elif action == "addmode":
            mode = parts[2] if len(parts) > 2 else ""
            await mg_set_addmode(cfg, update, context, mode)
        elif action == "cancel":
            await q.edit_message_text("لغو شد.")
        return


# ----------------------------
# Persian text commands (no slash)
# ----------------------------
async def on_farsi_text(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg or not msg.text:
        return
    text = normalize_fa(msg.text)

    # PV: super admin text commands
    if pv_only(update) and update.effective_user and is_super_admin(cfg, update.effective_user.id):
        # panel / help
        if text in ("پنل", "panel"):
            await cmd_panel(cfg, update, context)
            return
        if text in ("شروع", "راهنما", "help"):
            await cmd_start(cfg, update, context)
            return

        # start conversations via Persian trigger words
        if text == "تنظیم گروه مدیریتی":
            await sa_set_mg_start(cfg, update, context)
            return
        if text.startswith("افزودن عضو"):
            # اگر آرگومان هم دارد، مستقیم اجرا کن؛ اگر ندارد، وارد کانورسیشن شو
            rest = text[len("افزودن عضو"):].strip()
            if rest:
                context.args = rest.split()
                # emulate /add_member <ref>
                if len(context.args) == 1:
                    await sa_add_member_ref(cfg, update, context)
                else:
                    await msg.reply_text("فرمت: افزودن عضو 123  یا  افزودن عضو @username")
            else:
                await sa_add_member_start(cfg, update, context)
            return

        if text.startswith("حذف عضو"):
            rest = text[len("حذف عضو"):].strip()
            if rest:
                fake = Update(update.update_id, message=msg)
                fake.effective_chat = update.effective_chat
                fake.effective_user = update.effective_user
                msg.text = rest  # type: ignore
                await sa_remove_member_id(cfg, update, context)
            else:
                await sa_remove_member_start(cfg, update, context)
            return

        if text.startswith("بن"):
            rest = text[len("بن"):].strip()
            if rest:
                msg.text = rest  # type: ignore
                await sa_ban_id(cfg, update, context)
            else:
                await sa_ban_start(cfg, update, context)
            return

        if text.startswith("آنبن"):
            rest = text[len("آنبن"):].strip()
            if rest:
                msg.text = rest  # type: ignore
                await sa_unban_id(cfg, update, context)
            else:
                await sa_unban_start(cfg, update, context)
            return

        if text.startswith("افزودن گروه"):
            rest = text[len("افزودن گروه"):].strip()
            if rest:
                msg.text = rest  # type: ignore
                await sa_add_chat_id(cfg, update, context)
            else:
                await sa_add_chat_start(cfg, update, context)
            return

        if text.startswith("حذف گروه"):
            rest = text[len("حذف گروه"):].strip()
            if rest:
                msg.text = rest  # type: ignore
                await sa_remove_chat_id(cfg, update, context)
            else:
                await sa_remove_chat_start(cfg, update, context)
            return

        if text == "لیست اعضا":
            await sa_list_members(cfg, update, context)
            return

        if text == "لیست گروه‌ها":
            await sa_list_chats(cfg, update, context)
            return

    # MG: owner text commands (no slash)
    if await mg_owner_guard(cfg, update):
        if text in ("پنل", "panel"):
            await cmd_panel(cfg, update, context)
            return
        if text in ("راهنما", "help"):
            await msg.reply_text(help_for_mg_owner())
            return
        if text == "افزودن زیرگروه":
            await mg_add_group_start(cfg, update, context)
            return
        if text == "لیست زیرگروه‌ها":
            await mg_list_groups(cfg, update, context)
            return
        if text.startswith("حالت افزودن"):
            rest = text[len("حالت افزودن"):].strip().lower()
            await mg_set_addmode(cfg, update, context, rest)
            return
        if text == "لغو":
            await msg.reply_text("لغو شد.")
            return


# ----------------------------
# Events: joins / chat members / seen
# ----------------------------
async def on_new_members_message(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_db_ready(cfg):
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
    if not is_db_ready(cfg):
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


async def on_any_message_seen(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # PV را کامل رد کن
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return
    if chat.type == ChatType.PRIVATE:
        return
    if not is_db_ready(cfg):
        return

    if not await asyncio.to_thread(is_protected_chat, cfg.database_url, chat.id):
        return
    await asyncio.to_thread(mark_seen, cfg.database_url, chat.id, user.id)


# ----------------------------
# Periodic enforcement
# ----------------------------
async def periodic_enforce(cfg: Config, context: ContextTypes.DEFAULT_TYPE):
    if not is_db_ready(cfg):
        return

    bot = context.bot
    chats = await asyncio.to_thread(list_protected_chats, cfg.database_url)

    for chat_id in chats:
        try:
            admins = await bot.get_chat_administrators(chat_id)
            admin_ids = {a.user.id for a in admins}

            seen = await asyncio.to_thread(get_seen_users, cfg.database_url, chat_id, 5000)

            for user_id in seen:
                if user_id in admin_ids:
                    continue

                should_ban = await asyncio.to_thread(is_globally_banned, cfg.database_url, user_id) or (
                    not await asyncio.to_thread(is_allowed_member, cfg.database_url, user_id)
                )
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
                    log.warning("periodic ban failed chat=%s user=%s err=%s", chat_id, user_id, e)

        except Exception as e:
            log.warning("periodic scan failed chat=%s err=%s", chat_id, e)


# ----------------------------
# Error handler
# ----------------------------
async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.exception("Unhandled error: %s", context.error)
    # اگر خواستی، اینجا بعداً به گروه اصلی گزارش می‌دهیم.


# ----------------------------
# Webhook server (server mode)
# ----------------------------
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


def run_local_polling(app: Application) -> None:
    log.info("Starting in LOCAL mode (polling)")
    app.run_polling(drop_pending_updates=True)


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


# ----------------------------
# Build Application
# ----------------------------
def build_application(cfg: Config) -> Application:
    # افزایش timeout برای Render/شبکه‌های کند
    request = HTTPXRequest(
        connect_timeout=30,
        read_timeout=30,
        write_timeout=30,
        pool_timeout=30,
    )

    app = Application.builder().token(cfg.bot_token).request(request).build()

    # Error handler
    app.add_error_handler(on_error)

    # Persian text router (بدون اسلش)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: on_farsi_text(cfg, u, c)), group=0)

    # Buttons
    app.add_handler(CallbackQueryHandler(lambda u, c: on_callback(cfg, u, c)), group=1)

    # Panel / start / help
    app.add_handler(CommandHandler("start", lambda u, c: cmd_start(cfg, u, c)))
    app.add_handler(CommandHandler("help", lambda u, c: cmd_start(cfg, u, c)))
    app.add_handler(CommandHandler("panel", lambda u, c: cmd_panel(cfg, u, c)))

    # --- Super admin conversations (PV) ---
    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("set_mg", lambda u, c: sa_set_mg_start(cfg, u, c))],
            states={
                SA_SET_MG_CHAT: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: sa_set_mg_chat(cfg, u, c))],
                SA_SET_MG_OWNER: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: sa_set_mg_owner(cfg, u, c))],
            },
            fallbacks=[CommandHandler("cancel", lambda u, c: ConversationHandler.END)],
            name="sa_set_mg_conv",
            persistent=False,
        )
    )

    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("add_member", lambda u, c: sa_add_member_start(cfg, u, c))],
            states={SA_ADD_MEMBER_REF: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: sa_add_member_ref(cfg, u, c))]},
            fallbacks=[CommandHandler("cancel", lambda u, c: ConversationHandler.END)],
            name="sa_add_member_conv",
            persistent=False,
        )
    )

    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("remove_member", lambda u, c: sa_remove_member_start(cfg, u, c))],
            states={SA_REMOVE_MEMBER_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: sa_remove_member_id(cfg, u, c))]},
            fallbacks=[CommandHandler("cancel", lambda u, c: ConversationHandler.END)],
            name="sa_remove_member_conv",
            persistent=False,
        )
    )

    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("ban", lambda u, c: sa_ban_start(cfg, u, c))],
            states={SA_BAN_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: sa_ban_id(cfg, u, c))]},
            fallbacks=[CommandHandler("cancel", lambda u, c: ConversationHandler.END)],
            name="sa_ban_conv",
            persistent=False,
        )
    )

    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("unban", lambda u, c: sa_unban_start(cfg, u, c))],
            states={SA_UNBAN_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: sa_unban_id(cfg, u, c))]},
            fallbacks=[CommandHandler("cancel", lambda u, c: ConversationHandler.END)],
            name="sa_unban_conv",
            persistent=False,
        )
    )

    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("add_chat", lambda u, c: sa_add_chat_start(cfg, u, c))],
            states={SA_ADD_CHAT_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: sa_add_chat_id(cfg, u, c))]},
            fallbacks=[CommandHandler("cancel", lambda u, c: ConversationHandler.END)],
            name="sa_add_chat_conv",
            persistent=False,
        )
    )

    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("remove_chat", lambda u, c: sa_remove_chat_start(cfg, u, c))],
            states={SA_REMOVE_CHAT_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: sa_remove_chat_id(cfg, u, c))]},
            fallbacks=[CommandHandler("cancel", lambda u, c: ConversationHandler.END)],
            name="sa_remove_chat_conv",
            persistent=False,
        )
    )

    app.add_handler(CommandHandler("list_members", lambda u, c: sa_list_members(cfg, u, c)))
    app.add_handler(CommandHandler("list_chats", lambda u, c: sa_list_chats(cfg, u, c)))

    # --- MG owner conversations (inside mg) ---
    app.add_handler(
        ConversationHandler(
            entry_points=[CommandHandler("add_group", lambda u, c: mg_add_group_start(cfg, u, c))],
            states={MG_ADD_GROUP_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: mg_add_group_id(cfg, u, c))]},
            fallbacks=[CommandHandler("cancel", lambda u, c: ConversationHandler.END)],
            name="mg_add_group_conv",
            persistent=False,
        )
    )
    app.add_handler(CommandHandler("list_groups", lambda u, c: mg_list_groups(cfg, u, c)))
    app.add_handler(CommandHandler("addmode", lambda u, c: mg_set_addmode(cfg, u, c, (c.args[0] if c.args else ""))))

    # Join detection
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, lambda u, c: on_new_members_message(cfg, u, c)))
    app.add_handler(ChatMemberHandler(lambda u, c: on_chat_member(cfg, u, c), ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(ChatMemberHandler(lambda u, c: on_chat_member(cfg, u, c), ChatMemberHandler.MY_CHAT_MEMBER))

    # Seen from any messages
    app.add_handler(MessageHandler(filters.ALL & ~filters.StatusUpdate.NEW_CHAT_MEMBERS, lambda u, c: on_any_message_seen(cfg, u, c)))

    async def _post_init(application: Application):
        await init_db(cfg)
        application.job_queue.run_repeating(lambda c: periodic_enforce(cfg, c), interval=60, first=60)

        if cfg.run_mode == "server":
            # cfg.public_base_url مثل: https://xxx.onrender.com
            # cfg.webhook_path مثل: /webhook/SECRET
            webhook_url = f"{cfg.public_base_url}{cfg.webhook_path}"
            await application.bot.set_webhook(url=webhook_url, drop_pending_updates=True)
            log.info("Webhook set: %s", webhook_url)

    app.post_init = _post_init
    return app
