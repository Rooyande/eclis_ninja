from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from telegram import Update
from telegram.constants import ChatType
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from telegram.request import HTTPXRequest

from config import Config

from defender.db.repo.core import (
    add_protected_chat,
    add_global_ban,
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

from defender.db.repo.management import (
    init_management_schema,
    set_management_group,
    get_management_group_owner,
    add_subgroup,
    list_subgroups,
    set_add_member_mode,
    get_add_member_mode,
    # optional (recommended):
    # remove_management_group,
    # set_root_management_group,
)

from defender.ui.panels import (
    kb_super_admin_panel,
    kb_confirm,
    kb_back_to_super_admin_panel,
)
from defender.ui.pagination import (
    build_members_page,
    build_chats_page,
)
from defender.ui.mg_setup import kb_mg_after_register

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

RAID_WINDOW_SECONDS = 30
RAID_THRESHOLD_JOINS = 10
join_events: dict[int, list[float]] = {}
raid_notified_chats: set[int] = set()

BAN_NOTIFY_COOLDOWN = 30 * 60
_last_notified: dict[tuple[int, int], float] = {}

PENDING_OWNER_KEY = "pending_owner_for_chat"


# ---------- utilities ----------
def pv_only(update: Update) -> bool:
    return bool(update.effective_chat and update.effective_chat.type == ChatType.PRIVATE)


def is_db_ready(cfg: Config) -> bool:
    return bool(cfg.database_url and not cfg.database_url.strip().startswith("<"))


def is_super_admin(cfg: Config, user_id: int) -> bool:
    return user_id in cfg.admin_ids


async def super_admin_guard(cfg: Config, update: Update) -> bool:
    return (
        update.effective_user is not None
        and is_super_admin(cfg, update.effective_user.id)
    )


def normalize_fa(s: str) -> str:
    return (
        (s or "")
        .replace("ي", "ی")
        .replace("ك", "ک")
        .replace("\u200c", " ")
        .strip()
    )


def register_join(chat_id: int) -> int:
    now = time.time()
    q = join_events.setdefault(chat_id, [])
    q.append(now)
    cutoff = now - RAID_WINDOW_SECONDS
    while q and q[0] < cutoff:
        q.pop(0)
    return len(q)


async def init_db(cfg: Config) -> None:
    if not is_db_ready(cfg):
        log.warning("DATABASE_URL invalid -> DB features disabled.")
        return
    await asyncio.to_thread(init_schema, cfg.database_url)
    await asyncio.to_thread(init_management_schema, cfg.database_url)
    log.info("Database init ok.")


# ---------- panel ----------
async def cmd_panel(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        if update.effective_message:
            await update.effective_message.reply_text("دسترسی پنل برای شما فعال نیست.")
        return
    if not pv_only(update):
        if update.effective_message:
            await update.effective_message.reply_text("پنل فقط در PV قابل استفاده است.")
        return
    await update.effective_message.reply_text("پنل سوپرادمین:", reply_markup=kb_super_admin_panel())


async def _return_to_panel_job(context: ContextTypes.DEFAULT_TYPE):
    job = context.job
    if not job:
        return
    chat_id = job.data.get("chat_id")
    msg_id = job.data.get("message_id")
    try:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=msg_id,
            text="پنل سوپرادمین:",
            reply_markup=kb_super_admin_panel(),
        )
    except Exception:
        pass


# ---------- list members / chats (button-driven) ----------
async def show_members_page(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE, page: int):
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return

    members = await asyncio.to_thread(list_allowed_members, cfg.database_url)
    text, kb = build_members_page(members, page)

    if update.callback_query:
        await update.callback_query.edit_message_text(text=text, reply_markup=kb, parse_mode="HTML")
    else:
        await update.effective_message.reply_text(text=text, reply_markup=kb, parse_mode="HTML")

    if members == [] and update.callback_query:
        msg = update.callback_query.message
        if msg:
            context.job_queue.run_once(
                _return_to_panel_job,
                when=10,
                data={"chat_id": msg.chat_id, "message_id": msg.message_id},
            )


async def show_chats_page(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE, page: int):
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return

    chats = await asyncio.to_thread(list_protected_chats, cfg.database_url)
    text, kb = build_chats_page(chats, page)

    if update.callback_query:
        await update.callback_query.edit_message_text(text=text, reply_markup=kb, parse_mode="HTML")
    else:
        await update.effective_message.reply_text(text=text, reply_markup=kb, parse_mode="HTML")

    if chats == [] and update.callback_query:
        msg = update.callback_query.message
        if msg:
            context.job_queue.run_once(
                _return_to_panel_job,
                when=10,
                data={"chat_id": msg.chat_id, "message_id": msg.message_id},
            )


# ---------- owner capture flow ----------
async def request_mg_owner_id(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await super_admin_guard(cfg, update):
        return
    if not is_db_ready(cfg):
        await update.effective_message.reply_text("DATABASE_URL تنظیم نیست.")
        return

    chat = update.effective_chat
    if not chat or chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        await update.effective_message.reply_text("این دستور فقط داخل گروه قابل استفاده است.")
        return

    context.user_data[PENDING_OWNER_KEY] = chat.id
    await update.effective_message.reply_text("آیدی عددی اونر را بفرست (owner_user_id).")


async def on_text_set_owner(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if PENDING_OWNER_KEY not in context.user_data:
        return
    if not await super_admin_guard(cfg, update):
        return
    if not is_db_ready(cfg):
        return

    msg = update.effective_message
    if not msg or not msg.text:
        return

    text = normalize_fa(msg.text)
    if not text.isdigit():
        await msg.reply_text("فقط عدد. دوباره بفرست.")
        return

    mg_chat_id = int(context.user_data[PENDING_OWNER_KEY])
    owner_id = int(text)

    await asyncio.to_thread(set_management_group, cfg.database_url, mg_chat_id, owner_id)
    context.user_data.pop(PENDING_OWNER_KEY, None)

    await msg.reply_text(f"✅ اونر ثبت شد.\nmg: {mg_chat_id}\nowner: {owner_id}")


# ---------- callbacks (PV panel) ----------
async def on_callback(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if not q:
        return
    await q.answer()
    data = q.data or ""

    # back to panel
    if data == "sa:panel":
        await q.edit_message_text("پنل سوپرادمین:", reply_markup=kb_super_admin_panel())
        return

    # panel access
    if not (pv_only(update) and update.effective_user and is_super_admin(cfg, update.effective_user.id)):
        await q.edit_message_text("دسترسی ندارید.")
        return

    # paginated lists
    if data.startswith("sa:list_members:"):
        page = int(data.split(":")[-1])
        await show_members_page(cfg, update, context, page)
        return

    if data.startswith("sa:list_chats:"):
        page = int(data.split(":")[-1])
        await show_chats_page(cfg, update, context, page)
        return

    # member item click
    if data.startswith("sa:member:"):
        _, _, uid, _page = data.split(":")
        await q.edit_message_text(
            text=f"آیدی کاربر: <code>{uid}</code>",
            reply_markup=kb_back_to_super_admin_panel(),
            parse_mode="HTML",
        )
        return

    # guidance buttons
    if data == "sa:mg_register_here":
        await q.edit_message_text(
            "برای ثبت MG باید داخل همان گروه اجرا شود.\n"
            "داخل گروه مورد نظر بنویس:\n"
            "ثبت گروه مدیریتی",
            reply_markup=kb_back_to_super_admin_panel(),
        )
        return

    if data == "sa:mg_remove_here":
        await q.edit_message_text(
            "برای حذف MG باید داخل همان گروه اجرا شود.\n"
            "داخل گروه مورد نظر بنویس:\n"
            "حذف گروه مدیریتی",
            reply_markup=kb_back_to_super_admin_panel(),
        )
        return

    if data == "sa:root_mg_register_here":
        await q.edit_message_text(
            "برای ثبت MG اکلیس باید داخل همان گروه اصلی اجرا شود.\n"
            "داخل گروه اصلی بنویس:\n"
            "ثبت گروه مدیریتی اکلیس",
            reply_markup=kb_back_to_super_admin_panel(),
        )
        return

    # other actions (still slash-based for now)
    if data in ("sa:add_member", "sa:remove_member", "sa:ban", "sa:unban", "sa:add_chat", "sa:remove_chat"):
        await q.edit_message_text(
            "فعلاً این مورد را با دستور اسلشی در PV اجرا کن.\n"
            f"مثال: /{data.replace('sa:', '')}",
            reply_markup=kb_back_to_super_admin_panel(),
        )
        return


# ---------- farsi text router (group actions) ----------
async def on_farsi_text(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg or not msg.text:
        return

    text = normalize_fa(msg.text)

    # PV: panel command
    if pv_only(update) and update.effective_user and is_super_admin(cfg, update.effective_user.id):
        if text == "پنل":
            await cmd_panel(cfg, update, context)
            return

    # Group: MG actions
    chat = update.effective_chat
    if chat and chat.type in (ChatType.GROUP, ChatType.SUPERGROUP):
        if not await super_admin_guard(cfg, update):
            return

        if text == "ثبت گروه مدیریتی":
            await msg.reply_text(
                "آیا مطمئنی این گروه به عنوان گروه مدیریتی ثبت شود؟",
                reply_markup=kb_confirm("mg_register_here"),
            )
            return

        if text == "حذف گروه مدیریتی":
            await msg.reply_text(
                "آیا مطمئنی این گروه از حالت مدیریتی حذف شود؟",
                reply_markup=kb_confirm("mg_remove_here"),
            )
            return

        if text == "ثبت گروه مدیریتی اکلیس":
            await msg.reply_text(
                "آیا مطمئنی این گروه به عنوان گروه مدیریتی اکلیس (گروه اصلی) ثبت شود؟",
                reply_markup=kb_confirm("root_mg_register_here"),
            )
            return

        if text == "ثبت اونر":
            await request_mg_owner_id(cfg, update, context)
            return


# ---------- confirm callbacks (inside group) ----------
async def on_confirm_callback(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if not q:
        return
    await q.answer()
    data = q.data or ""
    if not data.startswith("sa:confirm:"):
        return

    # only super admin
    if not (update.effective_user and is_super_admin(cfg, update.effective_user.id)):
        await q.edit_message_text("دسترسی ندارید.")
        return

    parts = data.split(":")
    if len(parts) != 4:
        await q.edit_message_text("خطا: callback نامعتبر.")
        return

    _, _, tag, choice = parts
    if choice == "no":
        await q.edit_message_text("لغو شد.")
        return

    if not is_db_ready(cfg):
        await q.edit_message_text("DATABASE_URL تنظیم نیست.")
        return

    chat = update.effective_chat
    if not chat:
        await q.edit_message_text("خطا: chat پیدا نشد.")
        return

    if tag == "mg_register_here":
        # create record (owner temporary = super admin)
        await asyncio.to_thread(set_management_group, cfg.database_url, chat.id, update.effective_user.id)
        await q.edit_message_text(
            f"✅ این گروه به عنوان MG ثبت شد.\nchat_id: {chat.id}\n\n"
            "برای ثبت اونر واقعی، در همین گروه بنویس: «ثبت اونر»",
            reply_markup=kb_mg_after_register(),
        )
        return

    if tag == "mg_remove_here":
        try:
            from defender.db.repo.management import remove_management_group
        except Exception:
            await q.edit_message_text("تابع remove_management_group در management.py وجود ندارد. باید اضافه شود.")
            return

        await asyncio.to_thread(remove_management_group, cfg.database_url, chat.id)
        await q.edit_message_text("✅ این گروه از حالت MG حذف شد.")
        return

    if tag == "root_mg_register_here":
        try:
            from defender.db.repo.management import set_root_management_group
        except Exception:
            await q.edit_message_text("تابع set_root_management_group در management.py وجود ندارد. باید اضافه شود.")
            return

        await asyncio.to_thread(set_root_management_group, cfg.database_url, chat.id)
        await q.edit_message_text(f"✅ گروه مدیریتی اکلیس ثبت شد.\nchat_id: {chat.id}")
        return


# ---------- events ----------
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
        try:
            await asyncio.to_thread(mark_seen, cfg.database_url, chat_id, u.id)

            if await asyncio.to_thread(is_globally_banned, cfg.database_url, u.id):
                await context.bot.ban_chat_member(chat_id, u.id)
                continue

            if not await asyncio.to_thread(is_allowed_member, cfg.database_url, u.id):
                await context.bot.ban_chat_member(chat_id, u.id)
                await asyncio.to_thread(log_join_event, cfg.database_url, chat_id, None, u.id, None, None, None, "banned")
        except Exception:
            pass


async def on_any_message_seen(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
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

                should_ban = (
                    await asyncio.to_thread(is_globally_banned, cfg.database_url, user_id)
                    or (not await asyncio.to_thread(is_allowed_member, cfg.database_url, user_id))
                )
                if not should_ban:
                    continue

                try:
                    await bot.ban_chat_member(chat_id, user_id)
                except Exception:
                    pass
        except Exception:
            pass


# ---------- minimal webhook server (server mode) ----------
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
    log.info("Listening on 0.0.0.0:%s (health / , webhook %s)", cfg.port, cfg.webhook_path)

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


def build_application(cfg: Config) -> Application:
    # جلوگیری از تایم‌اوت‌های getMe در استارت
    request = HTTPXRequest(connect_timeout=30, read_timeout=30, write_timeout=30, pool_timeout=30)
    app = Application.builder().token(cfg.bot_token).request(request).build()

    # callbacks
    app.add_handler(CallbackQueryHandler(lambda u, c: on_confirm_callback(cfg, u, c)), group=0)
    app.add_handler(CallbackQueryHandler(lambda u, c: on_callback(cfg, u, c)), group=1)

    # text routers
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: on_farsi_text(cfg, u, c)), group=2)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: on_text_set_owner(cfg, u, c)), group=3)

    # commands
    app.add_handler(CommandHandler("panel", lambda u, c: cmd_panel(cfg, u, c)))

    # events
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, lambda u, c: on_new_members_message(cfg, u, c)))
    app.add_handler(MessageHandler(filters.ALL & ~filters.StatusUpdate.NEW_CHAT_MEMBERS, lambda u, c: on_any_message_seen(cfg, u, c)))

    async def _post_init(application: Application):
        await init_db(cfg)
        application.job_queue.run_repeating(lambda c: periodic_enforce(cfg, c), interval=60, first=60)

        if cfg.run_mode == "server":
            webhook_url = f"{cfg.public_base_url}{cfg.webhook_path}"
            await application.bot.set_webhook(url=webhook_url, drop_pending_updates=True)
            log.info("Webhook set: %s", webhook_url)

    app.post_init = _post_init
    return app
