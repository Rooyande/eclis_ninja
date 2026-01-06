from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from telegram import Update
from telegram.ext import (
    Application,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from config import Config
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

logging.basicConfig(level=logging.INFO)

# ---------------- UX strings ----------------
USAGE = (
    "Commands (PV only):\n"
    "/add_member <user_id|@username>\n"
    "/remove_member <user_id>\n"
    "/unban <user_id>\n"
    "/add_chat <chat_id>\n"
    "/remove_chat <chat_id>\n"
    "/list_members\n"
    "/list_chats\n"
    "\n"
    "دستورهای فارسی (بدون اسلش) در PV:\n"
    "شروع\n"
    "راهنما\n"
    "افزودن عضو <user_id|@username>\n"
    "حذف عضو <user_id>\n"
    "آنبن <user_id>\n"
    "افزودن گروه <chat_id>\n"
    "حذف گروه <chat_id>\n"
    "لیست اعضا\n"
    "لیست گروه‌ها\n"
)

# ---------------- anti-raid settings ----------------
RAID_WINDOW_SECONDS = 30
RAID_THRESHOLD_JOINS = 10
join_events: dict[int, list[float]] = {}
raid_notified_chats: set[int] = set()

BAN_NOTIFY_COOLDOWN = 30 * 60  # 30 min
_last_notified: dict[tuple[int, int], float] = {}  # (chat_id,user_id)->ts


# ---------------- guards ----------------
def pv_only(update: Update) -> bool:
    return update.effective_chat is not None and update.effective_chat.type == "private"


def is_admin(cfg: Config, user_id: int) -> bool:
    return user_id in cfg.admin_ids


async def admin_guard(cfg: Config, update: Update) -> bool:
    return pv_only(update) and update.effective_user is not None and is_admin(cfg, update.effective_user.id)


# ---------------- join tracking ----------------
def register_join(chat_id: int) -> int:
    now = time.time()
    q = join_events.setdefault(chat_id, [])
    q.append(now)
    cutoff = now - RAID_WINDOW_SECONDS
    while q and q[0] < cutoff:
        q.pop(0)
    return len(q)


# ---------------- helpers ----------------
async def init_db(cfg: Config) -> None:
    if not cfg.database_url or cfg.database_url.strip().startswith("<"):
        logging.warning("DATABASE_URL is not set/invalid. DB features disabled.")
        return
    await asyncio.to_thread(init_schema, cfg.database_url)
    logging.info("Database init ok.")



def normalize_fa(s: str) -> str:
    return (
        s.replace("ي", "ی")
        .replace("ك", "ک")
        .replace("\u200c", " ")
        .strip()
    )


def parse_fa_command(text: str) -> tuple[str, list[str]] | None:
    """
    فارسی بدون اسلش:
      شروع
      راهنما
      افزودن عضو 123 / افزودن عضو @username
      حذف عضو 123
      آنبن 123
      افزودن گروه -100...
      حذف گروه -100...
      لیست اعضا
      لیست گروه‌ها
    """
    t = normalize_fa(text)

    fa_map = {
        "شروع": "start",
        "راهنما": "help",
        "افزودن عضو": "add_member",
        "حذف عضو": "remove_member",
        "آنبن": "unban",
        "افزودن گروه": "add_chat",
        "حذف گروه": "remove_chat",
        "لیست اعضا": "list_members",
        "لیست گروه‌ها": "list_chats",
    }

    # exact commands (no args)
    if t in ("شروع", "راهنما", "لیست اعضا", "لیست گروه‌ها"):
        return fa_map[t], []

    # commands with args
    for phrase, key in fa_map.items():
        if t.startswith(phrase + " "):
            rest = t[len(phrase):].strip()
            args = rest.split() if rest else []
            return key, args

    return None


async def resolve_user_ref(
    cfg: Config,
    context: ContextTypes.DEFAULT_TYPE,
    ref: str
) -> tuple[int, str | None, str | None, str | None]:
    """Resolve a user reference to numeric user_id.

    Supports:
      - numeric user_id
      - @username  (requires the user to have a public username)
    Returns: (user_id, username, first_name, last_name)
    """
    ref = ref.strip()
    if ref.isdigit():
        return int(ref), None, None, None

    if ref.startswith("@"):
        chat = await context.bot.get_chat(ref)
        user = chat
        return int(user.id), getattr(user, "username", None), getattr(user, "first_name", None), getattr(user, "last_name", None)

    raise ValueError("bad_ref")


async def enforce_user(cfg: Config, context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int, reason: str):
    if user_id == context.bot.id:
        return

    await asyncio.to_thread(mark_seen, cfg.database_url, chat_id, user_id)

    try:
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

            for admin_id in cfg.admin_ids:
                try:
                    await context.bot.send_message(admin_id, f"⛔️ BAN ({reason})\nuser: {user_id}\nchat: {chat_id}")
                except Exception:
                    pass

            await asyncio.to_thread(log_join_event, cfg.database_url, chat_id, None, user_id, None, None, None, "banned")

    except Exception as e:
        logging.warning(f"enforce failed reason={reason} chat={chat_id} user={user_id} err={e}")


# ---------------- commands ----------------
async def cmd_start(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not pv_only(update):
        return
    if update.effective_user is None or not is_admin(cfg, update.effective_user.id):
        await update.effective_message.reply_text("این بات فقط برای ادمین‌هاست.")
        return
    await update.effective_message.reply_text(USAGE)


async def cmd_add_member(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(cfg, update):
        return
    if not context.args or len(context.args) != 1:
        await update.effective_message.reply_text(USAGE)
        return

    ref = context.args[0]
    try:
        user_id, username, first_name, last_name = await resolve_user_ref(cfg, context, ref)
    except Exception:
        await update.effective_message.reply_text("ورودی نامعتبر است. مثال: /add_member 123456 یا /add_member @username")
        return

    await asyncio.to_thread(upsert_allowed_member, cfg.database_url, user_id, username, first_name, last_name)
    await update.effective_message.reply_text(f"user {user_id} added. username={('@'+username) if username else 'N/A'}")


async def cmd_remove_member(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(cfg, update):
        return
    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        await update.effective_message.reply_text("Usage: /remove_member <user_id>")
        return

    target = int(context.args[0])

    await asyncio.to_thread(remove_allowed_member, cfg.database_url, target)
    await asyncio.to_thread(add_global_ban, cfg.database_url, target)

    chats = await asyncio.to_thread(list_protected_chats, cfg.database_url)
    for chat_id in chats:
        try:
            await context.bot.ban_chat_member(chat_id=chat_id, user_id=target)
        except Exception as e:
            logging.warning(f"ban failed user={target} chat={chat_id} err={e}")

    await update.effective_message.reply_text(f"user {target} removed & global banned.")


async def cmd_unban(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(cfg, update):
        return
    if not context.args or len(context.args) != 1 or not context.args[0].isdigit():
        await update.effective_message.reply_text("Usage: /unban <user_id>")
        return

    target = int(context.args[0])

    await asyncio.to_thread(remove_global_ban, cfg.database_url, target)
    await asyncio.to_thread(upsert_allowed_member, cfg.database_url, target, None, None, None)

    chats = await asyncio.to_thread(list_protected_chats, cfg.database_url)
    ok, fail = [], []
    for chat_id in chats:
        try:
            await context.bot.unban_chat_member(chat_id=chat_id, user_id=target, only_if_banned=False)
            ok.append(chat_id)
        except Exception as e:
            logging.warning(f"unban failed user={target} chat={chat_id} err={e}")
            fail.append(chat_id)

    for chat_id in ok:
        _last_notified.pop((chat_id, target), None)

    await update.effective_message.reply_text(
        f"✅ unban done for {target}\n"
        f"unbanned in:\n" + ("\n".join(map(str, ok)) if ok else "none") + (f"\n\nfailed:\n" + "\n".join(map(str, fail)) if fail else "")
    )


async def cmd_add_chat(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(cfg, update):
        return
    if not context.args or len(context.args) != 1 or not context.args[0].lstrip("-").isdigit():
        await update.effective_message.reply_text("Usage: /add_chat <chat_id>")
        return

    chat_id = int(context.args[0])
    await asyncio.to_thread(add_protected_chat, cfg.database_url, chat_id)
    await update.effective_message.reply_text(f"chat {chat_id} protected.")


async def cmd_remove_chat(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(cfg, update):
        return
    if not context.args or len(context.args) != 1 or not context.args[0].lstrip("-").isdigit():
        await update.effective_message.reply_text("Usage: /remove_chat <chat_id>")
        return

    chat_id = int(context.args[0])
    await asyncio.to_thread(remove_protected_chat, cfg.database_url, chat_id)
    await update.effective_message.reply_text(f"chat {chat_id} removed from protection.")


async def cmd_list_members(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(cfg, update):
        return

    members = await asyncio.to_thread(list_allowed_members, cfg.database_url)
    if not members:
        await update.effective_message.reply_text("هیچ عضو مجازی ثبت نشده.")
        return

    lines = []
    for uid, uname in members:
        lines.append(f"{uid}  {('@'+uname) if uname else ''}".rstrip())
    await update.effective_message.reply_text("لیست اعضای مجاز:\n" + "\n".join(lines))


async def cmd_list_chats(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(cfg, update):
        return

    chats = await asyncio.to_thread(list_protected_chats, cfg.database_url)
    if not chats:
        await update.effective_message.reply_text("هیچ گروه محافظت‌شده‌ای ثبت نشده.")
        return

    await update.effective_message.reply_text("لیست گروه‌های محافظت‌شده:\n" + "\n".join(map(str, chats)))


# ---------------- Persian text router ----------------
async def on_fa_text_command(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    # فقط PV و فقط ادمین
    if not pv_only(update):
        return
    if update.effective_user is None or not is_admin(cfg, update.effective_user.id):
        return
    msg = update.effective_message
    if msg is None or msg.text is None:
        return

    parsed = parse_fa_command(msg.text)
    if not parsed:
        return

    key, args = parsed

    # emulate context.args
    old_args = getattr(context, "args", None)
    context.args = args
    try:
        if key in ("start", "help"):
            await cmd_start(cfg, update, context)
        elif key == "add_member":
            await cmd_add_member(cfg, update, context)
        elif key == "remove_member":
            await cmd_remove_member(cfg, update, context)
        elif key == "unban":
            await cmd_unban(cfg, update, context)
        elif key == "add_chat":
            await cmd_add_chat(cfg, update, context)
        elif key == "remove_chat":
            await cmd_remove_chat(cfg, update, context)
        elif key == "list_members":
            await cmd_list_members(cfg, update, context)
        elif key == "list_chats":
            await cmd_list_chats(cfg, update, context)
    finally:
        context.args = old_args


# ---------------- event handlers ----------------
async def on_new_members_message(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
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
    chat = update.effective_chat
    user = update.effective_user
    if not chat or not user:
        return

    # مهم: PV را کامل رد کن (برای تست فرمان‌های فارسی و جلوگیری از DB-call)
    if chat.type == "private":
        return

    # اگر DB نداریم/خراب است، این بخش را غیرفعال کن
    if not cfg.database_url or cfg.database_url.strip().startswith("<"):
        return


# ---------------- periodic enforcement ----------------
async def periodic_enforce(cfg: Config, context: ContextTypes.DEFAULT_TYPE):
    if not cfg.database_url or cfg.database_url.strip().startswith("<"):
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
    app = Application.builder().token(cfg.bot_token).build()

    # Persian text commands (PV, admin only) - should be early
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: on_fa_text_command(cfg, u, c)), group=0)

    # commands (PV)
    app.add_handler(CommandHandler("start", lambda u, c: cmd_start(cfg, u, c)))
    app.add_handler(CommandHandler("help", lambda u, c: cmd_start(cfg, u, c)))
    app.add_handler(CommandHandler("add_member", lambda u, c: cmd_add_member(cfg, u, c)))
    app.add_handler(CommandHandler("remove_member", lambda u, c: cmd_remove_member(cfg, u, c)))
    app.add_handler(CommandHandler("unban", lambda u, c: cmd_unban(cfg, u, c)))
    app.add_handler(CommandHandler("add_chat", lambda u, c: cmd_add_chat(cfg, u, c)))
    app.add_handler(CommandHandler("remove_chat", lambda u, c: cmd_remove_chat(cfg, u, c)))
    app.add_handler(CommandHandler("list_members", lambda u, c: cmd_list_members(cfg, u, c)))
    app.add_handler(CommandHandler("list_chats", lambda u, c: cmd_list_chats(cfg, u, c)))

    # join detection
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, lambda u, c: on_new_members_message(cfg, u, c)))
    app.add_handler(ChatMemberHandler(lambda u, c: on_chat_member(cfg, u, c), ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(ChatMemberHandler(lambda u, c: on_chat_member(cfg, u, c), ChatMemberHandler.MY_CHAT_MEMBER))

    # seen from any messages
    app.add_handler(MessageHandler(filters.ALL & ~filters.StatusUpdate.NEW_CHAT_MEMBERS, lambda u, c: on_any_message_seen(cfg, u, c)))

    async def _post_init(application: Application):
        await init_db(cfg)
        application.job_queue.run_repeating(lambda c: periodic_enforce(cfg, c), interval=60, first=60)

        if cfg.run_mode == "server":
            webhook_url = f"{cfg.public_base_url}{cfg.webhook_path}"
            await application.bot.set_webhook(url=webhook_url, drop_pending_updates=True)
            logging.info(f"Webhook set: {webhook_url}")

    app.post_init = _post_init
    return app


def run_local_polling(app: Application) -> None:
    """Run the bot locally using long polling."""
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
    """Run the bot on a server using webhook."""
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
    WebhookHandler.webhook_path = cfg.webhook_path

    server = HTTPServer(("0.0.0.0", cfg.port), WebhookHandler)
    logging.info(f"Listening on 0.0.0.0:{cfg.port} (health: / , webhook: {cfg.webhook_path})")

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
