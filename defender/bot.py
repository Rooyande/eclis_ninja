from __future__ import annotations

import asyncio
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from config import Config
from defender.handlers.panel import cmd_panel, on_panel_callback
from defender.handlers.help import cmd_help
from defender.handlers.farsi import on_farsi_text
from defender.db.repo.core import init_schema
from defender.db.repo.management import init_management_schema

logging.basicConfig(level=logging.INFO)

async def init_db(cfg: Config) -> None:
    if not cfg.database_url:
        logging.warning("DATABASE_URL is empty. DB features disabled.")
        return
    await asyncio.to_thread(init_schema, cfg.database_url)
    await asyncio.to_thread(init_management_schema, cfg.database_url)
    logging.info("Database init ok.")

def build_application(cfg: Config) -> Application:
    app = Application.builder().token(cfg.bot_token).build()

    # فارسی بدون اسلش
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, lambda u, c: on_farsi_text(cfg, u, c)), group=0)

    # دستورات اصلی
    app.add_handler(CommandHandler("help", lambda u, c: cmd_help(cfg, u, c)))
    app.add_handler(CommandHandler("panel", lambda u, c: cmd_panel(cfg, u, c)))

    # callback دکمه‌ها
    app.add_handler(CallbackQueryHandler(lambda u, c: on_panel_callback(cfg, u, c), pattern=r"^panel:"))

    async def _post_init(application: Application):
        await init_db(cfg)
        if cfg.run_mode == "server":
            webhook_url = f"{cfg.public_base_url}{cfg.webhook_path}"
            await application.bot.set_webhook(url=webhook_url, drop_pending_updates=True)
            logging.info(f"Webhook set: {webhook_url}")

    app.post_init = _post_init
    return app

def run_local_polling(app: Application) -> None:
    logging.info("Starting in LOCAL mode (polling)")
    app.run_polling(drop_pending_updates=True)

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
