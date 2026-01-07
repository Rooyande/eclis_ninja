from telegram import Update
from telegram.ext import ContextTypes
from config import Config
from defender.handlers.panel import cmd_panel
from defender.handlers.help import cmd_help

def normalize_fa(s: str) -> str:
    return (
        (s or "")
        .replace("ي", "ی")
        .replace("ك", "ک")
        .replace("\u200c", " ")
        .strip()
    )

async def on_farsi_text(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg or not msg.text:
        return

    t = normalize_fa(msg.text)

    if t in ("پنل", "panel"):
        await cmd_panel(cfg, update, context)
    elif t in ("راهنما", "کمک", "help"):
        await cmd_help(cfg, update, context)
