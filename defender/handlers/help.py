import asyncio
from telegram import Update
from telegram.ext import ContextTypes
from config import Config
from defender.roles import get_role

HELP_SUPERADMIN = (
    "دسترسی شما: مالک اصلی بات\n\n"
    "پنل (دکمه‌ای): پنل /panel\n"
    "ثبت MG: /set_mg یا از پنل\n"
)

HELP_MG_OWNER = (
    "دسترسی شما: مالک گروه مدیریتی\n\n"
    "پنل (دکمه‌ای): پنل /panel\n"
    "افزودن زیرگروه: /add_group یا از پنل\n"
    "بن/آنبن سراسری (روی زیرگروه‌های همین MG)\n"
)

HELP_GUEST = "شما دسترسی ندارید."

async def cmd_help(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    role = await get_role(cfg, update)
    if role == "superadmin":
        txt = HELP_SUPERADMIN
    elif role == "mg_owner":
        txt = HELP_MG_OWNER
    else:
        txt = HELP_GUEST

    if update.effective_message:
        await update.effective_message.reply_text(txt)
