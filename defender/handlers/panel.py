import asyncio
from telegram import Update
from telegram.ext import ContextTypes
from config import Config
from defender.roles import get_role
from defender.keyboards import panel_keyboard
from defender.handlers.help import cmd_help

async def cmd_panel(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    role = await get_role(cfg, update)
    if role == "guest":
        if update.effective_message:
            await update.effective_message.reply_text("شما دسترسی ندارید.")
        return

    if update.effective_message:
        await update.effective_message.reply_text("پنل مدیریت:", reply_markup=panel_keyboard(role))

async def on_panel_callback(cfg: Config, update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if not q:
        return
    await q.answer()

    role = await get_role(cfg, update)
    if role == "guest":
        await q.edit_message_text("شما دسترسی ندارید.")
        return

    data = q.data or ""
    if data == "panel:help":
        # کمک را در همان چت بفرست
        fake_update = update
        await cmd_help(cfg, fake_update, context)
        return

    # این‌ها را به ConversationHandlerها وصل می‌کنیم (management/members)
    # اینجا فقط پیام راهنما می‌دهیم که "از دکمه استفاده شد"
    await q.edit_message_text("در حال انجام... (این دکمه به جریان مرحله‌ای وصل می‌شود)")
