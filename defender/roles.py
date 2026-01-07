import asyncio
from telegram import Update
from telegram.ext import ContextTypes
from config import Config
from defender.db.repo.management import get_management_group_owner

def is_superadmin(cfg: Config, user_id: int) -> bool:
    return user_id in cfg.admin_ids

async def get_role(cfg: Config, update: Update) -> str:
    user = update.effective_user
    chat = update.effective_chat
    if not user or not chat:
        return "guest"

    if is_superadmin(cfg, user.id):
        return "superadmin"

    # mg_owner فقط داخل گروه (group/supergroup)
    if chat.type in ("group", "supergroup") and cfg.database_url:
        owner = await asyncio.to_thread(get_management_group_owner, cfg.database_url, chat.id)
        if owner == user.id:
            return "mg_owner"

    return "guest"
