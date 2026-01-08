from telegram import InlineKeyboardButton, InlineKeyboardMarkup


def kb_super_admin_panel() -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("لیست اعضا", callback_data="sa:list_members:0")],
        [InlineKeyboardButton("لیست گروه‌ها", callback_data="sa:list_chats:0")],
        [InlineKeyboardButton("ثبت MG (داخل گروه)", callback_data="sa:mg_register_here")],
        [InlineKeyboardButton("حذف MG (داخل گروه)", callback_data="sa:mg_remove_here")],
        [InlineKeyboardButton("ثبت MG اکلیس (داخل گروه)", callback_data="sa:root_mg_register_here")],
    ]
    return InlineKeyboardMarkup(rows)


def kb_back_to_super_admin_panel() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("بازگشت به پنل", callback_data="sa:panel")]])


def kb_confirm(tag: str) -> InlineKeyboardMarkup:
    # tag examples: mg_register_here, mg_remove_here, root_mg_register_here
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("بله", callback_data=f"sa:confirm:{tag}:yes"),
                InlineKeyboardButton("خیر", callback_data=f"sa:confirm:{tag}:no"),
            ]
        ]
    )
