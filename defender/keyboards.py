from telegram import InlineKeyboardButton, InlineKeyboardMarkup

def panel_keyboard(role: str) -> InlineKeyboardMarkup:
    rows = []

    # مشترک برای ownerها
    if role in ("superadmin", "mg_owner"):
        rows += [
            [InlineKeyboardButton("افزودن عضو", callback_data="panel:add_member")],
            [InlineKeyboardButton("حذف عضو", callback_data="panel:remove_member")],
            [InlineKeyboardButton("بن سراسری", callback_data="panel:ban_global")],
            [InlineKeyboardButton("آنبن سراسری", callback_data="panel:unban_global")],
            [InlineKeyboardButton("لیست اعضا", callback_data="panel:list_members")],
            [InlineKeyboardButton("لیست گروه‌ها", callback_data="panel:list_groups")],
            [InlineKeyboardButton("افزودن زیرگروه", callback_data="panel:add_group")],
        ]

    # فقط سوپرادمین
    if role == "superadmin":
        rows = [
            [InlineKeyboardButton("ثبت گروه مدیریتی (MG)", callback_data="panel:set_mg")],
        ] + rows

    rows += [[InlineKeyboardButton("راهنما", callback_data="panel:help")]]

    return InlineKeyboardMarkup(rows)
