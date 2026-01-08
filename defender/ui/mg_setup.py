from telegram import InlineKeyboardButton, InlineKeyboardMarkup


def kb_mg_after_register() -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton("ثبت اونر (داخل همین گروه بنویس)", callback_data="sa:noop")],
    ]
    return InlineKeyboardMarkup(rows)