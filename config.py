import os


# config.py
import os

class Config:
    def __init__(self):
        self.run_mode = os.getenv("RUN_MODE", "local").strip().lower()

        self.bot_token = os.getenv("BOT_TOKEN", "").strip()
        if not self.bot_token:
            raise RuntimeError("BOT_TOKEN is not set")

        admins_raw = os.getenv("ADMINS", "").strip()
        self.admin_ids = {int(x.strip()) for x in admins_raw.split(",") if x.strip().isdigit()}

        self.database_url = os.getenv("DATABASE_URL", "").strip()

        # Server/Webhook settings
        self.public_base_url = (
            os.getenv("PUBLIC_BASE_URL", "").strip()
            or os.getenv("RENDER_EXTERNAL_URL", "").strip()
            or os.getenv("WEBHOOK_HOST", "").strip()
        )
        self.webhook_secret = os.getenv("WEBHOOK_SECRET", "").strip()

        # Render sets PORT automatically for web services
        self.port = int(os.getenv("PORT", "10000"))

        if self.run_mode == "server":
            if not self.public_base_url:
                raise RuntimeError(
                    "PUBLIC_BASE_URL (or RENDER_EXTERNAL_URL/WEBHOOK_HOST) is required in server mode"
                )
            if not self.webhook_secret:
                raise RuntimeError("WEBHOOK_SECRET is required in server mode")


    @property
    def webhook_path(self) -> str:
        return f"/bot/{self.bot_token}"

    @property
    def webhook_url(self) -> str:
        if not self.webhook_host:
            return ""
        return self.webhook_host.rstrip("/") + self.webhook_path
