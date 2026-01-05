import os


class Config:
    """Runtime configuration loaded from environment variables.

    RUN_MODE:
      - local  : long polling (best for Windows development)
      - server : webhook + minimal HTTP server

    Notes:
      - In local mode, WEBHOOK_HOST is NOT required.
      - In server mode, WEBHOOK_HOST is required.
    """

    def __init__(self) -> None:
        self.bot_token: str = os.getenv("BOT_TOKEN", "").strip()
        self.database_url: str = os.getenv("DATABASE_URL", "").strip()

        self.run_mode: str = os.getenv("RUN_MODE", "local").strip().lower()
        if self.run_mode not in ("local", "server"):
            raise RuntimeError("RUN_MODE must be 'local' or 'server'")

        # Comma-separated admin user IDs
        admins_env = os.getenv("ADMINS", "").strip()
        self.admin_ids = {int(x) for x in admins_env.split(",") if x.strip().isdigit()}

        # Server-mode only
        self.port: int = int(os.getenv("PORT", "10000"))
        self.webhook_host: str = os.getenv("WEBHOOK_HOST", "").strip()  # e.g. https://your-app.onrender.com

        if not self.bot_token:
            raise RuntimeError("BOT_TOKEN is not set")
        if not self.database_url:
            raise RuntimeError("DATABASE_URL is not set")
        if self.run_mode == "server" and not self.webhook_host:
            raise RuntimeError("WEBHOOK_HOST is required in server mode")

    @property
    def webhook_path(self) -> str:
        return f"/bot/{self.bot_token}"

    @property
    def webhook_url(self) -> str:
        if not self.webhook_host:
            return ""
        return self.webhook_host.rstrip("/") + self.webhook_path
