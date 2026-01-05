import logging
import sys
import asyncio

# Fix for Python 3.14+ where there's no default current event loop in MainThread
if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())



from config import Config
from defender.bot import build_application, run_local_polling, run_server_webhook
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO)


def main() -> None:
    cfg = Config()
    app = build_application(cfg)

    if cfg.run_mode == "local":
        run_local_polling(app)
    else:
        run_server_webhook(app, cfg)


if __name__ == "__main__":
    main()
