Windows Local Run (Base Setup)

0) Install Python
- Install Python 3.11+ from python.org (recommended) and enable "Add Python to PATH".
  Or install from Microsoft Store.

1) Open CMD in the project folder
Example:
  cd C:\Users\Aki\Desktop\defender

2) Create and activate venv
If python works:
  python -m venv .venv
If only the Python Launcher works:
  py -m venv .venv
Then:
  .venv\Scripts\activate

3) Install dependencies
  pip install -r requirements.txt

4) Start PostgreSQL (recommended: Docker)
If you have Docker Desktop:
  docker compose up -d

5) Create .env
Copy .env.example to .env and fill BOT_TOKEN and ADMINS.
Example:
  copy .env.example .env

6) Run the bot in local mode (polling)
  set RUN_MODE=local
  python app.py

7) Quick commands (PV to bot)
/start
/add_chat <chat_id>
/add_member <user_id> or /add_member @username
/list_members
/list_chats

Notes:
- For /add_member @username: the user must have a public username and Telegram must allow resolving it.
- The bot stores & bans by numeric user_id (stable), while keeping last known username for admins.
