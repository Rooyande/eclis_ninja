@echo off
set BOT_TOKEN=8470555671:AAE4RusYu-4bbQWNz_nU6vJWhBJ-ULOdsW0
set ADMINS=7495437597
set RUN_MODE=local
set DATABASE_URL=postgresql://defender:defender@localhost:5432/defender
call .venv\Scripts\activate
python app.py
pause
