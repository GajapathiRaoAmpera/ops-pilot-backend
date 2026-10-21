"""Connection check. Run: PYTHONPATH=. uv run python scripts/check_db.py
Prints server version, current user, and whether the opspilot schema/tables exist. Never prints the URL or password."""
from sqlalchemy import text

from app.db import SCHEMA, get_engine

with get_engine().connect() as c:
    print("connected:", c.execute(text("select version()")).scalar().split(",")[0])
    print("db user  :", c.execute(text("select current_user")).scalar())
    n = c.execute(text("select count(*) from information_schema.tables where table_schema=:s"), {"s": SCHEMA}).scalar()
    print(f"schema '{SCHEMA}' tables: {n}", "(run docs/supabase/001_opspilot_schema.sql)" if not n else "")
