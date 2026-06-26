"""
migrate_to_postgres.py — one-time data migration: SQLite (database.db) -> PostgreSQL.

USAGE
  Run this ONCE, in an environment that has:
    - DATABASE_URL set (so it knows which Postgres to write to)
    - The OLD database.db file present on disk (the SQLite file you want to migrate FROM)

  Locally (Termux), pointing at your Railway Postgres:
      DATABASE_URL="<paste the value from Railway Postgres.DATABASE_URL>" python3 migrate_to_postgres.py

  This script does NOT touch your live app — it just reads the old .db file and
  writes into Postgres. Safe to re-run; existing rows are skipped (ON CONFLICT DO NOTHING).
"""
import os
import sqlite3
import sys

if not os.environ.get('DATABASE_URL'):
    print("ERROR: DATABASE_URL is not set. Set it to your Railway Postgres connection string first.")
    sys.exit(1)

import psycopg2
import psycopg2.extras

SQLITE_PATH = os.environ.get('OLD_DATABASE_PATH', 'database.db')

if not os.path.exists(SQLITE_PATH):
    print(f"ERROR: '{SQLITE_PATH}' not found. Nothing to migrate — Postgres will just start empty, which is fine.")
    sys.exit(1)

# Make sure the destination tables exist before copying into them.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import init_db  # noqa: E402  (reuses the app's own schema definitions, kept in one place)
init_db()

TABLES = ['orders', 'reports', 'kritik', 'saran', 'ratings',
          'activity_log', 'admin_log', 'users', 'admin_users', 'vouchers']

src = sqlite3.connect(SQLITE_PATH)
src.row_factory = sqlite3.Row
dst = psycopg2.connect(os.environ['DATABASE_URL'])
dst_cur = dst.cursor()

total = 0
for table in TABLES:
    try:
        rows = src.execute(f'SELECT * FROM {table}').fetchall()
    except sqlite3.OperationalError:
        print(f"  skip {table}: table doesn't exist in the old SQLite file")
        continue
    if not rows:
        print(f"  {table}: 0 rows, nothing to copy")
        continue

    cols = rows[0].keys()
    col_list = ','.join(cols)
    placeholders = ','.join(['%s'] * len(cols))
    sql = f'INSERT INTO {table} ({col_list}) VALUES ({placeholders}) ON CONFLICT (id) DO NOTHING'

    for row in rows:
        dst_cur.execute(sql, tuple(row[c] for c in cols))
    dst.commit()

    # Keep the SERIAL sequence in sync so the NEXT insert (a real new order,
    # signup, etc.) doesn't collide with an id we just copied in manually.
    dst_cur.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                     f"COALESCE((SELECT MAX(id) FROM {table}), 1))")
    dst.commit()

    print(f"  {table}: copied {len(rows)} rows")
    total += len(rows)

src.close()
dst_cur.close()
dst.close()
print(f"\nDone — {total} total rows migrated into PostgreSQL.")
