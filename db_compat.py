"""
db_compat.py — SQLite <-> PostgreSQL compatibility shim.

Why this exists: app.py has 50+ call sites using sqlite3's `?` placeholder
style, dict-style row access (row['col']), and `cursor.lastrowid`. Rewriting
every one of them by hand to PostgreSQL's conventions is a lot of surface
area for a live production site to get wrong. Instead, this module gives
app.py the exact same `get_db()` / `db.execute(...)` / `row['col']` /
`cursor.lastrowid` interface it already uses, but transparently backed by
PostgreSQL when DATABASE_URL is set (Railway), or plain SQLite when it
isn't (local Termux development).

Driver choice: pg8000, NOT psycopg2. psycopg2 (even the "-binary" wheel)
links against the native libpq.so.5 system library, which Railway's
Nixpacks build environment doesn't reliably expose to the Python venv at
runtime (this caused real crash loops — see project history). pg8000 is a
pure-Python PostgreSQL driver with zero native/system dependencies, so
that entire class of "works on my machine, crashes on Railway" problem
is structurally impossible here.

Nothing in app.py's *query logic* needs to change — only get_db() and the
CREATE TABLE/ALTER TABLE statements in init_db() route through this.
"""
import os
import re
import sqlite3
from urllib.parse import urlparse

USE_POSTGRES = bool(os.environ.get('DATABASE_URL'))

if USE_POSTGRES:
    import pg8000.dbapi as pg8000


def _to_pg_params(query):
    """SQLite uses '?' placeholders; PostgreSQL uses '%s'. Plain string
    substitution is safe here because actual user-supplied values are
    always passed separately via `params`, never interpolated into the
    query text itself — so there's no SQL-injection concern in doing this."""
    return query.replace('?', '%s')


def _row_to_dict(cursor, row):
    """pg8000 returns plain tuples, not dict-like rows. app.py relies on
    sqlite3.Row's dict-style access (row['col'], dict(row)) everywhere, so
    we rebuild that here using cursor.description (column metadata)."""
    if row is None:
        return None
    cols = [d[0] for d in cursor.description]
    return dict(zip(cols, row))


class CompatCursor:
    """Wraps a pg8000 cursor so it behaves like a sqlite3 cursor for the
    handful of things app.py relies on: .execute(), .fetchone(), .fetchall(),
    dict-style rows, and .lastrowid (sqlite3 has this natively; pg8000
    doesn't, so we emulate it via lastval() right after an INSERT)."""
    def __init__(self, raw_cursor):
        self._cur = raw_cursor
        self.lastrowid = None

    def execute(self, query, params=()):
        pg_query = _to_pg_params(translate_schema(query))
        self._cur.execute(pg_query, params)
        if pg_query.strip().upper().startswith('INSERT'):
            try:
                self._cur.execute('SELECT lastval()')
                self.lastrowid = self._cur.fetchone()[0]
            except Exception:
                # Table has no SERIAL/IDENTITY column touched this transaction — fine, not every INSERT needs lastrowid.
                self.lastrowid = None
        return self

    def fetchone(self):
        return _row_to_dict(self._cur, self._cur.fetchone())

    def fetchall(self):
        cols = [d[0] for d in self._cur.description] if self._cur.description else []
        return [dict(zip(cols, row)) for row in self._cur.fetchall()]

    def __iter__(self):
        cols = [d[0] for d in self._cur.description] if self._cur.description else []
        for row in self._cur:
            yield dict(zip(cols, row))


class CompatConnection:
    """Wraps a pg8000 connection so `db.execute(...)` works directly on the
    connection object, exactly like sqlite3.Connection.execute() does —
    that's the calling convention used throughout app.py."""
    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, query, params=()):
        cur = CompatCursor(self._conn.cursor())
        return cur.execute(query, params)

    def commit(self): self._conn.commit()
    def rollback(self): self._conn.rollback()
    def close(self): self._conn.close()
    def cursor(self): return self._conn.cursor()

    def __enter__(self):
        # Matches sqlite3.Connection's `with conn:` behavior: commits on
        # clean exit, rolls back on exception — does NOT close the
        # connection (callers in app.py never rely on auto-close here).
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self._conn.commit()
        else:
            self._conn.rollback()
        return False


def _pg8000_connect():
    """pg8000 takes individual connection params, not a URL string — parse
    Railway's DATABASE_URL (postgres://user:pass@host:port/dbname) into them."""
    url = urlparse(os.environ['DATABASE_URL'])
    raw = pg8000.connect(
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port or 5432,
        database=url.path.lstrip('/'),
    )
    return CompatConnection(raw)


def connect(database_path):
    """Drop-in replacement for sqlite3.connect(database_path) — returns a
    connection that behaves the same regardless of backend."""
    if USE_POSTGRES:
        return _pg8000_connect()
    db = sqlite3.connect(database_path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA busy_timeout=15000')
    return db


def shield_connect(sqlite_path):
    """Same idea as connect(), but for the rate-limiter/IP-block tables
    (blocked, req_log, login_fail). When Postgres is available, these just
    live as extra tables in the SAME database — no second Railway Volume
    needed. journal_mode/synchronous PRAGMAs only make sense for SQLite,
    so they're skipped entirely on the Postgres path."""
    if USE_POSTGRES:
        return _pg8000_connect()
    db = sqlite3.connect(sqlite_path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=NORMAL')
    return db


def translate_schema(sql):
    """Translate SQLite-flavored CREATE TABLE / ALTER TABLE statements to
    PostgreSQL equivalents. Only matters for DDL; the regexes below never
    match ordinary SELECT/INSERT/UPDATE queries, so it's safe to run on
    every query rather than special-casing init_db() call sites."""
    if not USE_POSTGRES:
        return sql
    sql = re.sub(r'INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT', 'SERIAL PRIMARY KEY', sql, flags=re.IGNORECASE)
    # Postgres supports "ADD COLUMN IF NOT EXISTS" natively — this removes
    # the need for the try/except-swallow pattern used for SQLite, where
    # re-adding an existing column is the expected (and silently ignored) case.
    sql = re.sub(r'ADD\s+COLUMN\s+(?!IF\s+NOT\s+EXISTS)', 'ADD COLUMN IF NOT EXISTS ', sql, flags=re.IGNORECASE)
    return sql
