"""
db_compat.py — SQLite <-> PostgreSQL compatibility shim.

Why this exists: app.py has 50+ call sites using sqlite3's `?` placeholder
style and `cursor.lastrowid`. Rewriting every one of them by hand to
PostgreSQL's `%s` style is a lot of surface area for a live production
site to get wrong. Instead, this module gives app.py the exact same
`get_db()` / `db.execute(...)` / `cursor.lastrowid` interface it already
uses, but transparently backed by PostgreSQL when DATABASE_URL is set
(Railway), or plain SQLite when it isn't (local Termux development).

Nothing in app.py's *query logic* needs to change — only get_db() and the
CREATE TABLE/ALTER TABLE statements in init_db() route through this.
"""
import os
import re
import sqlite3

USE_POSTGRES = bool(os.environ.get('DATABASE_URL'))

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras


def _to_pg_params(query):
    """SQLite uses '?' placeholders; PostgreSQL uses '%s'. Plain string
    substitution is safe here because actual user-supplied values are
    always passed separately via `params`, never interpolated into the
    query text itself — so there's no SQL-injection concern in doing this."""
    return query.replace('?', '%s')


class CompatCursor:
    """Wraps a psycopg2 cursor so it behaves like a sqlite3 cursor for the
    handful of things app.py relies on: .execute(), .fetchone(), .fetchall(),
    and critically .lastrowid (sqlite3 has this natively; psycopg2 doesn't,
    so we emulate it via lastval() right after an INSERT)."""
    def __init__(self, raw_cursor):
        self._cur = raw_cursor
        self.lastrowid = None

    def execute(self, query, params=()):
        pg_query = _to_pg_params(translate_schema(query))
        self._cur.execute(pg_query, params)
        if pg_query.strip().upper().startswith('INSERT'):
            try:
                self._cur.execute('SELECT lastval()')
                self.lastrowid = self._cur.fetchone()['lastval']
            except Exception:
                # Table has no SERIAL/IDENTITY column touched this transaction — fine, not every INSERT needs lastrowid.
                self.lastrowid = None
        return self

    def fetchone(self): return self._cur.fetchone()
    def fetchall(self): return self._cur.fetchall()
    def __iter__(self): return iter(self._cur)


class CompatConnection:
    """Wraps a psycopg2 connection so `db.execute(...)` works directly on
    the connection object, exactly like sqlite3.Connection.execute() does —
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


def connect(database_path):
    """Drop-in replacement for sqlite3.connect(database_path) — returns a
    connection that behaves the same regardless of backend."""
    if USE_POSTGRES:
        raw = psycopg2.connect(
            os.environ['DATABASE_URL'],
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        return CompatConnection(raw)
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
        raw = psycopg2.connect(
            os.environ['DATABASE_URL'],
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        return CompatConnection(raw)
    db = sqlite3.connect(sqlite_path, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=NORMAL')
    return db


def translate_schema(sql):
    """Translate SQLite-flavored CREATE TABLE / ALTER TABLE statements to
    PostgreSQL equivalents. Only called from init_db(), never from regular
    query call sites, since this rewrites *schema syntax*, not just `?`."""
    if not USE_POSTGRES:
        return sql
    sql = re.sub(r'INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT', 'SERIAL PRIMARY KEY', sql, flags=re.IGNORECASE)
    sql = re.sub(r'TIMESTAMP\s+DEFAULT\s+CURRENT_TIMESTAMP', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP', sql, flags=re.IGNORECASE)
    # Postgres supports "ADD COLUMN IF NOT EXISTS" natively — this removes
    # the need for the try/except-swallow pattern used for SQLite, where
    # re-adding an existing column is the expected (and silently ignored) case.
    sql = re.sub(r'ADD\s+COLUMN\s+(?!IF\s+NOT\s+EXISTS)', 'ADD COLUMN IF NOT EXISTS ', sql, flags=re.IGNORECASE)
    return sql
