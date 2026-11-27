from contextlib import contextmanager

from mysql.connector import pooling

from app.config import DB_CONFIG

_pool = None


def _get_pool():
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(
            pool_name="pm_pool", pool_size=5, **DB_CONFIG
        )
    return _pool


@contextmanager
def get_conn():
    conn = _get_pool().get_connection()
    try:
        yield conn
    finally:
        conn.close()


def query_one(sql, params=()):
    with get_conn() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params)
        row = cur.fetchone()
        cur.close()
        return row


def query_all(sql, params=()):
    with get_conn() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, params)
        rows = cur.fetchall()
        cur.close()
        return rows


def execute(sql, params=()):
    """Run an INSERT/UPDATE/DELETE, commit, return (lastrowid, rowcount)."""
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()
        result = (cur.lastrowid, cur.rowcount)
        cur.close()
        return result


def execute_transaction(statements):
    """Run SQL statements atomically; callable statements receive prior results."""
    with get_conn() as conn:
        cur = conn.cursor()
        try:
            results = []
            for statement in statements:
                sql, params = statement(results) if callable(statement) else statement
                cur.execute(sql, params)
                results.append((cur.lastrowid, cur.rowcount))
            conn.commit()
            return results
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
