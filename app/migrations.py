from app.db import execute, query_all


_USER_COLUMNS = {
    "full_name": "VARCHAR(100) NOT NULL DEFAULT ''",
    "email": "VARCHAR(255) NULL",
    "email_verified": "TINYINT(1) NOT NULL DEFAULT 0",
    "auto_lock_minutes": "INT UNSIGNED NOT NULL DEFAULT 15",
    "theme": "VARCHAR(20) NOT NULL DEFAULT 'light'",
    "updated_at": "TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
}

_VAULT_COLUMNS = {
    "site_url": "VARCHAR(500) NULL",
    "category": "VARCHAR(100) NOT NULL DEFAULT 'Other'",
    "favourite": "TINYINT(1) NOT NULL DEFAULT 0",
}


def _column_names(table_name: str) -> set[str]:
    rows = query_all(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
        (table_name,),
    )
    return {row["COLUMN_NAME"] for row in rows}


def _index_names(table_name: str) -> set[str]:
    rows = query_all(
        "SELECT DISTINCT INDEX_NAME FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
        (table_name,),
    )
    return {row["INDEX_NAME"] for row in rows}


def _add_missing_columns(table: str, definitions: dict[str, str]) -> None:
    columns = _column_names(table)
    for column, definition in definitions.items():
        if column not in columns:
            execute(f"ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}")


def migrate_existing_schema() -> None:
    """Apply additive compatibility updates for databases created by earlier versions."""
    user_columns = _column_names("users")
    if not user_columns:
        raise RuntimeError("The users table is missing. Run schema.sql before starting the app.")

    _add_missing_columns("users", _USER_COLUMNS)

    if "username" in user_columns:
        execute(
            "UPDATE users SET full_name = username "
            "WHERE full_name = '' AND username IS NOT NULL"
        )
        execute(
            "UPDATE users SET email = LOWER(username) "
            "WHERE email IS NULL AND username REGEXP "
            "'^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$'"
        )
        execute("ALTER TABLE users MODIFY COLUMN username VARCHAR(50) NULL")

    indexes = _index_names("users")
    if "uq_users_email" not in indexes:
        execute("ALTER TABLE users ADD UNIQUE INDEX uq_users_email (email)")

    execute(
        "CREATE TABLE IF NOT EXISTS email_verifications ("
        "id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,"
        "user_id INT UNSIGNED NOT NULL,"
        "otp_hash CHAR(64) NOT NULL,"
        "purpose VARCHAR(30) NOT NULL,"
        "expires_at DATETIME NOT NULL,"
        "attempts INT UNSIGNED NOT NULL DEFAULT 0,"
        "consumed_at DATETIME NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,"
        "INDEX idx_otp_lookup (user_id, purpose, expires_at)"
        ") ENGINE=InnoDB"
    )
    execute(
        "CREATE TABLE IF NOT EXISTS categories ("
        "id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,"
        "user_id INT UNSIGNED NULL,"
        "name VARCHAR(100) NOT NULL,"
        "is_builtin TINYINT(1) NOT NULL DEFAULT 0,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE KEY uq_category (user_id, name),"
        "CONSTRAINT fk_category_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,"
        "INDEX idx_category_user (user_id)"
        ") ENGINE=InnoDB"
    )

    vault_columns = _column_names("vault_entries")
    if not vault_columns:
        raise RuntimeError("The vault_entries table is missing. Run schema.sql before starting the app.")
    _add_missing_columns("vault_entries", _VAULT_COLUMNS)
    execute(
        "CREATE TABLE IF NOT EXISTS vault_fields ("
        "id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,"
        "entry_id INT UNSIGNED NOT NULL,"
        "field_label VARCHAR(100) NOT NULL,"
        "field_type VARCHAR(20) NOT NULL DEFAULT 'text',"
        "is_sensitive TINYINT(1) NOT NULL DEFAULT 0,"
        "field_order INT UNSIGNED NOT NULL DEFAULT 0,"
        "value_enc MEDIUMBLOB NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
        "CONSTRAINT fk_vault_field_entry FOREIGN KEY (entry_id) "
        "REFERENCES vault_entries(id) ON DELETE CASCADE,"
        "INDEX idx_vault_field_entry_order (entry_id, field_order, id)"
        ") ENGINE=InnoDB"
    )

    for category in (
        "Social Media",
        "Banking and Finance",
        "Email",
        "Government and Identity",
        "Education",
        "Work",
        "Shopping",
        "Entertainment",
        "Other",
    ):
        existing = query_all(
            "SELECT id FROM categories WHERE user_id IS NULL AND name = %s LIMIT 1",
            (category,),
        )
        if not existing:
            execute(
                "INSERT INTO categories (user_id, name, is_builtin) VALUES (NULL, %s, 1)",
                (category,),
            )
