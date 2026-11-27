CREATE DATABASE IF NOT EXISTS password_manager
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE password_manager;

CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    kdf_salt VARBINARY(16) NOT NULL,
    email_verified TINYINT(1) NOT NULL DEFAULT 0,
    totp_secret_enc VARBINARY(255) NULL,
    totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
    failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    auto_lock_minutes INT UNSIGNED NOT NULL DEFAULT 15,
    theme VARCHAR(20) NOT NULL DEFAULT 'light',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_users_email (email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS email_verifications (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    otp_hash CHAR(64) NOT NULL,
    purpose VARCHAR(30) NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    consumed_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_otp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_otp_lookup (user_id, purpose, expires_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS categories (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NULL,
    name VARCHAR(100) NOT NULL,
    is_builtin TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_category (user_id, name),
    CONSTRAINT fk_category_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_category_user (user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS vault_entries (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    site_name VARCHAR(255) NOT NULL,
    site_url VARCHAR(500) NULL,
    username_enc VARBINARY(1024) NOT NULL,
    password_enc VARBINARY(2048) NOT NULL,
    category VARCHAR(100) NOT NULL DEFAULT 'Other',
    notes_enc VARBINARY(4096) NULL,
    favourite TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_vault_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_vault_user_name (user_id, site_name),
    INDEX idx_vault_user_category (user_id, category),
    INDEX idx_vault_user_updated (user_id, updated_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS vault_fields (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    entry_id INT UNSIGNED NOT NULL,
    field_label VARCHAR(100) NOT NULL,
    field_type VARCHAR(20) NOT NULL DEFAULT 'text',
    is_sensitive TINYINT(1) NOT NULL DEFAULT 0,
    field_order INT UNSIGNED NOT NULL DEFAULT 0,
    value_enc MEDIUMBLOB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_vault_field_entry FOREIGN KEY (entry_id) REFERENCES vault_entries(id) ON DELETE CASCADE,
    INDEX idx_vault_field_entry_order (entry_id, field_order, id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS activity_log (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NULL,
    action VARCHAR(50) NOT NULL,
    success TINYINT(1) NOT NULL DEFAULT 1,
    ip_address VARCHAR(45) NULL,
    detail VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_log_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_log_user (user_id, created_at)
) ENGINE=InnoDB;

INSERT IGNORE INTO categories (user_id, name, is_builtin) VALUES
 (NULL, 'Social Media', 1), (NULL, 'Banking and Finance', 1),
 (NULL, 'Email', 1), (NULL, 'Government and Identity', 1),
 (NULL, 'Education', 1), (NULL, 'Work', 1),
 (NULL, 'Shopping', 1), (NULL, 'Entertainment', 1),
 (NULL, 'Other', 1);
