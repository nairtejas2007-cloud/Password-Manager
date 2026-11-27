from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Response
from pydantic import ValidationError

from app import db, main, migrations, security, sessions
from app.schemas import ChangePasswordIn, EntryEditAuthIn, EntryFieldIn, EntryIn


class FakeRequest:
    client = SimpleNamespace(host="testclient")


def _session():
    return {
        "user_id": 7,
        "key": b"0123456789abcdef0123456789abcdef",
        "token": "test-session",
    }


def _record_transaction(items, statements):
    results = []
    for item in items:
        statement = item(results) if callable(item) else item
        statements.append(statement)
        results.append((41 if not results else 100 + len(results), 1))
    return results


def test_execute_transaction_resolves_statements_from_prior_insert_results(monkeypatch):
    from contextlib import contextmanager

    class FakeCursor:
        def __init__(self):
            self.lastrowid = None
            self.rowcount = 1
            self.executed = []

        def execute(self, sql, params):
            self.executed.append((sql, params))
            self.lastrowid = 41 if sql == "INSERT parent" else 99

        def close(self):
            pass

    class FakeConnection:
        def __init__(self):
            self.cursor_instance = FakeCursor()
            self.committed = False
            self.rolled_back = False

        def cursor(self):
            return self.cursor_instance

        def commit(self):
            self.committed = True

        def rollback(self):
            self.rolled_back = True

        def close(self):
            pass

    connection = FakeConnection()

    @contextmanager
    def fake_connection():
        yield connection

    monkeypatch.setattr(db, "get_conn", fake_connection)
    results = db.execute_transaction(
        [
            ("INSERT parent", ()),
            lambda prior: ("INSERT child", (prior[0][0],)),
        ]
    )

    assert connection.cursor_instance.executed == [
        ("INSERT parent", ()),
        ("INSERT child", (41,)),
    ]
    assert results == [(41, 1), (99, 1)]
    assert connection.committed
    assert not connection.rolled_back


def test_entry_accepts_new_title_and_legacy_site_name():
    assert EntryIn(title="Personal Gmail").title == "Personal Gmail"
    assert EntryIn(site_name="Old saved title").title == "Old saved title"

    with pytest.raises(ValidationError):
        EntryIn(title="   ")


@pytest.mark.parametrize(
    ("field_type", "value"),
    [
        ("email", "not-an-email"),
        ("url", "javascript:alert(1)"),
        ("number", "not-a-number"),
    ],
)
def test_custom_field_values_match_selected_type(field_type, value):
    with pytest.raises(ValidationError):
        EntryFieldIn(label="Custom field", type=field_type, value=value)


def test_add_entry_encrypts_every_field_and_keeps_category_and_favourite(monkeypatch):
    statements = []
    log_calls = []
    fields = [
        EntryFieldIn(label="Email Address", value="person@example.com", type="email"),
        EntryFieldIn(label="Password", value="private-password", type="password"),
        EntryFieldIn(label="Recovery Email", value="backup@example.com", sensitive=True),
    ]

    def fake_transaction(items):
        return _record_transaction(items, statements)

    monkeypatch.setattr(main, "execute_transaction", fake_transaction)
    monkeypatch.setattr(main, "log", lambda *args: log_calls.append(args))

    result = main.add_entry(
        EntryIn(
            title="Personal Gmail",
            category="Email",
            favourite=True,
            fields=fields,
        ),
        FakeRequest(),
        _session(),
    )

    assert result == {"id": 41}
    assert "INSERT INTO vault_entries" in statements[0][0]
    entry_params = statements[0][1]
    assert entry_params[1] == "Personal Gmail"
    assert entry_params[5:8] == ("Email", None, 1)
    assert security.decrypt(_session()["key"], entry_params[3]) == "person@example.com"
    assert security.decrypt(_session()["key"], entry_params[4]) == "private-password"

    field_rows = [params for sql, params in statements[1:] if "INSERT INTO vault_fields" in sql]
    assert len(field_rows) == 3
    assert [row[0] for row in field_rows] == [41, 41, 41]
    assert [row[4] for row in field_rows] == [0, 1, 2]
    assert [security.decrypt(_session()["key"], row[5]) for row in field_rows] == [
        "person@example.com",
        "private-password",
        "backup@example.com",
    ]
    assert field_rows[1][3] == 1
    assert field_rows[2][3] == 1
    assert "private-password" not in repr(statements)
    assert log_calls[0][-1] == "entry 41"


@pytest.mark.parametrize("field_count", [0, 1, 8])
def test_add_entry_persists_variable_field_counts(monkeypatch, field_count):
    statements = []
    monkeypatch.setattr(
        main,
        "execute_transaction",
        lambda items: _record_transaction(items, statements),
    )
    monkeypatch.setattr(main, "log", lambda *args: None)
    fields = [
        EntryFieldIn(label=f"Custom field {index}", value=f"value-{index}")
        for index in range(field_count)
    ]

    main.add_entry(
        EntryIn(title="Custom entry", fields=fields),
        FakeRequest(),
        _session(),
    )

    assert len(statements) == field_count + 1
    assert sum("INSERT INTO vault_fields" in sql for sql, _ in statements) == field_count


def test_large_custom_password_is_preserved_without_overflowing_legacy_column(monkeypatch):
    statements = []
    secret = "x" * 5000
    monkeypatch.setattr(
        main,
        "execute_transaction",
        lambda items: _record_transaction(items, statements),
    )
    monkeypatch.setattr(main, "log", lambda *args: None)

    main.add_entry(
        EntryIn(
            title="Large secret",
            fields=[EntryFieldIn(label="Credential", type="password", value=secret)],
        ),
        FakeRequest(),
        _session(),
    )

    assert security.decrypt(_session()["key"], statements[0][1][4]) == ""
    custom_value = next(params[5] for sql, params in statements if "INSERT INTO vault_fields" in sql)
    assert security.decrypt(_session()["key"], custom_value) == secret


def test_update_replaces_fields_and_persists_new_order_atomically(monkeypatch):
    statements = []
    sess = _session()
    sessions.authorize_entry_edit(sess["token"], 41)
    monkeypatch.setattr(main, "_get_entry", lambda *args: {"id": 41})
    monkeypatch.setattr(
        main,
        "execute_transaction",
        lambda items: (statements.extend(items) or [(None, 1)] * len(items)),
    )
    monkeypatch.setattr(main, "log", lambda *args: None)
    body = EntryIn(
        title="Updated portal",
        category="Education",
        favourite=True,
        fields=[
            EntryFieldIn(label="Password", value="second", type="password"),
            EntryFieldIn(label="Student ID", value="first", sensitive=True),
        ],
    )

    result = main.update_entry(41, body, FakeRequest(), sess)

    assert result == {"message": "Updated"}
    assert "WHERE id=%s AND user_id=%s" in statements[0][0]
    assert statements[0][1][0] == "Updated portal"
    assert statements[0][1][4:7] == ("Education", None, 1)
    assert statements[1] == ("DELETE FROM vault_fields WHERE entry_id=%s", (41,))
    inserted = [params for sql, params in statements if "INSERT INTO vault_fields" in sql]
    assert [params[4] for params in inserted] == [0, 1]
    assert [security.decrypt(_session()["key"], params[5]) for params in inserted] == [
        "second",
        "first",
    ]


def test_update_without_fields_deletes_existing_fields(monkeypatch):
    statements = []
    sess = _session()
    sessions.authorize_entry_edit(sess["token"], 41)
    monkeypatch.setattr(main, "_get_entry", lambda *args: {"id": 41})
    monkeypatch.setattr(
        main,
        "execute_transaction",
        lambda items: (statements.extend(items) or [(None, 1)] * len(items)),
    )
    monkeypatch.setattr(main, "log", lambda *args: None)

    main.update_entry(
        41, EntryIn(title="No custom fields", fields=[]), FakeRequest(), sess
    )

    assert statements[1] == ("DELETE FROM vault_fields WHERE entry_id=%s", (41,))
    assert not any("INSERT INTO vault_fields" in sql for sql, _ in statements)


def test_update_omitting_fields_preserves_existing_custom_fields(monkeypatch):
    statements = []
    sess = _session()
    sessions.authorize_entry_edit(sess["token"], 41)
    key = _session()["key"]
    monkeypatch.setattr(
        main,
        "_get_entry",
        lambda *args: {
            "id": 41,
            "username_enc": security.encrypt(key, "legacy-user"),
            "password_enc": security.encrypt(key, "legacy-password"),
            "notes_enc": None,
        },
    )
    monkeypatch.setattr(
        main,
        "execute_transaction",
        lambda items: (statements.extend(items) or [(None, 1)] * len(items)),
    )
    monkeypatch.setattr(main, "log", lambda *args: None)

    main.update_entry(41, EntryIn(title="Renamed only"), FakeRequest(), sess)

    assert len(statements) == 1
    assert "DELETE FROM vault_fields" not in statements[0][0]
    assert security.decrypt(key, statements[0][1][2]) == "legacy-user"
    assert security.decrypt(key, statements[0][1][3]) == "legacy-password"


def test_entry_edit_requires_password_authorization_and_grant_is_one_time(monkeypatch):
    sess = _session()
    sessions._entry_edit_authorizations.clear()
    monkeypatch.setattr(main, "_get_entry", lambda *args: {"id": 41})
    monkeypatch.setattr(main, "query_one", lambda *args: {"password_hash": "stored-hash"})
    monkeypatch.setattr(main.security, "verify_master_password", lambda *args: True)
    monkeypatch.setattr(main, "log", lambda *args: None)

    result = main.authorize_entry_edit(
        41,
        EntryEditAuthIn(master_password="correct-password"),
        FakeRequest(),
        sess,
    )

    assert result == {"message": "Master password verified."}
    assert sessions.consume_entry_edit_authorization(sess["token"], 41)
    assert not sessions.consume_entry_edit_authorization(sess["token"], 41)


def test_entry_edit_rejects_wrong_master_password(monkeypatch):
    sess = _session()
    sessions._entry_edit_authorizations.clear()
    monkeypatch.setattr(main, "_get_entry", lambda *args: {"id": 41})
    monkeypatch.setattr(main, "query_one", lambda *args: {"password_hash": "stored-hash"})
    monkeypatch.setattr(main.security, "verify_master_password", lambda *args: False)

    with pytest.raises(HTTPException) as failure:
        main.authorize_entry_edit(
            41,
            EntryEditAuthIn(master_password="incorrect-password"),
            FakeRequest(),
            sess,
        )

    assert failure.value.status_code == 401
    assert not sessions.consume_entry_edit_authorization(sess["token"], 41)


def test_update_rejects_without_recent_master_password(monkeypatch):
    sess = _session()
    sessions._entry_edit_authorizations.clear()
    monkeypatch.setattr(main, "_get_entry", lambda *args: {"id": 41})

    with pytest.raises(HTTPException) as failure:
        main.update_entry(
            41, EntryIn(title="Unauthorized edit"), FakeRequest(), sess
        )

    assert failure.value.status_code == 403


def test_favourite_patch_persists_owner_scoped_value(monkeypatch):
    executed = []
    sess = _session()
    sessions.authorize_entry_edit(sess["token"], 41)
    monkeypatch.setattr(main, "_get_entry", lambda entry_id, user_id: {"id": entry_id})
    monkeypatch.setattr(
        main, "execute", lambda sql, params=(): executed.append((sql, params)) or (None, 1)
    )

    result = main.toggle_favourite(41, False, sess)

    assert result == {"message": "Favourite updated"}
    assert executed == [
        (
            "UPDATE vault_entries SET favourite=%s WHERE id=%s AND user_id=%s",
            (0, 41, 7),
        )
    ]


def test_legacy_entry_values_are_available_after_fields_migration(monkeypatch):
    key = _session()["key"]
    row = {
        "id": 41,
        "site_name": "Legacy Gmail",
        "site_url": "https://mail.example.com",
        "username_enc": security.encrypt(key, "person@example.com"),
        "password_enc": security.encrypt(key, "old-secret"),
        "notes_enc": security.encrypt(key, "legacy note"),
        "category": "Email",
        "favourite": 1,
        "created_at": datetime(2025, 1, 1),
        "updated_at": datetime(2025, 1, 1),
    }
    monkeypatch.setattr(main, "query_all", lambda *args: [])

    output = main._entry_out(row, key, include_password=True)

    assert output["title"] == "Legacy Gmail"
    assert output["site_name"] == "Legacy Gmail"
    assert [field["label"] for field in output["fields"]] == [
        "Username or email",
        "Password",
        "Notes",
    ]
    assert [field["value"] for field in output["fields"]] == [
        "person@example.com",
        "old-secret",
        "legacy note",
    ]
    assert output["fields"][1]["sensitive"] is True


def test_saved_custom_fields_decrypt_only_in_entry_detail(monkeypatch):
    key = _session()["key"]
    row = {
        "id": 41,
        "site_name": "College Portal",
        "site_url": None,
        "username_enc": security.encrypt(key, ""),
        "password_enc": security.encrypt(key, ""),
        "notes_enc": None,
        "category": "Education",
        "favourite": 0,
        "created_at": datetime(2025, 1, 1),
        "updated_at": datetime(2025, 1, 1),
    }
    encrypted_value = security.encrypt(key, "private student number")
    monkeypatch.setattr(
        main,
        "query_all",
        lambda *args: [
            {
                "id": 89,
                "field_label": "Student ID",
                "field_type": "text",
                "is_sensitive": 1,
                "field_order": 0,
                "value_enc": encrypted_value,
            }
        ],
    )

    output = main._entry_out(row, key, include_password=True)

    assert output["fields"] == [
        {
            "id": 89,
            "label": "Student ID",
            "type": "text",
            "sensitive": True,
            "position": 0,
            "value": "private student number",
        }
    ]
    assert encrypted_value != output["fields"][0]["value"].encode()


def test_list_hides_username_values_marked_sensitive(monkeypatch):
    key = _session()["key"]
    row = {
        "id": 41,
        "site_name": "College Portal",
        "site_url": None,
        "username_enc": security.encrypt(key, "private@example.com"),
        "password_enc": security.encrypt(key, "private-password"),
        "notes_enc": None,
        "category": "Education",
        "favourite": 0,
        "created_at": datetime(2025, 1, 1),
        "updated_at": datetime(2025, 1, 1),
    }

    def fake_query_all(sql, params=()):
        if "FROM vault_entries" in sql:
            return [row]
        if "FROM vault_fields" in sql:
            return [
                {
                    "entry_id": 41,
                    "field_label": "Email Address",
                    "field_type": "email",
                    "is_sensitive": 1,
                }
            ]
        raise AssertionError(f"Unexpected query: {sql}")

    monkeypatch.setattr(main, "query_all", fake_query_all)

    output = main.list_entries(sess=_session())

    assert output[0]["username"] == ""
    assert "private@example.com" not in repr(output)
    assert "private-password" not in repr(output)


def test_master_password_change_reencrypts_custom_field_values(monkeypatch):
    old_key = _session()["key"]
    new_key = b"abcdef0123456789abcdef0123456789"
    field_value = security.encrypt(old_key, "sensitive field value")
    field_rows = [{"id": 89, "value_enc": field_value}]
    entry_rows = [
        {
            "id": 41,
            "username_enc": security.encrypt(old_key, "legacy-user"),
            "password_enc": security.encrypt(old_key, "legacy-password"),
            "notes_enc": None,
        }
    ]
    statements = []
    monkeypatch.setattr(main, "query_one", lambda *args: {"password_hash": "stored-hash"})
    monkeypatch.setattr(main.security, "verify_master_password", lambda *args: True)
    monkeypatch.setattr(main.security, "new_kdf_salt", lambda: b"0123456789abcdef")
    monkeypatch.setattr(main.security, "derive_vault_key", lambda *args: new_key)
    monkeypatch.setattr(main.security, "hash_master_password", lambda value: "new-hash")

    def fake_query_all(sql, params=()):
        return entry_rows if "FROM vault_entries" in sql else field_rows

    monkeypatch.setattr(main, "query_all", fake_query_all)
    monkeypatch.setattr(
        main,
        "execute_transaction",
        lambda items: (statements.extend(items) or [(None, 1)] * len(items)),
    )
    monkeypatch.setattr(main, "log", lambda *args: None)

    result = main.change_password(
        ChangePasswordIn(
            current_password="CurrentMasterPassword1",
            new_password="NewMasterPassword123",
            confirm_password="NewMasterPassword123",
        ),
        FakeRequest(),
        Response(),
        {**_session(), "token": "session-token"},
    )

    field_update = next(item for item in statements if "UPDATE vault_fields" in item[0])
    assert security.decrypt(new_key, field_update[1][0]) == "sensitive field value"
    assert result["message"].startswith("Master password changed")


def test_entry_lookup_rejects_another_users_entry(monkeypatch):
    queries = []
    monkeypatch.setattr(
        main,
        "query_one",
        lambda sql, params=(): queries.append((sql, params)) or None,
    )

    with pytest.raises(HTTPException) as missing:
        main._get_entry(41, 8)

    assert missing.value.status_code == 404
    assert queries[0][1] == (41, 8)


def test_startup_migration_creates_fields_table_without_replacing_categories(monkeypatch):
    executed = []
    monkeypatch.setattr(
        migrations,
        "_column_names",
        lambda table: {"id", "username", "password_hash"}
        if table == "users"
        else {"id", "user_id", "site_name", "username_enc", "password_enc"}
        if table == "vault_entries"
        else set(),
    )
    monkeypatch.setattr(migrations, "_index_names", lambda table: {"uq_users_email"})
    monkeypatch.setattr(
        migrations,
        "query_all",
        lambda *args: [{"id": 1}],
    )
    monkeypatch.setattr(
        migrations,
        "execute",
        lambda sql, params=(): executed.append((sql, params)) or (None, 1),
    )

    migrations.migrate_existing_schema()

    create_fields = [
        sql for sql, _ in executed if "CREATE TABLE IF NOT EXISTS vault_fields" in sql
    ]
    assert len(create_fields) == 1
    assert "ON DELETE CASCADE" in create_fields[0]
    assert not any("DELETE FROM vault_entries" in sql for sql, _ in executed)
    assert not any("DROP TABLE" in sql for sql, _ in executed)
