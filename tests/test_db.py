"""DB round-trip on an isolated sqlite file; ciphertext-at-rest assertion."""

import os
import sqlite3
import tempfile

import pytest

from app.crypto import CredentialCrypto, generate_key
from app.db import AccountStore


@pytest.fixture()
def store():
    tmp = tempfile.mkdtemp(prefix="kxstrel-db-")
    return AccountStore(f"sqlite:///{tmp}/t.db")


async def test_crud_and_status(store):
    await store.connect()
    await store.init_schema()
    assert await store.ping()
    await store.upsert_account("acct1", "ENC-A", "ENC-C", enabled=True, meta="{}")
    accounts = await store.get_enabled_accounts()
    assert [a.label for a in accounts] == ["acct1"]
    assert accounts[0].enc_auth_token == "ENC-A"
    await store.update_status("acct1", "CONNECTED", True, None)
    metas = await store.list_accounts_meta()
    assert metas[0]["status"] == "CONNECTED"
    assert "enc_auth_token" not in metas[0] and "enc_ct0" not in metas[0]
    assert await store.delete_account("acct1") is True
    assert await store.delete_account("acct1") is False
    await store.close()


async def test_ciphertext_at_rest(store):
    await store.connect()
    await store.init_schema()
    crypto = CredentialCrypto(generate_key())
    secret_auth, secret_ct0 = "real-auth-token-value", "real-ct0-value"
    await store.upsert_account("acct2", crypto.encrypt(secret_auth), crypto.encrypt(secret_ct0))
    path = store._sqlite_path
    with sqlite3.connect(path) as conn:
        row = conn.execute("SELECT enc_auth_token, enc_ct0 FROM x_accounts WHERE label='acct2'").fetchone()
    assert secret_auth not in row[0] and secret_ct0 not in row[1]
    assert os.environ.get("CREDENTIAL_ENCRYPTION_KEY", "") not in (row[0] + row[1])
    await store.close()
