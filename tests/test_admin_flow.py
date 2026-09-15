import os

ADMIN = {"Authorization": f"Bearer {os.environ['ADMIN_TOKEN']}"}
FAKE_AUTH = "a" * 64
FAKE_CT0 = "b" * 160


def test_setup_disabled_account_no_x_traffic(client):
    r = client.post("/admin/account", headers=ADMIN, json={
        "label": "testacct", "auth_token": FAKE_AUTH, "ct0": FAKE_CT0, "enabled": False})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["label"] == "testacct"
    assert "auth_token" not in r.text or "auth_token_secret" not in r.text
    assert FAKE_AUTH not in r.text and FAKE_CT0 not in r.text


def test_accounts_listing_is_redacted(client):
    r = client.get("/admin/accounts", headers=ADMIN)
    assert r.status_code == 200
    accounts = r.json()["accounts"]
    labels = [a["label"] for a in accounts]
    assert "testacct" in labels
    blob = r.text
    assert "enc_auth_token" not in blob and "enc_ct0" not in blob
    assert FAKE_AUTH not in blob and FAKE_CT0 not in blob


def test_invalid_label_rejected(client):
    r = client.post("/admin/account", headers=ADMIN, json={
        "label": "bad label!", "auth_token": FAKE_AUTH, "ct0": FAKE_CT0})
    assert r.status_code == 400


def test_rotation_overwrites(client):
    r = client.post("/admin/account", headers=ADMIN, json={
        "label": "testacct", "auth_token": "c" * 64, "ct0": "d" * 160, "enabled": False})
    assert r.status_code == 200
    r = client.get("/admin/accounts", headers=ADMIN)
    assert sum(1 for a in r.json()["accounts"] if a["label"] == "testacct") == 1


def test_delete_account(client):
    r = client.delete("/admin/account/testacct", headers=ADMIN)
    assert r.status_code == 200
    assert r.json()["deleted"] == "testacct"
    r = client.delete("/admin/account/testacct", headers=ADMIN)
    assert r.status_code == 404
