import os
import tempfile

# Shim for PyMySQL>=1.2.1 where escape_dict was removed but aiomysql<=0.3.2 still imports it
try:
    import pymysql.converters as _pm_conv
    if not hasattr(_pm_conv, "escape_dict"):
        def _escape_dict(val, charset=None, mapping=None):
            raise TypeError("dict can not be used as parameter")
        _pm_conv.escape_dict = _escape_dict
except Exception:
    pass

# Test env must be set BEFORE app modules are imported (settings are cached).
# Tokens are 48 chars: startup now refuses bearer/admin secrets shorter than
# 32 (app.config.MIN_SECRET_LENGTH), and the previous fixtures were 31.
_TMP = tempfile.mkdtemp(prefix="kxstrel-test-")

os.environ.setdefault("MCP_ACCESS_TOKEN", "test-mcp-token-0123456789abcdef-0123456789abcdef")
os.environ.setdefault("ADMIN_TOKEN", "test-admin-token-0123456789abcdef-0123456789abcdef")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP}/test.db")
os.environ.setdefault("SPECTRE_DB_PATH", f"{_TMP}/spectre.db")
os.environ.setdefault("VALIDATE_ON_STARTUP", "false")
os.environ.setdefault("SESSION_CHECK_INTERVAL_SECONDS", "3600")
os.environ.setdefault("RATE_LIMIT_ADMIN_PER_MIN", "1000")
os.environ.setdefault("LOG_LEVEL", "WARNING")

if not os.environ.get("CREDENTIAL_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["CREDENTIAL_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import reset_settings_cache  # noqa: E402


@pytest.fixture(scope="session")
def client():
    reset_settings_cache()
    from app.main import create_app  # noqa: PLC0415 - env must be set first

    app = create_app()
    with TestClient(app) as c:
        yield c
