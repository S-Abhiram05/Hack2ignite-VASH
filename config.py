import os
import secrets

# Centralized VASH Configuration
# Fallback to random process secret if not provided via environment variable
_DEFAULT_SECRET = os.environ.get("VASH_SECRET_KEY")
if not _DEFAULT_SECRET:
    _DEFAULT_SECRET = secrets.token_hex(32)

_DEFAULT_SALT = os.environ.get("VASH_PSI_SALT")
if not _DEFAULT_SALT:
    _DEFAULT_SALT = secrets.token_hex(32)

SECRET_KEY = _DEFAULT_SECRET
PSI_SALT = _DEFAULT_SALT

ALGORITHM = os.environ.get("VASH_JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("VASH_TOKEN_EXPIRE_MINUTES", "60"))
ISSUER = os.environ.get("VASH_ISSUER", "vash.neural.core")

# Database & Cache Config
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
DB_NAME = os.environ.get("VASH_DB_NAME", "fintech_threat_db.sqlite")
