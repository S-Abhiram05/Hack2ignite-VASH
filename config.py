import os

# Centralized VASH Configuration
SECRET_KEY = os.environ.get("VASH_SECRET_KEY", "VASH_ENTERPRISE_SCALE_KEY_2026")
ALGORITHM = os.environ.get("VASH_JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("VASH_TOKEN_EXPIRE_MINUTES", "60"))
ISSUER = os.environ.get("VASH_ISSUER", "vash.neural.core")

# Database & Cache Config
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
DB_NAME = os.environ.get("VASH_DB_NAME", "fintech_threat_db.sqlite")
PSI_SALT = os.environ.get("VASH_PSI_SALT", "VASH_PSI_SALT_2026")
