from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
import secrets 
PBKDF2_ROUNDS=310_000
MIN_PASSWORD_LENGHT = 8
MAX_PASSWORD_LEGHT = 128
RESET_CODE_MINUTES = 10
SESSION_DAYS = 7
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS)
    return 'pbkdf2_sha256$%d$%s$%s' % (PBKDF2_ROUNDS, salt.hex(), digest.hex())
