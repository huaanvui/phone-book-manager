from datetime import datetime, timezone
import hashlib
import hmac
import re
import secrets


PBKDF2_ROUNDS = 310_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS)
    return 'pbkdf2_sha256$%d$%s$%s' % (PBKDF2_ROUNDS, salt.hex(), digest.hex())


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt, digest = encoded.split('$', 3)
        if algo != 'pbkdf2_sha256' or int(rounds) > 1_000_000:
            return False
        result = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(result, bytes.fromhex(digest))
    except (TypeError, ValueError, AttributeError):
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def normalize_email(email: str) -> str:
    return (email or '').strip().lower()


def normalize_phone(phone: str) -> str:
    return re.sub(r'\D', '', phone or '')


def is_valid_email(address: str) -> bool:
    return len(address) <= 254 and bool(re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', address))


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)
