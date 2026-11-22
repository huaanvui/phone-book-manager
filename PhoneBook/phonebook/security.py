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
