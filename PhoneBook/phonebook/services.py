from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta
import csv
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
from urllib.parse import quote
import webbrowser

from sqlalchemy import and_, delete as sql_delete, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from .models import Contact, Group, PasswordReset, Session as LoginSession, TrashEntry, User, split_values
from .security import hash_password, verify_password, hash_token, normalize_email, normalize_phone, is_valid_email, utcnow
from .mail import SMTPMailer