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

class AppError(Exception):
    """Expected, user-friendly business error."""


class ValidationError(AppError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__('\n'.join(f'{key}: {value}' for key, value in errors.items()))

def _owned_contact(db, user_id, contact_id, deleted=False):
    contact = db.scalar(select(Contact).options(selectinload(Contact.groups)).where(
        Contact.id == contact_id, Contact.user_id == user_id, Contact.is_deleted == deleted))
    if contact is None:
        raise AppError('Contact not found in this account' + ('\'s Trash.' if deleted else '.'))
    return contact


def _owned_group(db, user_id, group_id):
    group = db.scalar(select(Group).options(selectinload(Group.contacts)).where(Group.id == group_id, Group.user_id == user_id))
    if group is None:
        raise AppError('Group not found in this account.')
    return group

class AuthService:
    """UC01 register; UC02 login; UC03 logout; UC04 verified password reset."""
    def __init__(self, database, mailer=None):
        self.database = database
        self.mailer = mailer or SMTPMailer()

    def register(self, full_name, email, password, confirm_password, phone_number=''):
        email = normalize_email(email)
        errors = {}
        if not full_name or not full_name.strip(): errors['Name'] = 'Full name is required.'
        if not is_valid_email(email): errors['Email'] = 'Enter a valid email address.'
        if len(password) < 8: errors['Password'] = 'Password must have at least 8 characters.'
        if password != confirm_password: errors['Confirm password'] = 'Passwords do not match.'
        if phone_number and not re.fullmatch(r'[\d +\-]{3,40}', phone_number):
            errors['Phone'] = 'Enter a valid phone number.'
        if errors: raise ValidationError(errors)
        with self.database.session() as db:
            with db.begin():
                if db.scalar(select(User.id).where(User.email == email)):
                    raise AppError('Email is already registered.')
                user = User(full_name=full_name.strip(), email=email, phone_number=phone_number.strip(),
                            password_hash=hash_password(password))
                db.add(user)
                db.flush()
                return user.id

    def login(self, email, password):
        if not email or not password:
            raise AppError('Please fill in all fields.')
        with self.database.session() as db:
            with db.begin():
                user = db.scalar(select(User).where(User.email == normalize_email(email)))
                if not user:
                    raise AppError('Email or password is incorrect.')
                now = utcnow()
                if user.locked_until and user.locked_until > now:
                    raise AppError('Too many attempts. Try again later.')
                if not verify_password(password, user.password_hash):
                    user.failed_logins += 1
                    if user.failed_logins >= 5:
                        user.locked_until = now + timedelta(minutes=15)
                        user.failed_logins = 0
                    raise_message = 'Email or password is incorrect.'
                else:
                    raise_message = None
                if raise_message is None:
                    user.failed_logins = 0
                    user.locked_until = None
                    token = secrets.token_urlsafe(32)
                    db.add(LoginSession(token_hash=hash_token(token), user_id=user.id,
                                        expires_at=now + timedelta(hours=12)))
                    result = (token, user.id, user.full_name)
            if raise_message:
                raise AppError(raise_message)
            return result

    def get_user(self, token):
        with self.database.session() as db:
            s = db.scalar(select(LoginSession).where(LoginSession.token_hash == hash_token(token),
                LoginSession.revoked_at.is_(None), LoginSession.expires_at > utcnow()))
            return db.get(User, s.user_id) if s else None

    def logout(self, token):
        with self.database.session() as db:
            with db.begin():
                s = db.scalar(select(LoginSession).where(LoginSession.token_hash == hash_token(token)))
                if s:
                    s.revoked_at = utcnow()

    def request_reset(self, email):
        """Never expose account existence or a reset code in the GUI (UC04)."""
        email = normalize_email(email)
        if not is_valid_email(email):
            raise AppError('Please enter a valid email address.')
        if isinstance(self.mailer, SMTPMailer) and not os.environ.get('SMTP_HOST'):
            raise AppError('SMTP email delivery is not configured. See README and .env.example.')
        with self.database.session() as db:
            with db.begin():
                user = db.scalar(select(User).where(User.email == email))
                if not user:
                    return 
                code = f'{secrets.randbelow(100_000_000):08d}'
                salt = secrets.token_bytes(16)
                digest = hashlib.pbkdf2_hmac('sha256', code.encode(), salt, 100_000).hex()
                reset = PasswordReset(user_id=user.id, code_hash=digest, salt=salt.hex(),
                                      expires_at=utcnow() + timedelta(minutes=10))
                try:
                    self.mailer.send_reset_code(email, code)
                except Exception as exc:
                    raise AppError('Could not send the recovery email. Check SMTP settings and try again.') from exc
                db.add(reset)

    def resetPassword(self, email, code, new_password, confirmation):
        if new_password != confirmation or len(new_password) < 8:
            raise AppError('New password must be at least 8 characters and match confirmation.')
        with self.database.session() as db:
            with db.begin():
                user = db.scalar(select(User).where(User.email == normalize_email(email)))
                if not user:
                    raise AppError('Invalid or expired verification code.')
                reset = db.scalar(select(PasswordReset).where(
                    PasswordReset.user_id == user.id, PasswordReset.used_at.is_(None),
                    PasswordReset.expires_at > utcnow()).order_by(PasswordReset.id.desc()))
                if not reset or reset.attempts >= 5:
                    raise AppError('Invalid or expired verification code.')
                reset.attempts += 1
                digest = hashlib.pbkdf2_hmac('sha256', (code or '').strip().encode(),
                                             bytes.fromhex(reset.salt), 100_000).hex()
                valid = hmac.compare_digest(reset.code_hash, digest)
                if valid:
                    user.password_hash = hash_password(new_password)
                    reset.used_at = utcnow()
                    for active in db.scalars(select(LoginSession).where(
                        LoginSession.user_id == user.id, LoginSession.revoked_at.is_(None))):
                        active.revoked_at = utcnow()
            if not valid:
                raise AppError('Invalid or expired verification code.')
            return True