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