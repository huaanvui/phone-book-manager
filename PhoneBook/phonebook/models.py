from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, Table, Column, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


contact_groups = Table(
    'contact_groups', Base.metadata,
    Column('contact_id', ForeignKey('contacts.id', ondelete='CASCADE'), primary_key=True),
    Column('group_id', ForeignKey('groups.id', ondelete='CASCADE'), primary_key=True),
)


def utc_naive():
    """UTC naive datetime for compatibility with MySQL DATETIME columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def split_values(value):
    """UI supports a semicolon-separated list, including values from a merge."""
    if isinstance(value, (list, tuple, set)):
        raw = value
    else:
        raw = (value or '').replace('\n', ';').split(';')
    return list(dict.fromkeys(str(x).strip() for x in raw if str(x).strip()))


class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(180), nullable=False)
    username: Mapped[str | None] = mapped_column(String(254), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False, index=True)
    phone_number: Mapped[str] = mapped_column(String(40), default='')
    password_hash: Mapped[str] = mapped_column(String(250), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_naive)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    contacts: Mapped[list[Contact]] = relationship('Contact', back_populates='owner', cascade='all, delete-orphan')
    groups: Mapped[list[Group]] = relationship('Group', back_populates='owner', cascade='all, delete-orphan')
    sessions: Mapped[list[Session]] = relationship('Session', back_populates='owner', cascade='all, delete-orphan')

    def getProfile(self):
        return {'id': self.id, 'fullName': self.full_name, 'email': self.email, 'phone': self.phone_number}


class Session(Base):
    __tablename__ = 'sessions'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_naive)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    owner: Mapped[User] = relationship('User', back_populates='sessions')


class Contact(Base):
    __tablename__ = 'contacts'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(180), nullable=False, index=True)
    phone: Mapped[str] = mapped_column(String(300), default='')
    email: Mapped[str] = mapped_column(String(600), default='')
    address: Mapped[str] = mapped_column(Text, default='')
    avatar: Mapped[str] = mapped_column(String(400), default='')
    notes: Mapped[str] = mapped_column(Text, default='')
    is_favorite: Mapped[bool] = mapped_column(Boolean, default=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_naive)
    owner: Mapped[User] = relationship('User', back_populates='contacts')
    groups: Mapped[list[Group]] = relationship('Group', secondary=contact_groups, back_populates='contacts')

    @property
    def phones(self):
        return split_values(self.phone)

    @property
    def emails(self):
        return split_values(self.email)

    def validate(self):
        """UC22 included by UC05/UC07. Returns field-specific errors."""
        errors = {}
        if not self.name or not self.name.strip():
            errors['Name'] = 'Name is required.'
        if len(self.name or '') > 180:
            errors['Name'] = 'Name must contain at most 180 characters.'
        for number in self.phones:
            if not re.fullmatch(r'[\d +\-]{3,40}', number) or not re.search(r'\d', number):
                errors['Phone'] = 'Phone accepts digits, spaces, +, -, and parentheses (3–40 characters).'
                break
        for address in self.emails:
            if len(address) > 254 or not re.fullmatch(r'[^\s@;]+@[^\s@;]+\.[^\s@;]+', address):
                errors['Email'] = 'Email must have a valid address format (name@domain.tld).'
                break
        if self.avatar and not re.search(r'\.(jpg|jpeg|png|gif|webp)$', self.avatar, re.I):
            errors['Avatar'] = 'Avatar must be a JPG, PNG, GIF, or WEBP image.'
        if len(self.phone or '') > 300:
            errors['Phone'] = 'Too many phone numbers (maximum 300 characters).'
        if len(self.email or '') > 600:
            errors['Email'] = 'Too many email addresses (maximum 600 characters).'
        return errors

    def toggleFavorite(self):
        self.is_favorite = not self.is_favorite
        return self.is_favorite

    def moveToTrash(self):
        self.is_deleted = True
        self.deleted_at = utc_naive()

    def restore(self):
        self.is_deleted = False
        self.deleted_at = None


class Group(Base):
    __tablename__ = 'groups'
    __table_args__ = (UniqueConstraint('user_id', 'name', name='uq_user_group_name'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    owner: Mapped[User] = relationship('User', back_populates='groups')
    contacts: Mapped[list[Contact]] = relationship('Contact', secondary=contact_groups, back_populates='groups')

    def rename(self, name):
        self.name = name.strip()

    def addContact(self, contact):
        if contact not in self.contacts:
            self.contacts.append(contact)

    def removeContact(self, contact):
        if contact in self.contacts:
            self.contacts.remove(contact)


class TrashEntry(Base):
    """DFD Level 1 D4: active trash membership, not irreversible data deletion."""
    __tablename__ = 'trash'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    contact_id: Mapped[int] = mapped_column(ForeignKey('contacts.id', ondelete='CASCADE'), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    deleted_at: Mapped[datetime] = mapped_column(DateTime, default=utc_naive)


class PasswordReset(Base):
    __tablename__ = 'password_resets'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    salt: Mapped[str] = mapped_column(String(32), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime)