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

class ContactService:
    """UC05-13, UC20, UC22-24; new records belong to one owner."""
    def __init__(self, database):
        self.database = database

    def create(self, user_id, *, name, phone='', email='', address='', avatar='', notes='', group_ids=()):
        contact = Contact(user_id=user_id, name=(name or '').strip(), phone='; '.join(split_values(phone)),
                          email='; '.join(split_values(email)), address=address.strip(), avatar=avatar,
                          notes=notes.strip(), is_favorite=False, is_deleted=False)
        errors = contact.validate()
        if errors: raise ValidationError(errors)
        with self.database.session() as db:
            with db.begin():
                for gid in set(map(int, group_ids)):
                    contact.groups.append(_owned_group(db, user_id, gid))
                db.add(contact)
                db.flush()
                return contact.id

    def get(self, user_id, contact_id, trash=False):
        with self.database.session() as db:
            return _owned_contact(db, user_id, contact_id, deleted=trash)

    def update(self, user_id, contact_id, *, name, phone='', email='', address='', avatar='', notes='', group_ids=None):
        with self.database.session() as db:
            with db.begin():
                c = _owned_contact(db, user_id, contact_id)
                old = (c.name, c.phone, c.email, c.address, c.avatar, c.notes)
                c.name, c.phone, c.email = (name or '').strip(), '; '.join(split_values(phone)), '; '.join(split_values(email))
                c.address, c.avatar, c.notes = address.strip(), avatar, notes.strip()
                errors = c.validate()
                if errors: raise ValidationError(errors)
                if group_ids is not None:
                    c.groups = [_owned_group(db, user_id, gid) for gid in set(map(int, group_ids))]
                return c.id

    def delete(self, user_id, contact_id, confirmed=False):
        if not confirmed:
            raise AppError('Deletion requires explicit confirmation (UC23).')
        with self.database.session() as db:
            with db.begin():
                c = _owned_contact(db, user_id, contact_id)
                c.moveToTrash()
                db.add(TrashEntry(contact_id=c.id, user_id=user_id, deleted_at=c.deleted_at))
                return True

    def restore(self, user_id, contact_id):
        with self.database.session() as db:
            with db.begin():
                c = _owned_contact(db, user_id, contact_id, deleted=True)
                c.restore()
                db.execute(sql_delete(TrashEntry).where(
                    TrashEntry.user_id == user_id, TrashEntry.contact_id == contact_id))
                return True

    def toggle_favorite(self, user_id, contact_id):
        with self.database.session() as db:
            with db.begin():
                return _owned_contact(db, user_id, contact_id).toggleFavorite()

    def list_contacts(self, user_id, *, keyword='', group_id=None, favorites=False, sort='A-Z', trash=False):
        with self.database.session() as db:
            q = select(Contact).options(selectinload(Contact.groups)).where(
                Contact.user_id == user_id, Contact.is_deleted == trash)
            if group_id is not None:
                _owned_group(db, user_id, int(group_id))
                q = q.join(Contact.groups).where(Group.id == int(group_id))
            if favorites:
                q = q.where(Contact.is_favorite.is_(True))
            if keyword and keyword.strip():
                s = '%' + keyword.strip().lower().replace('\\','\\\\').replace('%','\\%').replace('_','\\_') + '%'
                q = q.where(or_(func.lower(Contact.name).like(s, escape='\\'),
                                func.lower(Contact.phone).like(s, escape='\\'),
                                func.lower(Contact.email).like(s, escape='\\')))
            q = q.order_by(func.lower(Contact.name).desc() if sort == 'Z-A' else func.lower(Contact.name).asc(), Contact.id)
            return list(db.scalars(q).unique().all())

    def search(self, user_id, keyword):  
        return self.list_contacts(user_id, keyword=keyword)

    def filter(self, user_id, group_id=None, favorites=False):
        return self.list_contacts(user_id, group_id=group_id, favorites=favorites)

    def sort(self, user_id, order='A-Z'):
        return self.list_contacts(user_id, sort=order)

    def findDuplicates(self, user_id):
        """UC24: same normalized phone or email, including multi-valued merged contacts.

        A union-find clusters transitive matches without merging automatically.
        """
        contacts = self.list_contacts(user_id)
        ids = {c.id: c.id for c in contacts}
        def root(x):
            while ids[x] != x:
                ids[x] = ids[ids[x]]
                x = ids[x]
            return x
        def union(a, b):
            a, b = root(a), root(b)
            if a != b: ids[b] = a
        keys = {}
        for c in contacts:
            for phone in c.phones:
                norm = normalize_phone(phone)
                if norm:
                    key = ('phone', norm)
                    if key in keys: union(c.id, keys[key])
                    else: keys[key] = c.id
            for email in c.emails:
                norm = normalize_email(email)
                if norm:
                    key = ('email', norm)
                    if key in keys: union(c.id, keys[key])
                    else: keys[key] = c.id
        groups = defaultdict(list)
        for c in contacts:
            groups[root(c.id)].append(c)
        return [g for g in groups.values() if len(g) > 1]

    def merge(self, user_id, contact_ids, *, name=None, phone=None, email=None, address=None, notes=None):
        """UC20: preserve ALL phone/email values, group memberships and originals in D4."""
        unique_ids = list(dict.fromkeys(int(x) for x in contact_ids))
        if len(unique_ids) < 2:
            raise AppError('Select two or more contacts to merge.')
        with self.database.session() as db:
            with db.begin():
                existing = [_owned_contact(db, user_id, cid) for cid in unique_ids]
                def join_unique(values):
                    found, seen = [], set()
                    for x in values:
                        key = x.casefold()
                        if key not in seen: seen.add(key); found.append(x)
                    return '; '.join(found)
                phones = join_unique(p for c in existing for p in c.phones)
                emails = join_unique(e for c in existing for e in c.emails)
                group_map = {g.id: g for c in existing for g in c.groups}
                merged = Contact(user_id=user_id, name=(name if name is not None else existing[0].name).strip(),
                                 phone=phones if phone is None else '; '.join(split_values(phone)),
                                 email=emails if email is None else '; '.join(split_values(email)),
                                 address=address if address is not None else next((c.address for c in existing if c.address), ''),
                                 notes=notes if notes is not None else '\n'.join(dict.fromkeys(c.notes for c in existing if c.notes)),
                                 avatar=next((c.avatar for c in existing if c.avatar), ''),
                                 is_favorite=any(c.is_favorite for c in existing))
                errors = merged.validate()
                if errors: raise ValidationError(errors)
                merged.groups.extend(group_map.values())
                db.add(merged)
                db.flush()
                for c in existing:
                    c.moveToTrash()
                    db.add(TrashEntry(contact_id=c.id, user_id=user_id, deleted_at=c.deleted_at))
                return merged.id

    def duplicate_of(self, user_id, phone='', email='', exclude_id=None):
        phones = {normalize_phone(p) for p in split_values(phone)} - {''}
        emails = {normalize_email(e) for e in split_values(email)} - {''}
        if not phones and not emails: return None
        for c in self.list_contacts(user_id):
            if c.id != exclude_id and (phones & {normalize_phone(p) for p in c.phones}
                                     or emails & {normalize_email(e) for e in c.emails}):
                return c
        return None

class GroupService:
    """UC14-17. The junction table supports many-to-many contact-group membership."""
    def __init__(self, database):
        self.database = database

    def list_groups(self, user_id):
        with self.database.session() as db:
            return list(db.scalars(select(Group).where(Group.user_id == user_id).order_by(func.lower(Group.name))).all())

    def create(self, user_id, name):
        name = (name or '').strip()
        if not name: raise AppError('Group name is required.')
        if len(name) > 100: raise AppError('Group name must be shorter than 100 characters.')
        with self.database.session() as db:
            with db.begin():
                if db.scalar(select(Group.id).where(Group.user_id == user_id, func.lower(Group.name) == name.lower())):
                    raise AppError('Group name already exists.')
                group = Group(user_id=user_id, name=name)
                db.add(group); db.flush()
                return group.id

    def rename(self, user_id, group_id, name):
        name = (name or '').strip()
        if not name: raise AppError('Group name is required.')
        if len(name) > 100: raise AppError('Group name must be shorter than 100 characters.')
        with self.database.session() as db:
            with db.begin():
                group = _owned_group(db, user_id, group_id)
                match = db.scalar(select(Group.id).where(Group.user_id == user_id,
                    Group.id != group_id, func.lower(Group.name) == name.lower()))
                if match: raise AppError('Group name already exists.')
                group.rename(name)

    def delete(self, user_id, group_id, confirmed=False):
        if not confirmed: raise AppError('Deleting a group requires confirmation.')
        with self.database.session() as db:
            with db.begin():
                group = _owned_group(db, user_id, group_id)
                db.delete(group)

    def add_contact(self, user_id, group_id, contact_ids):
        with self.database.session() as db:
            with db.begin():
                group = _owned_group(db, user_id, group_id)
                for cid in set(map(int, contact_ids)):
                    group.addContact(_owned_contact(db, user_id, cid))

    def remove_contact(self, user_id, group_id, contact_id):
        with self.database.session() as db:
            with db.begin():
                group = _owned_group(db, user_id, group_id)
                group.removeContact(_owned_contact(db, user_id, contact_id))

class ImportExportService:
    """UC18/19; only CSV and VCF, no implicit duplicate merging."""
    MAX_IMPORT_BYTES = 20_000_000

    def __init__(self, database, contact_service):
        self.database = database
        self.contacts = contact_service

    @staticmethod
    def _unescape_vcard(value):
        escapes = {'n': '\n', 'N': '\n', ',': ',', ';': ';', '\\': '\\'}
        return re.sub(r'\\([nN,;\\])', lambda match: escapes[match[1]], value)

    @staticmethod
    def _escape_vcard(value):
        return str(value or '').replace('\\','\\\\').replace('\n','\\n').replace(';','\\;').replace(',','\\,')

    def importFile(self, user_id, filepath):
        file = Path(filepath)
        if file.suffix.lower() not in ('.csv', '.vcf'):
            raise AppError('File type is not supported. Use .csv or .vcf.')
        if not file.is_file() or file.stat().st_size == 0:
            raise AppError('File is missing or empty.')
        if file.stat().st_size > self.MAX_IMPORT_BYTES:
            raise AppError('File is too large (limit: 20 MB).')
        try:
            if file.suffix.lower() == '.csv':
                with file.open('r', encoding='utf-8-sig', newline='') as stream:
                    reader = csv.DictReader(stream)
                    if not reader.fieldnames: raise AppError('CSV file has no header.')
                    rows = [
                        {str(key or '').strip().lower(): str(v or '').strip() for key, v in r.items()}
                        for r in reader
                    ]
            else:
                content = file.read_text(encoding='utf-8-sig')
                unfolded = re.sub(r'\r?\n[ \t]', '', content)
                rows, current = [], None
                for line in unfolded.splitlines():
                    line = line.strip('\r')
                    if line.upper() == 'BEGIN:VCARD': current = {'phones':[], 'emails':[]}
                    elif line.upper() == 'END:VCARD' and current is not None:
                        rows.append({'name': current.get('name',''), 'phone': '; '.join(current['phones']),
                                     'email': '; '.join(current['emails']), 'address':current.get('address',''),
                                     'notes':current.get('notes','')})
                        current = None
                    elif current is not None and ':' in line:
                        prop, val = line.split(':', 1)
                        prop = prop.split(';')[0].upper()
                        if prop == 'ADR':
                            parts = re.findall(r'(?:\\.|[^;\\])+', val)
                            current['address'] = ', '.join(self._unescape_vcard(part) for part in parts)
                            continue
                        val = self._unescape_vcard(val)
                        if prop == 'FN': current['name'] = val
                        elif prop == 'TEL': current['phones'].append(val)
                        elif prop == 'EMAIL': current['emails'].append(val)
                        elif prop == 'NOTE': current['notes'] = val
        except (UnicodeDecodeError, csv.Error, OSError) as exc:
            raise AppError('File is damaged or cannot be read as UTF-8 CSV/VCF.') from exc
        if not rows:
            raise AppError('The file has no valid contact records.')
        imported, skipped, issues = 0, 0, []
        for i, row in enumerate(rows, 1):
            try:
                self.contacts.create(user_id,
                    name=row.get('name') or row.get('full_name') or row.get('fullname') or '',
                    phone=row.get('phone') or row.get('phone_number') or '',
                    email=row.get('email') or '', address=row.get('address') or '',
                    notes=row.get('notes') or '')
                imported += 1
            except (AppError, ValueError, IntegrityError) as exc:
                skipped += 1
                if len(issues) < 12: issues.append(f'Row {i}: {str(exc)[:110]}')
        return {'imported':imported, 'skipped':skipped, 'errors':issues}

    def exportFile(self, user_id, filepath, group_id=None):
        file = Path(filepath)
        if file.suffix.lower() not in ('.csv', '.vcf'):
            raise AppError('Choose a .csv or .vcf output file.')
        rows = self.contacts.list_contacts(user_id, group_id=group_id)
        if not rows:
            raise AppError('No contact to export.')
        try:
            if file.suffix.lower() == '.csv':
                with file.open('w', encoding='utf-8-sig', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['name','phone','email','address','notes'])
                    for c in rows: writer.writerow([c.name,c.phone,c.email,c.address,c.notes])
            else:
                with file.open('w', encoding='utf-8', newline='\r\n') as f:
                    for c in rows:
                        lines = ['BEGIN:VCARD', 'VERSION:3.0', 'FN:' + self._escape_vcard(c.name)]
                        for p in c.phones: lines.append('TEL:' + self._escape_vcard(p))
                        for e in c.emails: lines.append('EMAIL:' + self._escape_vcard(e))
                        if c.address: lines.append('ADR:;;' + self._escape_vcard(c.address) + ';;;;')
                        if c.notes: lines.append('NOTE:' + self._escape_vcard(c.notes))
                        lines.append('END:VCARD')
                        f.write('\n'.join(lines) + '\n')
        except OSError as exc:
            raise AppError('Could not write the export file.') from exc
        return len(rows)

class EmailService:
    """UC21: open user's external mail app with receiver pre-filled."""
    def __init__(self, contact_service):
        self.contacts = contact_service

    def send_email(self, user_id, contact_id):
        contact = self.contacts.get(user_id, contact_id)
        if not contact.emails:
            raise AppError('This contact does not have an email address.')
        url = 'mailto:' + quote(contact.emails[0], safe='@.+_-')
        success = webbrowser.open(url)
        if not success:
            raise AppError('No default email application is configured on this computer.')
        return True
