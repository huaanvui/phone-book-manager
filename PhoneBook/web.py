"""Local browser entry point for the phone book."""
import argparse
from io import BytesIO
import os
import secrets
from pathlib import Path
from tempfile import TemporaryDirectory

from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, session, url_for

from phonebook.database import Database, get_database_url
from phonebook.services import AppError, AuthService, ContactService, GroupService, ImportExportService


CONTACT_FILE_TYPES = {'csv': 'text/csv; charset=utf-8', 'vcf': 'text/vcard; charset=utf-8'}
CONTACT_FIELDS = ('name', 'phone', 'email', 'address', 'notes')


def create_app(database):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get('PHONEBOOK_WEB_SECRET') or secrets.token_hex(32),
        SESSION_COOKIE_NAME='phonebook_session',
        SESSION_COOKIE_SAMESITE='Lax',
    )
    auth = AuthService(database)
    contacts = ContactService(database)
    groups = GroupService(database)
    transfers = ImportExportService(database, contacts)

    @app.before_request
    def load_user():
        if request.endpoint == 'static':
            return
        token = session.get('token')
        g.user = auth.get_user(token) if token else None
        protected = {'index', 'contact_form', 'contact_action', 'logout', 'import_contacts', 'export_contacts'}
        if g.user is None and request.endpoint in protected:
            return redirect(url_for('login'))
        if request.endpoint == 'import_contacts':
            request.max_content_length = transfers.MAX_IMPORT_BYTES + 64 * 1024

        csrf = session.setdefault('csrf', secrets.token_urlsafe(32))
        if request.method == 'POST' and not secrets.compare_digest(
            csrf.encode('ascii'), request.form.get('csrf', '').encode('utf-8')
        ):
            abort(400)

    @app.route('/login', methods=['GET', 'POST'])
    @app.route('/register', methods=['GET', 'POST'], endpoint='register')
    def login():
        registering = request.endpoint == 'register'
        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            try:
                if registering:
                    auth.register(request.form.get('name', ''), request.form.get('email', ''),
                                  password, password, username=username)
                    flash('Account created. You can now log in.')
                    return redirect(url_for('login'))
                token, _, _ = auth.login(username, password, by_username=True)
                if session.get('token'):
                    auth.logout(session['token'])
                session.clear()
                session['token'] = token
                return redirect(url_for('index'))
            except AppError as exc:
                return render_template('auth.html', registering=registering, error=str(exc)), 400
        return render_template('auth.html', registering=registering)

    @app.post('/logout')
    def logout():
        auth.logout(session['token'])
        session.clear()
        return redirect(url_for('login'))

    @app.get('/')
    def index():
        query = request.args.get('q', '')
        view = request.args.get('view', 'all')
        group_id = request.args.get('group', type=int)
        order = request.args.get('sort', 'A-Z')
        try:
            records = contacts.list_contacts(g.user.id, keyword=query, group_id=group_id,
                                             favorites=view == 'favorites', sort=order,
                                             trash=view == 'trash')
        except AppError as exc:
            flash(str(exc), 'error')
            return redirect(url_for('index'))
        return render_template('contacts.html', records=records, groups=groups.list_groups(g.user.id),
                               query=query, view=view, group_id=group_id, order=order)

    @app.errorhandler(413)
    def upload_too_large(error):
        if request.endpoint != 'import_contacts':
            return error
        flash('File is too large (limit: 20 MB).', 'error')
        return redirect(url_for('index'), code=303)

    @app.post('/contacts/import')
    def import_contacts():
        upload = request.files.get('file')
        if not upload or not upload.filename:
            flash('Choose a CSV or VCF file to import.', 'error')
            return redirect(url_for('index'), code=303)

        extension = Path(upload.filename).suffix.lower().lstrip('.')
        if extension not in CONTACT_FILE_TYPES:
            flash('File type is not supported. Use .csv or .vcf.', 'error')
            return redirect(url_for('index'), code=303)

        try:
            with TemporaryDirectory() as directory:
                path = Path(directory) / f'contacts.{extension}'
                upload.save(path)
                result = transfers.importFile(g.user.id, path)
            imported, skipped = result['imported'], result['skipped']
            flash(f'Imported {imported} contact(s). Skipped {skipped} row(s).',
                  'error' if not imported else 'message')
        except AppError as exc:
            flash(str(exc), 'error')
        except OSError:
            flash('Could not process the uploaded file.', 'error')
        return redirect(url_for('index'), code=303)

    @app.get('/contacts/export')
    def export_contacts():
        extension = request.args.get('format', '')
        if extension not in CONTACT_FILE_TYPES:
            flash('Choose CSV or VCF to export.', 'error')
            return redirect(url_for('index'))

        group = request.args.get('group', '')
        group_id = request.args.get('group', type=int)
        if group and group_id is None:
            flash('Choose a valid group to export.', 'error')
            return redirect(url_for('index'))

        filename = f'contacts.{extension}'
        try:
            with TemporaryDirectory() as directory:
                path = Path(directory) / filename
                transfers.exportFile(g.user.id, path, group_id=group_id)
                content = BytesIO(path.read_bytes())
        except AppError as exc:
            flash(str(exc), 'error')
            return redirect(url_for('index'))
        except OSError:
            flash('Could not prepare the download.', 'error')
            return redirect(url_for('index'))
        response = send_file(content, mimetype=CONTACT_FILE_TYPES[extension],
                             as_attachment=True, download_name=filename)
        response.cache_control.no_store = True
        return response

    @app.route('/contacts/new', methods=['GET', 'POST'])
    @app.route('/contacts/<int:contact_id>/edit', methods=['GET', 'POST'])
    def contact_form(contact_id=None):
        uid = g.user.id
        contact = None
        if contact_id is not None:
            try:
                contact = contacts.get(uid, contact_id)
            except AppError:
                abort(404)
        values = {field: getattr(contact, field, '') for field in CONTACT_FIELDS}
        available_groups = groups.list_groups(uid)
        selected = [group.id for group in contact.groups] if contact else []
        error = None
        if request.method == 'POST':
            values = {field: request.form.get(field, '') for field in CONTACT_FIELDS}
            selected = request.form.getlist('groups', type=int)
            try:
                if contact is None:
                    contacts.create(uid, group_ids=selected, **values)
                else:
                    contacts.update(uid, contact_id, avatar=contact.avatar, group_ids=selected, **values)
                flash('Contact saved.')
                return redirect(url_for('index'))
            except AppError as exc:
                error = str(exc)
        return render_template('contact_form.html', contact=contact, values=values, error=error,
                               groups=available_groups, selected=selected), 400 if error else 200

    @app.post('/contacts/<int:contact_id>/<any(favorite,trash,restore):action>')
    def contact_action(contact_id, action):
        uid = g.user.id
        try:
            if action == 'favorite':
                contacts.toggle_favorite(uid, contact_id)
            elif action == 'trash':
                contacts.delete(uid, contact_id, confirmed=True)
                flash('Contact moved to Trash.')
            else:
                contacts.restore(uid, contact_id)
                flash('Contact restored.')
        except AppError as exc:
            flash(str(exc), 'error')
        return redirect(url_for('index', view='trash' if action == 'restore' else 'all'))

    return app


def load_dot_env(file='.env'):
    """Read plain key=value settings without adding a dependency or overwriting OS vars."""
    path=Path(__file__).parent/file
    if not path.exists():return
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        line=line.strip()
        if not line or line.startswith('#') or '=' not in line:continue
        key,val=line.split('=',1)
        key=key.strip();val=val.strip().strip('"').strip("'")
        os.environ.setdefault(key,val)


def main():
    parser = argparse.ArgumentParser(description='Phone Book browser interface')
    parser.add_argument('--demo', action='store_true', help='use the existing local SQLite demo')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    load_dot_env()
    database = Database(get_database_url(demo=args.demo))
    try:
        database.initialize()
        create_app(database).run(host='127.0.0.1', port=args.port)
    finally:
        database.dispose()


if __name__ == '__main__':
    main()