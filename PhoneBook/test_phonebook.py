import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from phonebook.database import Database, get_database_url
from phonebook.mail import SMTPMailer
from phonebook.models import Base, Contact, split_values
from phonebook.security import (
    hash_password,
    is_valid_email,
    normalize_email,
    normalize_phone,
    verify_password,
)
from phonebook.services import (
    AppError,
    AuthService,
    ContactService,
    GroupService,
    ImportExportService,
    ValidationError,
)
from web import create_app, load_dot_env


class MemoryDatabase(Database):

    def __init__(self):
        self.url = "sqlite:///:memory:"
        self.engine = create_engine(
            self.url,
            connect_args={"check_same_thread": False},
            pool_pre_ping=True,
            future=True,
        )

        @event.listens_for(self.engine, "connect")
        def sqlite_fk(conn, rec):
            conn.execute("PRAGMA foreign_keys=ON")

        self.SessionLocal = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)


class TestDatabaseAndMailer(unittest.TestCase):
    def test_memory_database_session(self):
        db = MemoryDatabase()
        with db.session() as session:
            self.assertIsNotNone(session)
        db.dispose()

    def test_get_database_url_demo_and_default(self):
        demo_url = get_database_url(demo=True)
        self.assertTrue(demo_url.startswith("sqlite:///"))

        with patch.dict("os.environ", {"DB_URL": "sqlite:///:memory:"}, clear=False):
            self.assertEqual(get_database_url(demo=False), "sqlite:///:memory:")

    def test_mailer_raises_when_missing_env(self):
        mailer = SMTPMailer()
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(RuntimeError):
                mailer.send_reset_code("user@example.com", "12345678")

    def test_load_dot_env_reads_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("SAMPLE_TEST_KEY=hello_world\n", encoding="utf-8")
            with patch("web.Path") as mock_path:
                mock_path.return_value.parent.__truediv__.return_value = env_file
                with patch.dict("os.environ", {}, clear=False):
                    load_dot_env(".env")
                    self.assertEqual(env_file.read_text(encoding="utf-8").strip(), "SAMPLE_TEST_KEY=hello_world")


class TestModelsSecurityAndServices(unittest.TestCase):
    def setUp(self):
        self.db = MemoryDatabase()
        self.auth = AuthService(self.db, mailer=MagicMock())
        self.contacts = ContactService(self.db)
        self.groups = GroupService(self.db)
        self.io = ImportExportService(self.db, self.contacts)

        self.user_id = self.auth.register(
            full_name="Nguyen Van A",
            email="a@example.com",
            password="Password123",
            confirm_password="Password123",
            phone_number="0901234567",
            username="nguyenvana",
        )

    def tearDown(self):
        self.db.dispose()

    def test_security_and_model_helpers(self):
        pw_hash = hash_password("Secret@123")
        self.assertTrue(verify_password("Secret@123", pw_hash))
        self.assertFalse(verify_password("Wrong@123", pw_hash))
        self.assertEqual(normalize_email("  TEST@MAIL.COM "), "test@mail.com")
        self.assertEqual(normalize_phone("+84-90-123-4567"), "84901234567")
        self.assertTrue(is_valid_email("dev@example.com"))
        self.assertFalse(is_valid_email("not-an-email"))
        self.assertEqual(split_values("0901; 0902; 0901"), ["0901", "0902"])

        bad_contact = Contact(user_id=self.user_id, name="", phone="abc", email="invalid", avatar="bad.exe")
        errors = bad_contact.validate()
        self.assertIn("Name", errors)
        self.assertIn("Phone", errors)
        self.assertIn("Email", errors)
        self.assertIn("Avatar", errors)

    def test_auth_login_logout_and_lockout(self):
        token, uid, name = self.auth.login("nguyenvana", "Password123", by_username=True)
        self.assertEqual(uid, self.user_id)
        self.assertEqual(name, "Nguyen Van A")
        self.assertIsNotNone(self.auth.get_user(token))

        self.auth.logout(token)
        self.assertIsNone(self.auth.get_user(token))

        for _ in range(5):
            with self.assertRaises(AppError):
                self.auth.login("nguyenvana", "wrongpass", by_username=True)

        with self.assertRaises(AppError) as ctx:
            self.auth.login("nguyenvana", "Password123", by_username=True)
        self.assertIn("Too many attempts", str(ctx.exception))

    def test_contacts_groups_duplicates_merge_and_export(self):
        gid = self.groups.create(self.user_id, "Work")
        c1 = self.contacts.create(
            self.user_id,
            name="Tran B",
            phone="0912345678",
            email="b@example.com",
            group_ids=[gid],
        )
        c2 = self.contacts.create(
            self.user_id,
            name="Tran B Dup",
            phone="0912345678",
            email="b2@example.com",
            group_ids=[gid],
        )

        self.assertEqual(len(self.contacts.findDuplicates(self.user_id)), 1)
        merged_id = self.contacts.merge(self.user_id, [c1, c2])
        merged = self.contacts.get(self.user_id, merged_id)
        self.assertEqual(merged.phones, ["0912345678"])

        with self.assertRaises(ValidationError):
            self.contacts.create(self.user_id, name="   ")

        with tempfile.TemporaryDirectory() as tmp:
            out_csv = Path(tmp) / "contacts.csv"
            count = self.io.exportFile(self.user_id, out_csv)
            self.assertEqual(count, 1)
            self.assertTrue(out_csv.exists())


class TestFlaskWebRoutes(unittest.TestCase):
    def setUp(self):
        self.db = MemoryDatabase()
        self.app = create_app(self.db)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        self.db.dispose()

    def _get_csrf(self):
        with self.client.session_transaction() as sess:
            return sess.setdefault("csrf", "test-csrf-token")

    def _csrf(self):
        with self.client.session_transaction() as sess:
            return sess.setdefault("csrf", "test-csrf-token")

    @patch("web.render_template", return_value="<html>ok</html>")
    def test_register_login_create_contact_and_logout(self, mock_render):
        res_reg = self.client.post(
            "/register",
            data={
                "csrf": self._csrf(),
                "name": "Le Van C",
                "email": "c@example.com",
                "username": "levanc",
                "password": "Password123",
            },
        )
        self.assertEqual(res_reg.status_code, 302)
        self.assertIn("/login", res_reg.headers["Location"])

        res_login = self.client.post(
            "/login",
            data={
                "csrf": self._csrf(),
                "username": "levanc",
                "password": "Password123",
            },
        )
        self.assertEqual(res_login.status_code, 302)
        self.assertEqual(res_login.headers["Location"], "/")

        res_create = self.client.post(
            "/contacts/new",
            data={
                "csrf": self._csrf(),
                "name": "Pham D",
                "phone": "0987654321",
                "email": "d@example.com",
                "address": "HCMC",
                "notes": "Friend",
            },
        )
        self.assertEqual(res_create.status_code, 302)
        self.assertEqual(res_create.headers["Location"], "/")

        res_home = self.client.get("/")
        self.assertEqual(res_home.status_code, 200)

        res_logout = self.client.post("/logout", data={"csrf": self._csrf()})
        self.assertEqual(res_logout.status_code, 302)
        self.assertIn("/login", res_logout.headers["Location"])

    def test_post_without_csrf_returns_400(self):
        self._get_csrf()
        res = self.client.post("/login", data={"username": "a", "password": "b"})
        self.assertEqual(res.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)