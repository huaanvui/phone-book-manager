"""SQLAlchemy persistence for MySQL; SQLite is available in explicit demo/test mode."""
import os
from pathlib import Path
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import sessionmaker
from .models import Base

class Database:
    def __init__(self, url: str):
        self.url = url
        connect_args = {'check_same_thread': False} if url.startswith('sqlite') else {}
        self.engine = create_engine(url, connect_args=connect_args, pool_pre_ping=True, future=True)
        if url.startswith('sqlite'):
            @event.listens_for(self.engine, 'connect')
            def sqlite_fk(conn, rec):
                conn.execute('PRAGMA foreign_keys=ON')
        self.SessionLocal = sessionmaker(self.engine, expire_on_commit=False)


    def initialize(self):
        Base.metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            schema = inspect(connection)
            if 'username' not in {column['name'] for column in schema.get_columns('users')}:
                connection.exec_driver_sql('ALTER TABLE users ADD COLUMN username VARCHAR(254)')
            if 'ix_users_username' not in {index['name'] for index in schema.get_indexes('users')}:
                connection.exec_driver_sql('CREATE UNIQUE INDEX ix_users_username ON users (username)')
            connection.exec_driver_sql('UPDATE users SET username = email WHERE username IS NULL')

    def session(self):
        return self.SessionLocal()

    def dispose(self):
        self.engine.dispose()
