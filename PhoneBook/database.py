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
