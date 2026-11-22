"""SQLAlchemy persistence for MySQL; SQLite is available in explicit demo/test mode."""
import os
from pathlib import Path
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import sessionmaker
from .models import Base
