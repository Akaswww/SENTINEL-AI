
import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.engine import URL

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

database_url = URL.create(
    drivername="postgresql+psycopg",
    username=os.environ["DATABASE_USER"],
    password=os.environ["POSTGRES_PASSWORD"],
    host=os.getenv("DATABASE_HOST", "127.0.0.1"),
    port=int(os.getenv("DATABASE_PORT", "5433")),
    database=os.getenv("DATABASE_NAME", "sentinel_db"),
)

engine = create_engine(
    database_url,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass
