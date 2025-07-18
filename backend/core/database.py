from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings
import aiosqlite
import sqlite3

# Database setup
engine = create_engine(
    settings.database_url, 
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database initialization
async def init_db():
    """Initialize the database with required tables"""
    Base.metadata.create_all(bind=engine)

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Async database operations
class AsyncDatabase:
    def __init__(self, db_path: str = "cybersec_toolkit.db"):
        self.db_path = db_path
    
    async def execute_query(self, query: str, params: tuple = ()):
        """Execute a query asynchronously"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(query, params)
            await db.commit()
            return cursor
    
    async def fetch_all(self, query: str, params: tuple = ()):
        """Fetch all results from a query"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(query, params)
            return await cursor.fetchall()
    
    async def fetch_one(self, query: str, params: tuple = ()):
        """Fetch one result from a query"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(query, params)
            return await cursor.fetchone()

async_db = AsyncDatabase()
