from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from .creds import pwd

DATABASE_URL = f"postgresql://postgres:{pwd}@localhost:5432/digital_twin"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()