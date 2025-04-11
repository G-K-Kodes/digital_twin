from db.connection import engine, Base
from db.schemas import Netflow

def init_db():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_db()
    print("Database initialized.")