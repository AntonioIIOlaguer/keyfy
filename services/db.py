from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from services.models.models import Base

DATABASE_URL = "sqlite:///vaults.db"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)

Base.metadata.create_all(bind=engine)
