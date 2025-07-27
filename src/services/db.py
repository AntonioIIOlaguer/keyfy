from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.services.models.models import Base

DATABASE_URL = "sqlite:///src/vaults.db"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)

Base.metadata.create_all(bind=engine)
