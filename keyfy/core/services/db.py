from pathlib import Path

from platformdirs import user_data_dir
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from keyfy.core.services.models.models import Base

# Set up DB path
app_name = "keyfy"
db_path = Path(user_data_dir(app_name)) / "vaults.db"

# Ensure directory exists
db_path.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{db_path}"

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)

Base.metadata.create_all(bind=engine)
