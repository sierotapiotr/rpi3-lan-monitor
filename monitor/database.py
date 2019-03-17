import sqlalchemy
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base

sqlachemy_uri = "sqlite:///database/database.db"

engine = sqlalchemy.create_engine(sqlachemy_uri)
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)

Base = declarative_base()
Base.metadata.bind = engine

def init_db():
    import monitor.models
    Base.metadata.create_all(bind=engine)
