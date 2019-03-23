import sqlalchemy
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
import logging

sqlachemy_uri = "sqlite:///database/database.sqlite"

engine = sqlalchemy.create_engine(sqlachemy_uri)
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)

Base = declarative_base()
Base.metadata.bind = engine


def init_db():
    Base.metadata.create_all(bind=engine)
    logging.info('Database initialized.')
