from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, Text, DateTime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from configparser import ConfigParser
import logging
import os

current_file_path = os.path.dirname(os.path.abspath(__file__))
config = ConfigParser()
config.read(current_file_path + '/../app_config.ini')

sqlalchemy_uri = config['sqlalchemy']['SQLALCHEMY_DATABASE_URI']
engine = create_engine(sqlalchemy_uri)
session_factory = sessionmaker(bind=engine)
Session = scoped_session(session_factory)

Base = declarative_base()
Base.metadata.bind = engine


class User(UserMixin, Base):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}
    id = Column(Integer, primary_key=True)
    email = Column(String(80), unique=True)
    password = Column(String(80))
    monitoring_activated = Column(Boolean)
    network_learning = Column(String(10))
    target = Column(Text)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class DetectedHost(Base):
    __tablename__ = 'detected_host'
    id = Column(Integer, primary_key=True)
    address = Column(String(20))
    confirmed = Column(Boolean)
    last_seen = Column(DateTime)
    mac_address = Column(String(20), unique=True)
    manufacturer = Column(Text)
    open_ports = relationship("OpenPort", backref="host")
    cracked_passwords = relationship("CrackedPassword", backref="host")


class OpenPort(Base):
    __tablename__ = 'open_port'
    id = Column(Integer, primary_key=True)
    l3_protocol = Column(String(10))
    port = Column(Integer)
    service = Column(Text)
    suspicious = Column(Boolean)
    host_id = Column(Integer, ForeignKey("detected_host.id"))


class CrackedPassword(Base):
    __tablename__ = 'cracked_password'
    id = Column(Integer, primary_key=True)
    login = Column(Text)
    service = Column(Text)
    host_id = Column(Integer, ForeignKey("detected_host.id"))


def init_db():
    Base.metadata.create_all(bind=engine)
    logging.info('Database initialized.')
