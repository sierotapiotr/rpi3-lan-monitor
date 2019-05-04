from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from sqlalchemy.ext.declarative import declarative_base
import logging
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, Text, DateTime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from configparser import ConfigParser, ExtendedInterpolation

config = ConfigParser(interpolation=ExtendedInterpolation())
config.read('config/config_dev.ini')

sqlalchemy_uri = config['sqlalchemy']['SQLALCHEMY_URI_MONITOR']
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


class MonitoringSession(Base):
    __tablename__ = 'monitoring_session'
    id = Column(Integer, primary_key=True)
    datetime = Column(DateTime)
    detected_hosts = relationship("DetectedHost", backref="session")


class DetectedHost(Base):
    __tablename__ = 'detected_host'
    id = Column(Integer, primary_key=True)
    address = Column(String(20))
    mac_address = Column(String(20))
    session_id = Column(Integer, ForeignKey("monitoring_session.id"))
    open_ports = relationship("OpenPort", backref="host")


class OpenPort(Base):
    __tablename__ = 'open_port'
    id = Column(Integer, primary_key=True)
    l3_protocol = Column(String(10))
    port = Column(Integer)
    host_id = Column(Integer, ForeignKey("detected_host.id"))


class TrustedHost(Base):
    __tablename__ = 'trusted_host'
    id = Column(Integer, primary_key=True)
    mac_address = Column(String(20))
    confirmed = Column(Boolean)


def init_db():
    Base.metadata.create_all(bind=engine)
    logging.info('Database initialized.')
