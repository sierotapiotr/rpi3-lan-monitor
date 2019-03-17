from flask_login import UserMixin
from monitor.database import Base
from sqlalchemy import Column, Integer, String

class User(UserMixin, Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(80), unique=True)
    password = Column(String(80))



