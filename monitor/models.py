from flask_login import UserMixin
from monitor import login
from monitor.database import Base, Session
from sqlalchemy import Column, Integer, String, Boolean
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, Base):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}
    id = Column(Integer, primary_key=True)
    email = Column(String(80), unique=True)
    password = Column(String(80))
    monitoring_activated = Column(Boolean)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


@login.user_loader
def load_user(id):
    session = Session()
    user = session.query(User).get(int(id))
    Session.remove()
    return user