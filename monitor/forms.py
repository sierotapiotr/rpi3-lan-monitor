from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Email, Length


class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[InputRequired(), Email(message="Nieprawidłowy adres email.")])
    password = PasswordField('Hasło', validators=[InputRequired(), Length(min=8, max=80)])

