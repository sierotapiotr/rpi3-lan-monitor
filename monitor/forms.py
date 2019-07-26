from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Email, Length


class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[InputRequired(), Email(message="Nieprawidłowy adres email.")])
    password = PasswordField('Hasło', validators=[InputRequired(), Length(min=8, max=80)])


class PasswordResetForm(FlaskForm):
    current_password = PasswordField('Obecne hasło', validators=[InputRequired(), Length(min=8, max=80)])
    new_password = PasswordField('Nowe hasło', validators=[InputRequired(), Length(min=8, max=80)])
    repeated_new_password = PasswordField('Powtórzone nowe hasło', validators=[InputRequired(), Length(min=8, max=80)])


class SettingsForm(FlaskForm):
    target = StringField('Pula monitorowanych adresów:', validators=[InputRequired()])
