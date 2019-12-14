import logging

from flask import flash, redirect, render_template, url_for
from flask_login import current_user, login_required, login_user, logout_user

from database.database import Session, User
from monitor import app, login_manager
from monitor.forms import LoginForm


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('network_state'))
    form = LoginForm()
    if form.validate_on_submit():
        logging.info('LoginForm validated.')
        session = Session()
        user = session.query(User).filter_by(email=form.email.data).first()
        if user.check_password(form.password.data):
            login_user(user)
            Session.remove()
            logging.info('User successfully logged in.')
            return redirect(url_for("network_state"))
        else:
            flash('Podano niewłaściwy adres e-mail lub hasło.')
            Session.remove()
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@login_manager.user_loader
def load_user(id):
    session = Session()
    user = session.query(User).get(int(id))
    Session.remove()
    return user


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
