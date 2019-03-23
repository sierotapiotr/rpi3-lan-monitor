from flask import flash, redirect, url_for, render_template
from flask_login import login_user, logout_user, login_required, current_user
from monitor import app
from monitor.forms import LoginForm
from monitor.models import User
from monitor.database import Session
import logging

@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    user_name = current_user.email.split("@")[0]
    return render_template("dashboard.html", name=user_name)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        session = Session()
        user = session.query(User).filter_by(email=form.email.data).first()
        user.set_password(form.password.data)
        session.commit()
        Session.remove()
        session = Session()
        user = session.query(User).filter_by(email=form.email.data).first()

        logging.info(user.password)
        if user.check_password(form.password.data):
            login_user(user)
            Session.remove()
            return redirect(url_for("dashboard"))
        else:
            flash('Podano niewłaściwy adres e-mail lub hasło.')
            Session.remove()
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route('/settings')
def settings():
    return redirect(url_for("settings"))

@app.teardown_appcontext
def shutdown_session(exception=None):
    Session.remove()


if __name__ == "__main__":
  app.run(host='0.0.0.0', debug=True, port=5000)