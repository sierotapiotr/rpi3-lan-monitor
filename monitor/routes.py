from flask import flash, redirect, url_for, render_template
from flask_login import login_user, logout_user, login_required, current_user
from monitor import app
from monitor.forms import LoginForm
from monitor.models import User
from monitor.database import Session

@app.route("/")
@app.route("/dashboard")
def dashboard():
    user_name = current_user.email.split("@")[0]
    return render_template(url_for("dashboard"), name=user_name)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(form.email.data).first()
        if user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash('Podano niewłaściwy adres e-mail lub hasło.')
            return redirect(url_for('login'))
    return render_template("login.html")


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.teardown_appcontext
def shutdown_session(exception=None):
    Session.remove()


if __name__ == "__main__":
  app.run(host='0.0.0.0', debug=True)