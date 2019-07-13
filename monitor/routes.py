from flask import flash, redirect, url_for, render_template
from flask_login import login_user, logout_user, login_required, current_user
import logging
import re
import datetime

from monitor import app, login_manager
from monitor.forms import LoginForm, SettingsForm
from monitor.anomaly_finder import find_untrusted_mac_addresses
from monitor_utils.db_utils import sqlalchemy_tuples_to_list
from database.database import Session, User, DetectedHost


@app.route("/")
@app.route("/network_state")
@login_required
def network_state():
    user_name = current_user.email.split("@")[0]
    interval_end = datetime.datetime.now()
    interval_beginning = interval_end - datetime.timedelta(hours=152)
    session = Session()

    detected_hosts = session.query(DetectedHost).order_by(DetectedHost.last_seen.desc()).\
        filter(DetectedHost.last_seen > interval_beginning).all()

    if len(detected_hosts) is 0:
        return render_template("network_state.html", name=user_name, user=current_user)

    logging.info(str(detected_hosts))
    host_data_dict = {}
    for host in detected_hosts:
        host_data_dict[host.id] = {}
        host_data_dict[host.id]['mac_address'] = host.mac_address
        host_data_dict[host.id]['ip_address'] = host.address
        host_data_dict[host.id]['manufacturer'] = host.manufacturer
    return render_template("network_state.html", name=user_name, user=current_user, detected_hosts=detected_hosts,
                           host_addr_dict=host_data_dict)


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


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm()
    if form.validate_on_submit():
        logging.info("Settings form validated.")
        address_pattern = r'(?:\d{1,3}\.){3}\d{1,3}(?:(?:-(?:\d{1,3}\.){3}\d{1,3})|(?:\/(?:[2][1-9]|[3][0-2])))?'
        address_string = form.target.data
        address_list = re.findall(address_pattern, address_string)
        address = "; ".join(address_list)
        if address == "":
            return redirect(url_for("settings"))

        logging.info("Address: " + address)

        session = Session()
        session.query(User).filter(User.id == current_user.id).update(
            {User.target: address})
        session.commit()
        logging.info('Target address changed to: ' + address)
        Session.remove()
        return redirect(url_for("network_state"))

    return render_template("settings.html", form=form)


@app.teardown_appcontext
def shutdown_session(exception=None):
    Session.remove()


@app.route('/statistics')
@login_required
def statistics():
    return render_template('statistics.html')


@app.route('/toggle_monitoring')
@login_required
def toggle_monitoring():
    session = Session()
    session.query(User).filter(User.id == current_user.id).update({User.monitoring_activated: not current_user.monitoring_activated})
    session.commit()
    logging.info('Monitoring toggled.')
    Session.remove()
    return redirect(url_for('network_state'))


@app.route('/toggle_learning')
@login_required
def toggle_learning():
    session = Session()
    if current_user.network_learning == "active":
        session.query(User).filter(User.id == current_user.id).update({User.network_learning: "finished"})
    else:
        session.query(User).filter(User.id == current_user.id).update({User.network_learning: "active"})
    session.commit()
    logging.info('Network learning toggled.')
    Session.remove()
    return redirect(url_for('network_state'))


if __name__ == "__main__":
  app.run(host='0.0.0.0', debug=True, port=5000)
