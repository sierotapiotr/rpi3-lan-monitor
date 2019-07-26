import datetime
import logging

from flask import redirect, url_for, render_template
from flask_login import login_required, current_user

from monitor import app
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


@app.route('/set_host_as_confirmed/<host_id>')
@login_required
def set_host_as_confirmed(host_id):
    session = Session()
    session.query(DetectedHost).filter(DetectedHost.id == host_id).update({DetectedHost.confirmed: True})
    session.commit()
    logging.info('Host set as confirmed.')
    Session.remove()
    return redirect(url_for('network_state'))


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
