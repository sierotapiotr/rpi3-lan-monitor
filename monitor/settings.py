import logging
import re

from flask import redirect, render_template, request, url_for
from flask_login import login_required, current_user

from database.database import Session, User
from monitor import app
from monitor.forms import ChangePasswordForm, SettingsForm


@app.route('/settings', methods=['GET'])
@login_required
def settings():
    settings_form = SettingsForm()
    password_reset_form = ChangePasswordForm()

    if request.method == 'GET':
        settings_form.target.data = current_user.target

    return render_template("settings.html",
                           password_reset_form=password_reset_form,
                           settings_form=settings_form)


@app.route('/change_range', methods=['POST'])
@login_required
def change_range():
    settings_form = SettingsForm()
    password_reset_form = ChangePasswordForm()

    if settings_form.validate_on_submit():
        logging.info("Settings form validated.")
        address_pattern = r'(?:\d{1,3}\.){3}\d{1,3}(?:(?:-(?:\d{1,3}\.){3}\d{1,3})|(?:\/(?:[2][1-9]|[3][0-2])))?'
        address_string = settings_form.target.data
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

    return render_template("settings.html", password_reset_form=password_reset_form, settings_form=settings_form)


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    settings_form = SettingsForm()
    password_reset_form = ChangePasswordForm()

    if password_reset_form.validate_on_submit():
        logging.info('Password reset form validated')
        session = Session()
        if not current_user.check_password(password_reset_form.current_password.data):
            return 'Podano nieprawidłowe hasło'
        if password_reset_form.new_password.data != password_reset_form.repeated_new_password.data:
            return 'Podane hasła są różne'
        user = session.query(User).filter_by(id=current_user.id).first()
        user.set_password(password_reset_form.new_password.data)
        session.commit()
        logging.info('Password changed.')
        Session.remove()

    return render_template("settings.html", password_reset_form=password_reset_form, settings_form=settings_form)
