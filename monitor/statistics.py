from flask import render_template
from flask_login import login_required, current_user

from monitor import app


@app.route('/statistics')
@login_required
def statistics():
    return render_template('statistics.html')