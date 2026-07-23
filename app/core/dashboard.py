from flask import Blueprint, render_template, session, redirect, url_for

dashboard_bp = Blueprint("dashboard", __name__, template_folder="templates")


@dashboard_bp.route("/dashboard")
def index():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    return render_template("dashboard/index.html")
