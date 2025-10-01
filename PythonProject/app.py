# Copyright (C) 2025 mattsva
# This file is part of Washplan.
#
# Washplan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# Washplan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Washplan.  If not, see <https://www.gnu.org/licenses/>.
#
# Version 1
# Github: https://github.com/mattsva

import logging
from datetime import datetime
from flask import (
    Flask, render_template, redirect, url_for,
    flash, request, jsonify, abort
)
from flask_migrate import Migrate
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from flask_session import Session
from sqlalchemy.exc import ProgrammingError
from config import Config
from models import db, User, House, Booking, Appliance
from forms import LoginForm, RegistrationForm, ChangePasswordForm
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# -------------------------------------------------
# Application setup
# -------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

# Database
db.init_app(app)
migrate = Migrate(app, db)

# Server-side session if configured (e.g. Redis)
if getattr(Config, "SESSION_TYPE", None):
    # Config should set SESSION_TYPE and SESSION_REDIS if server-side sessions required
    Session(app)

# CSRF protection (will check form token or X-CSRFToken header)
csrf = CSRFProtect(app)

# Rate limiter: prefer configured storage, otherwise memory (dev)
limiter_storage = getattr(Config, "LIMITER_STORAGE_URI", "memory://")
limiter = Limiter(key_func=get_remote_address, storage_uri=limiter_storage)
limiter.init_app(app)

# Logging
logging.basicConfig(
    filename=getattr(Config, "LOG_FILE", "washplan.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Login manager
login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# -------------------------------------------------
# Initialize default data (only if DB/tables exist)
# -------------------------------------------------
def init_defaults():
    try:
        # if tables aren't created yet, this will raise ProgrammingError
        if not House.query.first():
            from datetime import time
            default_house = House(name="House A", allowed_from=time(7, 0), allowed_to=time(22, 0))
            db.session.add(default_house)
            db.session.commit()
            logger.info("Default house created: House A")

        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", is_admin=True, house_id=House.query.first().id)
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()
            logger.info("Default admin created: username=admin, password=admin123")

        if not Appliance.query.first():
            house_id = House.query.first().id
            washer = Appliance(name="Washer 1", type="washer", house_id=house_id)
            dryer = Appliance(name="Dryer 1", type="dryer", house_id=house_id)
            db.session.add_all([washer, dryer])
            db.session.commit()
            logger.info("Default appliances created")
    except ProgrammingError:
        # tables not created yet (use migrations)
        logger.warning("Database tables not present — skip creating defaults. Run migrations first.")
    except Exception as exc:
        logger.error(f"Error initializing defaults: {exc}")


with app.app_context():
    init_defaults()

# -------------------------------------------------
# Error handlers
# -------------------------------------------------
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.warning(f"CSRF error: {e.description}")
    if request.is_json or request.headers.get("Accept", "").startswith("application/json"):
        return jsonify(success=False, error="Invalid or missing CSRF token"), 400
    flash("Invalid or missing CSRF token. Please try again.", "danger")
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

# -------------------------------------------------
# Startpage
# -------------------------------------------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# -------------------------------------------------
# Authentication
# -------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()
        except ProgrammingError:
            flash("Database not initialized. Please run migrations.", "danger")
            return render_template("error.html")

        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            logger.info(f"User {user.username} logged in.")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
            logger.warning(f"Failed login attempt for username {form.username.data}")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logger.info(f"User {current_user.username} logged out.")
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = RegistrationForm()
    # populate house choices dynamically
    try:
        form.house.choices = [(h.id, h.name) for h in House.query.order_by(House.name).all()]
    except Exception:
        form.house.choices = []

    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already exists.", "danger")
            return render_template("register.html", form=form)

        new_user = User(username=form.username.data, house_id=form.house.data or None)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"New user registered: {new_user.username}")
        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.old_password.data):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("change_password"))

        current_user.set_password(form.new_password.data)
        db.session.commit()
        logger.info(f"User {current_user.username} changed password.")
        flash("Your password has been updated.", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html", form=form)


# -------------------------------------------------
# Dashboard + Calendar (HTML)
# -------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)


@app.route("/calendar")
@login_required
def calendar():
    house = current_user.house
    if not house:
        flash("No house assigned to your account.", "warning")
        return redirect(url_for("dashboard"))

    washer_resources = [
        {"id": f"washer-{a.id}", "title": a.name}
        for a in house.appliances if a.type == "washer"
    ]
    dryer_resources = [
        {"id": f"dryer-{a.id}", "title": a.name}
        for a in house.appliances if a.type == "dryer"
    ]

    washer_events, dryer_events = [], []
    for b in house.bookings:
        event = {
            "id": b.id,
            "title": b.user.username,
            "start": b.start_time.isoformat(),
            "end": b.end_time.isoformat(),
            "resourceId": f"{b.appliance.type}-{b.appliance.id}"
        }
        if b.appliance.type == "washer":
            washer_events.append(event)
        else:
            dryer_events.append(event)

    slot_min = house.allowed_from.strftime("%H:%M:%S") if house.allowed_from else "07:00:00"
    slot_max = house.allowed_to.strftime("%H:%M:%S") if house.allowed_to else "22:00:00"

    return render_template(
        "calendar.html",
        washer_resources=washer_resources,
        dryer_resources=dryer_resources,
        washer_events=washer_events,
        dryer_events=dryer_events,
        slot_min=slot_min,
        slot_max=slot_max,
        current_user=current_user
    )


# -------------------------------------------------
# Calendar API (JSON)
# -------------------------------------------------
@app.route("/api/resources")
@login_required
def api_resources():
    house = current_user.house
    appliances = [
        {"id": str(a.id), "title": a.name, "type": a.type}
        for a in house.appliances
    ]
    return jsonify(appliances)


@app.route("/api/bookings")
@login_required
def api_bookings():
    house = current_user.house
    bookings = Booking.query.join(Appliance).filter(Appliance.house_id == house.id).all()
    events = [
        {
            "id": b.id,
            "title": b.user.username,
            "start": b.start_time.isoformat(),
            "end": b.end_time.isoformat(),
            "resourceId": str(b.appliance_id)
        }
        for b in bookings
    ]
    return jsonify(events)


# -------------------------------------------------
# Booking endpoint (expects JSON, protected by CSRF header)
# -------------------------------------------------
@app.route("/book", methods=["POST"])
@login_required
def book():
    # CSRFProtect will validate token from form or X-CSRFToken header automatically
    data = request.get_json(silent=True)
    if not data:
        return jsonify(success=False, error="Invalid request payload"), 400

    try:
        start = datetime.fromisoformat(data.get("start"))
        end = datetime.fromisoformat(data.get("end"))
    except Exception:
        return jsonify(success=False, error="Invalid date format"), 400

    appliance_id = data.get("appliance_id")
    if isinstance(appliance_id, str) and "-" in appliance_id:
        appliance_id = appliance_id.split("-", 1)[1]

    try:
        appliance = Appliance.query.get_or_404(int(appliance_id))
    except Exception:
        return jsonify(success=False, error="Invalid appliance"), 400

    if appliance.house_id != current_user.house_id:
        return jsonify(success=False, error="Invalid appliance for your house"), 403

    now = datetime.now().astimezone()
    if start < now:
        return jsonify(success=False, error="Cannot book past times"), 400

    if appliance.house.allowed_from and appliance.house.allowed_to:
        if start.time() < appliance.house.allowed_from or end.time() > appliance.house.allowed_to:
            return jsonify(success=False, error="Outside allowed time range"), 400

    conflict = Booking.query.filter(
        Booking.appliance_id == appliance.id,
        Booking.start_time < end,
        Booking.end_time > start
    ).first()
    if conflict:
        return jsonify(success=False, error="Time slot already taken"), 409

    try:
        booking = Booking(
            start_time=start,
            end_time=end,
            user_id=current_user.id,
            house_id=appliance.house_id,
            appliance_id=appliance.id
        )
        db.session.add(booking)
        db.session.commit()
        logger.info(f"Booking created: {booking} by {current_user.username}")
        return jsonify(success=True)
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Booking error: {exc}")
        return jsonify(success=False, error="Server error"), 500


# -------------------------------------------------
# Admin helpers & endpoints
# -------------------------------------------------
def admin_required():
    if not current_user.is_authenticated or not getattr(current_user, "is_admin", False):
        abort(403)


@app.route("/admin")
@login_required
def admin():
    admin_required()
    users = User.query.all()
    houses = House.query.all()
    appliances = Appliance.query.all()
    return render_template("admin.html", users=users, houses=houses, appliances=appliances)


@app.route("/admin/create_user", methods=["POST"])
@login_required
def create_user():
    admin_required()
    username = request.form.get("username")
    password = request.form.get("password")
    house_id = request.form.get("house_id") or None
    is_admin = bool(request.form.get("is_admin"))
    if not username or not password:
        flash("Username and password required.", "danger")
        return redirect(url_for("admin"))

    if User.query.filter_by(username=username).first():
        flash("Username already exists.", "danger")
        return redirect(url_for("admin"))

    u = User(username=username, is_admin=is_admin, house_id=house_id)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    logger.info(f"Admin {current_user.username} created user {username}")
    flash("User created.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    admin_required()
    u = User.query.get_or_404(user_id)
    db.session.delete(u)
    db.session.commit()
    logger.info(f"Admin {current_user.username} deleted user {u.username}")
    flash("User deleted.", "info")
    return redirect(url_for("admin"))


@app.route("/admin/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    admin_required()
    u = User.query.get_or_404(user_id)
    if request.method == "POST":
        u.username = request.form.get("username") or u.username
        if request.form.get("password"):
            u.set_password(request.form.get("password"))
        u.is_admin = bool(request.form.get("is_admin"))
        u.house_id = request.form.get("house_id") or u.house_id
        db.session.commit()
        flash("User updated.", "success")
        return redirect(url_for("admin"))
    houses = House.query.all()
    return render_template("edit_user.html", user=u, houses=houses)


@app.route("/admin/create_house", methods=["POST"])
@login_required
def create_house():
    admin_required()
    name = request.form.get("name")
    allowed_from = request.form.get("allowed_from")
    allowed_to = request.form.get("allowed_to")
    if not name:
        flash("Name required.", "danger")
        return redirect(url_for("admin"))

    from datetime import datetime as dt
    af = dt.strptime(allowed_from, "%H:%M").time() if allowed_from else None
    at = dt.strptime(allowed_to, "%H:%M").time() if allowed_to else None
    h = House(name=name, allowed_from=af, allowed_to=at)
    db.session.add(h)
    db.session.commit()
    flash("House created.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/delete_house/<int:house_id>", methods=["POST"])
@login_required
def delete_house(house_id):
    admin_required()
    h = House.query.get_or_404(house_id)
    db.session.delete(h)
    db.session.commit()
    flash("House deleted.", "info")
    return redirect(url_for("admin"))


@app.route("/admin/edit_house/<int:house_id>", methods=["GET", "POST"])
@login_required
def edit_house(house_id):
    admin_required()
    h = House.query.get_or_404(house_id)
    if request.method == "POST":
        h.name = request.form.get("name", h.name)
        from datetime import datetime as dt
        if request.form.get("allowed_from"):
            h.allowed_from = dt.strptime(request.form.get("allowed_from"), "%H:%M").time()
        if request.form.get("allowed_to"):
            h.allowed_to = dt.strptime(request.form.get("allowed_to"), "%H:%M").time()
        db.session.commit()
        flash("House updated.", "success")
        return redirect(url_for("admin"))
    return render_template("edit_house.html", house=h)


@app.route("/admin/create_appliance", methods=["POST"])
@login_required
def create_appliance():
    admin_required()
    name = request.form.get("name")
    type_ = request.form.get("type")
    house_id = request.form.get("house_id")
    if not name or not type_ or not house_id:
        flash("All fields required.", "danger")
        return redirect(url_for("admin"))
    a = Appliance(name=name, type=type_, house_id=house_id)
    db.session.add(a)
    db.session.commit()
    flash("Appliance added.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/delete_appliance/<int:appliance_id>", methods=["POST"])
@login_required
def delete_appliance(appliance_id):
    admin_required()
    a = Appliance.query.get_or_404(appliance_id)
    db.session.delete(a)
    db.session.commit()
    flash("Appliance deleted.", "info")
    return redirect(url_for("admin"))


@app.route("/admin/edit_appliance/<int:appliance_id>", methods=["GET", "POST"])
@login_required
def edit_appliance(appliance_id):
    admin_required()
    a = Appliance.query.get_or_404(appliance_id)
    if request.method == "POST":
        a.name = request.form.get("name", a.name)
        a.type = request.form.get("type", a.type)
        a.house_id = request.form.get("house_id", a.house_id)
        db.session.commit()
        flash("Appliance updated.", "success")
        return redirect(url_for("admin"))
    houses = House.query.all()
    return render_template("edit_appliance.html", appliance=a, houses=houses)


# -------------------------------------------------
# Run
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
