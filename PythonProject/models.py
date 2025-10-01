from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import time

db = SQLAlchemy()


class House(db.Model):
    __tablename__ = "houses"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    # Allowed booking time window for this house (default: 07:00 - 22:00)
    allowed_from = db.Column(db.Time, nullable=False, default=time(7, 0))
    allowed_to = db.Column(db.Time, nullable=False, default=time(22, 0))

    # Relationships
    users = db.relationship("User", backref="house", lazy=True)
    appliances = db.relationship("Appliance", backref="house", lazy=True)
    bookings = db.relationship("Booking", backref="house", lazy=True)

    def __repr__(self):
        return f"<House {self.name}>"


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    # Reference to the house the user belongs to
    house_id = db.Column(db.Integer, db.ForeignKey("houses.id"))

    # A user can have multiple bookings
    bookings = db.relationship("Booking", backref="user", lazy=True)

    def set_password(self, password: str):
        """Hashes and stores the user password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verifies the given password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class Appliance(db.Model):
    __tablename__ = "appliances"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)  # e.g., Washer 1, Dryer 2
    type = db.Column(db.String(32), nullable=False)   # e.g., "washer" or "dryer"

    # Reference to the house this appliance belongs to
    house_id = db.Column(db.Integer, db.ForeignKey("houses.id"), nullable=False)

    # An appliance can have multiple bookings
    bookings = db.relationship("Booking", backref="appliance", lazy=True)

    def __repr__(self):
        return f"<Appliance {self.name} ({self.type})>"


class Booking(db.Model):
    __tablename__ = "bookings"

    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)

    # References
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    house_id = db.Column(db.Integer, db.ForeignKey("houses.id"), nullable=False)
    appliance_id = db.Column(db.Integer, db.ForeignKey("appliances.id"), nullable=False)

    def __repr__(self):
        return f"<Booking {self.start_time} - {self.end_time}>"
