# reset_db.py
from app import app, db
from models import User, House
from datetime import time

with app.app_context():
    print("   All tables will be dropped and recreated...")
    db.drop_all()
    db.create_all()
    print("   Database fully reset.")

    # Create a default house (so admin belongs somewhere)
    house = House(name="House A", allowed_from=time(7, 0), allowed_to=time(22, 0))
    db.session.add(house)
    db.session.commit()

    # Create new admin user
    admin = User(
        username="admin",
        is_admin=True,
        house_id=house.id
    )
    admin.set_password("admin123")
    db.session.add(admin)
    db.session.commit()

    print("   Admin user has been created:")
    print("   Username: admin")
    print("   Password: admin123")
