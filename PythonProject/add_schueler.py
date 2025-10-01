import csv
from app import app, db
from models import User, House

FILENAME = "students.csv"  # csv format: username,house,password

with app.app_context():
    try:
        with open(FILENAME, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile, delimiter=",")
            for row in reader:
                username = row.get("username", "").strip()
                house_name = row.get("house", "").strip()
                password = row.get("password", "").strip() or "start123"

                if not username:
                    continue  # skip if no username

                # Check/create house
                house = None
                if house_name:
                    house = House.query.filter_by(name=house_name).first()
                    if not house:
                        house = House(name=house_name)
                        db.session.add(house)
                        db.session.flush()
                        print(f"House '{house_name}' created")

                # Check if user already exists
                if User.query.filter_by(username=username).first():
                    print(f"User {username} already exists, skipping...")
                    continue

                # Create user
                student = User(
                    username=username,
                    is_admin=False,
                    house_id=house.id if house else None,
                )
                student.set_password(password)
                db.session.add(student)
                print(f"User {username} created (House: {house_name}, Password: {password})")

    except FileNotFoundError:
        print(f"File '{FILENAME}' not found, no users imported.")

    db.session.commit()
    print("User import completed.")
