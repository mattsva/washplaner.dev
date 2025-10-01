import time
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from psycopg2 import sql
from app import app
from models import db, User, House

DB_NAME = "washplan"
DB_USER = "washuser"
DB_PASS = "washpass"


def recreate_db():
    """Drop & recreate database and user cleanly."""
    try:
        conn = psycopg2.connect(dbname="postgres", user="postgres", password="", host="localhost")
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()

        # Alle Verbindungen zur DB killen
        cur.execute(f"""
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = '{DB_NAME}' AND pid <> pg_backend_pid();
        """)

        # DB löschen, wenn vorhanden
        cur.execute(sql.SQL("DROP DATABASE IF EXISTS {};").format(sql.Identifier(DB_NAME)))

        # User löschen
        cur.execute(sql.SQL("DROP USER IF EXISTS {};").format(sql.Identifier(DB_USER)))

        # User & DB neu erstellen
        cur.execute(sql.SQL("CREATE USER {} WITH PASSWORD %s;").format(sql.Identifier(DB_USER)), [DB_PASS])
        cur.execute(sql.SQL("CREATE DATABASE {} OWNER {};").format(sql.Identifier(DB_NAME), sql.Identifier(DB_USER)))

        conn.close()
        print(f"✅ Datenbank '{DB_NAME}' und User '{DB_USER}' erfolgreich erstellt.")
        return True
    except Exception as e:
        print(f"❌ Fehler bei der DB-Erstellung: {e}")
        return False


def init_tables():
    """Create tables and insert defaults."""
    with app.app_context():
        # Engine reset erzwingen, falls vorher noch alte Connection da war
        db.engine.dispose()

        db.create_all()

        # Default-Haus
        if not House.query.first():
            haus = House(name="Haus A")
            db.session.add(haus)
            db.session.commit()
            print("🏠 Haus 'Haus A' erstellt.")

        # Default-Admin
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", is_admin=True, house_id=House.query.first().id)
            admin.set_password("admin123")
            db.session.add(admin)
            db.session.commit()
            print("👑 Admin 'admin' mit Passwort 'admin123' erstellt.")

        print("✅ Tabellen erstellt & Standarddaten eingefügt.")


if __name__ == "__main__":
    if recreate_db():
        # kurze Pause, damit DB sicher ready ist
        time.sleep(2)

        # DB-URI neu setzen (kein init_app mehr!)
        app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://{DB_USER}:{DB_PASS}@localhost/{DB_NAME}"

        # Tabellen & Admin anlegen
        init_tables()
