# scripts/create_users.py
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import SessionLocal, create_tables
from backend.models import User
from backend.auth import hash_password

def create_test_users():
    create_tables()
    db = SessionLocal()

    test_users = [
        {
            "username": "admin",
            "email":    "admin@ids-ml.local",
            "password": "admin123",
            "role":     "admin"
        },
        {
            "username": "analyst",
            "email":    "analyst@ids-ml.local",
            "password": "analyst123",
            "role":     "analyst"
        },
        {
            "username": "viewer",
            "email":    "viewer@ids-ml.local",
            "password": "viewer123",
            "role":     "viewer"
        },
    ]

    for u in test_users:
        exists = db.query(User).filter(User.username == u["username"]).first()
        if exists:
            print(f"⚠️  User '{u['username']}' already exists — skipping")
            continue
        new_user = User(
            username        = u["username"],
            email           = u["email"],
            hashed_password = hash_password(u["password"]),
            role            = u["role"],
        )
        db.add(new_user)
        print(f"✅ Created user: {u['username']} ({u['role']})")

    db.commit()
    db.close()

    print("\n" + "="*45)
    print("📋 Test Credentials")
    print("="*45)
    print(f"  Admin:   admin    /  admin123")
    print(f"  Analyst: analyst  /  analyst123")
    print(f"  Viewer:  viewer   /  viewer123")
    print("="*45)

if __name__ == "__main__":
    create_test_users()