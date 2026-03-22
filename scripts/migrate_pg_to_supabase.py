import os
import sys

# Ensure backend package can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv
load_dotenv(override=True)

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

POSTGRES_URL = os.getenv("POSTGRES_URL", "").strip()
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()

if not POSTGRES_URL or not SUPABASE_URL:
    print("❌ Both POSTGRES_URL and SUPABASE_URL must be defined in .env")
    sys.exit(1)

# Ensure proper PG driver
if SUPABASE_URL.startswith("postgres://"):
    SUPABASE_URL = SUPABASE_URL.replace("postgres://", "postgresql://", 1)
if POSTGRES_URL.startswith("postgres://"):
    POSTGRES_URL = POSTGRES_URL.replace("postgres://", "postgresql://", 1)

print("[INFO] Connecting to Local Postgres (Source)...")
src_engine = create_engine(POSTGRES_URL)

print("[INFO] Connecting to Supabase (Destination)...")
dest_engine = create_engine(SUPABASE_URL, connect_args={"sslmode": "require"})

TABLES_TO_MIGRATE = [
    "users",
    "role_requests",
    "password_reset_requests",
    "pcap_analysis",
    "prediction_logs",
    "live_capture_sessions"
]

def migrate_data():
    with src_engine.connect() as src_conn:
        with dest_engine.connect() as dest_conn:
            for table in TABLES_TO_MIGRATE:
                print(f"[MIGRATE] Processing table: {table}...")
                
                # Check if destination table exists
                try:
                    result = src_conn.execute(text(f"SELECT * FROM {table}"))
                    rows = result.mappings().all()
                    
                    if not rows:
                        print(f"  -> {table} is empty. Skipping.")
                        continue
                        
                    print(f"  -> Found {len(rows)} rows. Inserting into Supabase...")
                    
                    # Instead of bulk insert which might fail on constraint duplicates,
                    # we insert one by one or use ON CONFLICT DO NOTHING natively via pandas
                    # But raw SQL is safer for cross-engine
                    
                    columns = rows[0].keys()
                    col_str = ", ".join([f'"{c}"' for c in columns])
                    val_str = ", ".join([f":{c}" for c in columns])
                    insert_sql = text(f"INSERT INTO {table} ({col_str}) VALUES ({val_str}) "
                                      f"ON CONFLICT (id) DO NOTHING")
                    
                    inserted = 0
                    for row in rows:
                        dest_conn.execute(insert_sql, dict(row))
                        inserted += 1
                        
                    dest_conn.commit()
                    print(f"  -> Successfully synchronized {inserted} records into {table}.")
                    
                except Exception as e:
                    print(f"  ⚠️ Error migrating {table}: {e}")
                    dest_conn.rollback()
                    try:
                        src_conn.rollback()
                    except:
                        pass

    print("[SUCCESS] Data Migration to Supabase Complete! 🎉")

if __name__ == "__main__":
    # Ensure tables exist on destination first
    import backend.database as db
    db.SUPABASE_URL = SUPABASE_URL
    db.engine = dest_engine
    db.create_tables()

    migrate_data()
