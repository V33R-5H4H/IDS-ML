import os
import sys
import time

# Ensure backend package can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv
load_dotenv(override=True)

from sqlalchemy import create_engine, text

POSTGRES_URL = os.getenv("POSTGRES_URL", "").strip()
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()

if not POSTGRES_URL or not SUPABASE_URL:
    print("❌ Both POSTGRES_URL and SUPABASE_URL must be defined for Sync.")
    sys.exit(1)

# Ensure proper PG driver
if SUPABASE_URL.startswith("postgres://"):
    SUPABASE_URL = SUPABASE_URL.replace("postgres://", "postgresql://", 1)
if POSTGRES_URL.startswith("postgres://"):
    POSTGRES_URL = POSTGRES_URL.replace("postgres://", "postgresql://", 1)

print("[SYNC] Connecting to Supabase (Master)...")
supabase_engine = create_engine(SUPABASE_URL, connect_args={"sslmode": "require"})

print("[SYNC] Connecting to Local Postgres (Replica)...")
local_engine = create_engine(POSTGRES_URL)

SYNC_TABLES = [
    "users",
    "role_requests",
    "password_reset_requests",
    "pcap_analysis",
    "prediction_logs",
    "live_capture_sessions"
]

def perform_sync():
    """Fetches all data from Supabase and mirrors it down into Local Postgres using ON CONFLICT"""
    with supabase_engine.connect() as sup_conn:
        with local_engine.connect() as loc_conn:
            for table in SYNC_TABLES:
                try:
                    # 1. Fetch from Master
                    sup_result = sup_conn.execute(text(f"SELECT * FROM {table}"))
                    rows = sup_result.mappings().all()
                    
                    if not rows:
                        continue
                        
                    # 2. Sync to Replica
                    columns = rows[0].keys()
                    col_str = ", ".join([f'"{c}"' for c in columns])
                    val_str = ", ".join([f":{c}" for c in columns])
                    
                    # For local Postgres, ON CONFLICT (id) DO UPDATE allows refreshing mutable fields!
                    # We dynamically generate DO UPDATE SET statements
                    update_str = ", ".join([f'"{c}" = EXCLUDED."{c}"' for c in columns if c != "id"])
                    
                    if update_str:
                        insert_sql = text(f"""
                            INSERT INTO {table} ({col_str}) VALUES ({val_str})
                            ON CONFLICT (id) DO UPDATE SET {update_str}
                        """)
                    else:
                        insert_sql = text(f"""
                            INSERT INTO {table} ({col_str}) VALUES ({val_str})
                            ON CONFLICT (id) DO NOTHING
                        """)
                    
                    for row in rows:
                        loc_conn.execute(insert_sql, dict(row))
                    
                    loc_conn.commit()
                except Exception as e:
                    loc_conn.rollback()
                    sup_conn.rollback()
                    print(f"  [SYNC] ⚠️ Warning syncing {table}: {e}")

if __name__ == "__main__":
    print("[SYNC] Ensuring Local Postgres has latest schema before starting loop...")
    import backend.database as db
    db.DATABASE_URL = POSTGRES_URL
    db.engine = local_engine
    db.create_tables()

    print("[SYNC] Starting Periodic Sync (Every 60 seconds)...")
    print("Press Ctrl+C to stop.")
    
    run_once = "--once" in sys.argv
    
    try:
        while True:
            t0 = time.time()
            perform_sync()
            elapsed = time.time() - t0
            print(f"[{time.strftime('%H:%M:%S')}] Sync complete. Took {elapsed:.2f}s")
            
            if run_once:
                break
                
            # Wait 60 seconds before pulling again
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n[SYNC] Gracefully stopped manual sync.")
