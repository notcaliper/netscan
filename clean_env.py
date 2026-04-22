#!/usr/bin/env python
import os
import logging
from sqlalchemy import create_engine

# Import the database initialization function
from app.db.db_session import init_db

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def clean_environment():
    db_path = 'netscan.db'
    model_path = os.path.join('models', 'isolation_forest.pkl')

    logging.info("Starting NetScan environment cleanup...")

    # 1. Clean Database
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
            logging.info(f"Deleted old database: {db_path}")
        except Exception as e:
            logging.error(f"Failed to delete {db_path}: {e}")
    else:
        logging.info(f"Database {db_path} not found (already clean).")

    # Re-initialize fresh database schema
    logging.info("Re-initializing blank database schema...")
    init_db()
    logging.info("✓ Database wipe complete.")

    # 2. Clean ML Model Cache
    if os.path.exists(model_path):
        try:
            os.remove(model_path)
            logging.info(f"Deleted old ML model cache: {model_path}")
        except Exception as e:
            logging.error(f"Failed to delete {model_path}: {e}")
    else:
        logging.info("No cached ML model found.")

    logging.info("\nEnvironment is 100% clean and ready for a fresh capture!")

if __name__ == "__main__":
    reply = input("WARNING: This will permanently delete all captured network data, alerts, and AI history. Continue? (y/n): ")
    if reply.lower() == 'y':
        clean_environment()
    else:
        logging.info("Cleanup cancelled.")
