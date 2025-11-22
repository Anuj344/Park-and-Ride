# backend/utils/mongo.py

import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()  # loads MONGO_URI and optional MONGO_DB

MONGO_URI = os.environ["MONGO_URI"] 
if not MONGO_URI:
    raise RuntimeError("MONGO_URI must be set in .env")

# Create the client
_client = AsyncIOMotorClient(MONGO_URI)

# Try to get a default database from the URI
_default_db = _client.get_default_database()

# If URI did not include a database, fall back to MONGO_DB or "park_and_ride"
if _default_db is None:
    db_name = os.getenv("MONGO_DB", "park_and_ride")
    _default_db = _client[db_name]

def get_db():
    """
    Returns the Motor AsyncIO Database instance.
    """
    return _default_db