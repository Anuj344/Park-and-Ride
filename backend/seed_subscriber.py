# backend/seed_subscriber.py
import asyncio
from datetime import datetime
from utils.mongo import get_db

async def main():
    db = get_db()
    result = await db["subscribers"].insert_one({
        "plate": "AP09",
        "subscribedAt": datetime.utcnow(),
        "stripeSessionId": "TEST",
    })
    print("Inserted:", result.inserted_id)

if __name__ == "__main__":
    asyncio.run(main())