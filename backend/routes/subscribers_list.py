# backend/routes/subscribers_list.py

from typing import List
from fastapi import APIRouter
from utils.mongo import get_db

# NO prefix here
router = APIRouter()

@router.get("/", response_model=List[str], summary="List Subscribers")
async def list_subscribers():
    """
    Returns all subscriber plate numbers.
    """
    db = get_db()
    docs = await (
        db["subscribers"]
        .find({}, {"_id": 0, "plate": 1})
        .to_list(length=None)
    )
    return [d["plate"] for d in docs]