# ← CORRECT
from utils.mongo import get_db
db = get_db()
from models.user import User
from utils.security import hash_password, verify_password
from utils.jwt import create_access_token
from fastapi import HTTPException

async def signup_user(email: str, password: str):
    existing = await db["users"].find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = hash_password(password)
    user = {"email": email, "hashed_password": hashed_pw}
    await db["users"].insert_one(user)
    return {"msg": "Signup successful"}

async def login_user(email: str, password: str):
    user = await db["users"].find_one({"email": email})
    if not user or not verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": user["email"]})
    return {"access_token": token, "token_type": "bearer"}
