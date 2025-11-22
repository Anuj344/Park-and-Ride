from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from utils.mongo import get_db
from auth.auth_utils import hash_password, verify_password, create_access_token, decode_access_token
from models.schemas import UserRegister, UserLogin, TokenResponse, UserProfile, SimpleMessage

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
router = APIRouter(prefix="/auth", tags=["Auth"])

def get_current_email(token: str = Depends(oauth2_scheme)) -> str:
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = decode_access_token(token)
    except JWTError:
        raise HTTPException(401, "Invalid or expired token")
    if not isinstance(payload, dict) or "sub" not in payload:
        raise HTTPException(401, "Invalid credentials")
    return payload["sub"]

@router.post("/register", response_model=SimpleMessage)
async def register(user: UserRegister):
    db = get_db()
    if await db["users"].find_one({"email": user.email}):
        raise HTTPException(400, "User exists")
    hashed = hash_password(user.password)
    await db["users"].insert_one({"email": user.email, "hashed_password": hashed, "loyaltyPoints": 0})
    return SimpleMessage(message="Registered")

@router.post("/login", response_model=TokenResponse)
async def login(user: UserLogin):
    db = get_db()
    rec = await db["users"].find_one({"email": user.email})
    if not rec or not verify_password(user.password, rec["hashed_password"]):
        raise HTTPException(400, "Bad email or password")
    token = create_access_token({"sub": user.email})
    return TokenResponse(access_token=token)

@router.get("/me", response_model=UserProfile)
async def me(email: str = Depends(get_current_email)):
    db = get_db()
    rec = await db["users"].find_one({"email": email})
    pts = rec.get("loyaltyPoints", 0) if rec else 0
    return UserProfile(userId=email, loyaltyPoints=pts)