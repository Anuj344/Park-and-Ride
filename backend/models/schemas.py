from pydantic import BaseModel, constr, Field
from datetime import datetime
from typing import List

# Auth
class UserRegister(BaseModel):
    email: constr(strip_whitespace=True, min_length=3, max_length=100)
    password: constr(strip_whitespace=True, min_length=6)

class UserLogin(BaseModel):
    email: constr(strip_whitespace=True, min_length=3, max_length=100)
    password: str

class TokenResponse(BaseModel):
    access_token: str

class UserProfile(BaseModel):
    userId: str
    loyaltyPoints: int

class SimpleMessage(BaseModel):
    message: str

# Booking
class BookingRequest(BaseModel):
    start: datetime
    hours: int = Field(0, ge=0)
    days: int = Field(0, ge=0)
    months: int = Field(0, ge=0)
    plate: constr(strip_whitespace=True, min_length=1)

class CancelRequest(BaseModel):
    row: int
    col: int
    start: datetime
    end: datetime
    plate: constr(strip_whitespace=True, min_length=1)

class Slot(BaseModel):
    row: int
    col: int

class SlotResponse(BaseModel):
    slot: Slot
    start: datetime
    end: datetime
    qr: str

class SlotOnly(BaseModel):
    slot: Slot

class SlotOccupiedStatus(BaseModel):
    occupied: bool

class OccupancyStatus(BaseModel):
    occupied: int
    total: int

class FreeSlotsStatus(BaseModel):
    free: int
    total: int