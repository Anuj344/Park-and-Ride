import os
from datetime import datetime

from dotenv import load_dotenv
import stripe

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# 1) Load .env + Stripe
load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# 2) Auth dependency
from auth.auth_utils import get_current_user

# 3) Routers
from auth.routes               import router as auth_router
from routes.payments           import router as payments_router
from routes.subscriptions      import router as subscriptions_router
from routes.subscribers_list   import router as subscribers_router

# 4) Booking service & schemas
from services.booking_service import service, BookingError
from models.schemas import (
    BookingRequest,
    CancelRequest,
    SlotResponse,
    SimpleMessage,
    SlotOnly,
    SlotOccupiedStatus,
    OccupancyStatus,
    FreeSlotsStatus,
)

app = FastAPI(
    title="Park & Ride API",
    description="Bookings, payments & subscriptions",
    version="1.0",
)

# 5) CORS (dev-open)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 6) Mount routers (each router file has its own prefix)
app.include_router(auth_router)           
app.include_router(payments_router)       
app.include_router(subscriptions_router) 

app.include_router(
    subscribers_router,
    prefix="/subscribers",
    tags=["Subscribers"],
)

# 7) Booking endpoints (protected)
@app.post("/book", response_model=SlotResponse)
def book(req: BookingRequest, user: str = Depends(get_current_user)):
    try:
        slot, start_dt, end_dt, qr = service.book(
            req.start, req.hours, req.days, req.months, req.plate
        )
        return SlotResponse(
            slot={"row": slot[0], "col": slot[1]},
            start=start_dt,
            end=end_dt,
            qr=qr,
        )
    except BookingError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/cancel", response_model=SimpleMessage)
def cancel(req: CancelRequest, user: str = Depends(get_current_user)):
    try:
        service.cancel(req.row, req.col, req.start, req.end, req.plate)
        return SimpleMessage(message="Cancelled successfully")
    except BookingError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/occupancy", response_model=OccupancyStatus)
def occupancy(at: datetime, user: str = Depends(get_current_user)):
    occupied = service.occupancy_at(at)
    return OccupancyStatus(occupied=occupied, total=service.TOTAL)

@app.get("/slot-occupied", response_model=SlotOccupiedStatus)
def slot_occupied(slot: str, at: datetime, user: str = Depends(get_current_user)):
    return SlotOccupiedStatus(occupied=service.is_slot_occupied(slot, at))

@app.post("/find-slot", response_model=SlotOnly)
def find_slot(start: datetime, end: datetime, user: str = Depends(get_current_user)):
    s = service.find_slot(start, end)
    if not s:
        raise HTTPException(status_code=404, detail="No available slot")
    return SlotOnly(slot={"row": s[0], "col": s[1]})

@app.get("/free-slots", response_model=FreeSlotsStatus)
def free_slots(at: datetime, user: str = Depends(get_current_user)):
    occ = service.occupancy_at(at)
    return FreeSlotsStatus(free=service.TOTAL - occ, total=service.TOTAL)

# 8) Debug: list all routes on startup
@app.on_event("startup")
def list_routes():
    for route in app.routes:
        print(f"{route.methods} -> {route.path}")

# 9) Root health-check
@app.get("/", tags=["root"])
async def read_root():
    return {"message": "Welcome to Park & Ride API"}

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
