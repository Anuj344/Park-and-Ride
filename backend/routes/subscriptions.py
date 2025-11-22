import os
import stripe
import logging

from fastapi import APIRouter, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, constr

from utils.mongo import get_db
from auth.auth_utils import get_current_user

# Logging setup
logging.basicConfig(level=logging.INFO)

# Stripe credentials
from dotenv import load_dotenv
load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
BASE_URL = os.getenv("BASE_URL", "http://localhost:3000")

# Router setup
router = APIRouter(
    prefix="/subscriptions",
    tags=["Subscriptions"],
)

# Request and response models
class SessionIn(BaseModel):
    plate: constr(strip_whitespace=True, min_length=1)

class SessionOut(BaseModel):
    sessionId: str

# Create Checkout Session
@router.post(
    "/create-checkout-session",
    response_model=SessionOut,
    summary="Create Checkout Session",
)
async def create_checkout_session(body: SessionIn):
    """
    Creates a Stripe Checkout Session for the given plate.
    Checks if the user is already subscribed.
    """
    plate = body.plate.strip().upper()
    logging.info("Creating checkout session for %s", plate)

    db = get_db()
    existing = await db["subscribers"].find_one({"plate": plate})
    if existing:
        logging.info("Plate %s already subscribed", plate)
        raise HTTPException(status_code=400, detail="You are already subscribed")

    try:
        sess = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "unit_amount": 20000,
                    "product_data": {"name": f"Subscription {plate}"},
                },
                "quantity": 1,
            }],
            mode="payment",
            metadata={"plate": plate},
            success_url=f"{BASE_URL}/subscribe?success=1",
            cancel_url=f"{BASE_URL}/subscribe?canceled=1",
        )
        return SessionOut(sessionId=sess.id)

    except Exception as e:
        logging.exception("Stripe session creation failed")
        raise HTTPException(status_code=500, detail="Stripe session failed")

# Stripe Webhook Handler
@router.post("/webhook", include_in_schema=False)
async def webhook(
    request: Request,
    stripe_signature: str = Header(alias="Stripe-Signature"),
):
    """
    Stripe webhook endpoint. Upserts subscriber on checkout.session.completed.
    """
    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=stripe_signature,
            secret=WEBHOOK_SECRET
        )
    except Exception as e:
        logging.error("❌ Invalid webhook signature: %s", e)
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    logging.info("✅ Received Stripe event %s", event["type"])

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        plate = session["metadata"].get("plate")

        if plate:
            db = get_db()
            await db["subscribers"].update_one(
                {"plate": plate},
                {"$set": {
                    "plate": plate,
                    "subscribedAt": session["created"],
                    "stripeSessionId": session["id"],
                }},
                upsert=True,
            )
            logging.info("✅ Upserted subscriber %s", plate)

    return JSONResponse(content={"received": True})
