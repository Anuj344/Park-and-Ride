from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import stripe
import os

# Load Stripe secret key securely from environment variables
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# ✅ Router with correct prefix
router = APIRouter(
    prefix="/payments",
    tags=["Payments"]
)

# -----------------------------
# Request & Response Models
# -----------------------------

class CreateIntentReq(BaseModel):
    amount_cents: int = Field(..., gt=0, description="Total amount in cents")
    currency: str = "usd"
    metadata: dict | None = None

class CreateIntentResp(BaseModel):
    client_secret: str

class ConfirmReq(BaseModel):
    payment_intent_id: str
    booking_id: str

# -----------------------------
# Endpoint: Create PaymentIntent
# -----------------------------

@router.post("/create-intent", response_model=CreateIntentResp)
def create_intent(req: CreateIntentReq):
    """
    Creates a Stripe PaymentIntent and returns the client secret.
    The client uses this to proceed with payment on the frontend.
    """
    try:
        intent = stripe.PaymentIntent.create(
            amount=req.amount_cents,
            currency=req.currency,
            metadata=req.metadata or {}
        )
        return {"client_secret": intent.client_secret}
    except stripe.error.StripeError as e:
        raise HTTPException(
            status_code=400,
            detail=e.user_message or str(e)
        )

# -----------------------------
# Endpoint: Confirm Payment
# -----------------------------

@router.post("/confirm")
def confirm_payment(req: ConfirmReq):
    """
    Confirms if a Stripe PaymentIntent has succeeded.
    Associates it with the booking ID and stores the transaction.
    """
    try:
        intent = stripe.PaymentIntent.retrieve(req.payment_intent_id)
    except stripe.error.StripeError as e:
        raise HTTPException(
            status_code=400,
            detail=e.user_message or str(e)
        )

    if intent.status != "succeeded":
        raise HTTPException(
            status_code=400,
            detail="Payment has not succeeded yet"
        )

    # ---------------------
    # TODO: Persist payment
    # ---------------------
    # For example:
    # db.record_payment(
    #     intent_id=req.payment_intent_id,
    #     booking_id=req.booking_id,
    #     amount=intent.amount,
    #     currency=intent.currency,
    #     timestamp=intent.created,
    #     status=intent.status,
    # )

    return {"status": "ok", "payment_id": req.payment_intent_id}
