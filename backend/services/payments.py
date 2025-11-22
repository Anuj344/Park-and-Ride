import stripe
from fastapi import HTTPException

def create_payment_intent(amount_cents: int, currency: str = "usd", metadata: dict = None):
    try:
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=currency,
            metadata=metadata or {}
        )
        return intent
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=e.user_message or str(e))

def retrieve_intent(intent_id: str):
    try:
        return stripe.PaymentIntent.retrieve(intent_id)
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=e.user_message or str(e))
