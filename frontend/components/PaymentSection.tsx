import { useState, useEffect } from "react";
import { loadStripe } from "@stripe/stripe-js";
import {
  Elements,
  CardElement,
  useStripe,
  useElements,
} from "@stripe/react-stripe-js";

const stripePromise = loadStripe(
  process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!
);

type CreateIntentResp = { client_secret: string };

interface PaymentSectionProps {
  bookingId: string;
  amount: number;        // dollars
  onSuccess: () => void; // called once payment is confirmed
}

function CheckoutForm({
  clientSecret,
  bookingId,
  amount,
  onSuccess,
}: {
  clientSecret: string;
  bookingId: string;
  amount: number;
  onSuccess: () => void;
}) {
  const stripe = useStripe();
  const elements = useElements();
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!stripe || !elements) return;
    setLoading(true);

    const { error, paymentIntent } = await stripe.confirmCardPayment(
      clientSecret,
      {
        payment_method: {
          card: elements.getElement(CardElement)!,
        },
      }
    );

    if (error) {
      setMessage(error.message!);
      setLoading(false);
      return;
    }

    if (paymentIntent?.status === "succeeded") {
      // notify backend
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/payments/confirm`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            payment_intent_id: paymentIntent.id,
            booking_id: bookingId,
          }),
        }
      );
      const data = await res.json();
      if (data.status === "ok") {
        setMessage("✅ Payment successful!");
        onSuccess();
      } else {
        setMessage("❌ Payment confirmation failed.");
      }
    }
    setLoading(false);
  };

  return (
    <form onSubmit={handleSubmit} style={{ maxWidth: 400 }}>
      <CardElement options={{ hidePostalCode: true }} />
      <button
        type="submit"
        disabled={!stripe || loading}
        style={{
          marginTop: 12,
          padding: "8px 16px",
          background: "#0070f3",
          color: "#fff",
          border: "none",
          borderRadius: 4,
          cursor: "pointer",
        }}
      >
        {loading ? "Processing…" : `Pay $${amount.toFixed(2)}`}
      </button>
      {message && <p style={{ marginTop: 8 }}>{message}</p>}
    </form>
  );
}

export default function PaymentSection({
  bookingId,
  amount,
  onSuccess,
}: PaymentSectionProps) {
  const [clientSecret, setClientSecret] = useState<string | null>(null);

  useEffect(() => {
    const amount_cents = Math.round(amount * 100);
    fetch(`${process.env.NEXT_PUBLIC_API_URL}/payments/create-intent`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        amount_cents,
        currency: "usd",
        metadata: { booking_id: bookingId },
      }),
    })
      .then((r) => r.json() as Promise<CreateIntentResp>)
      .then((data) => setClientSecret(data.client_secret))
      .catch(console.error);
  }, [bookingId, amount]);

  if (!clientSecret) return <p>Loading payment form…</p>;

  return (
    <Elements stripe={stripePromise} options={{ clientSecret }}>
      <CheckoutForm
        clientSecret={clientSecret}
        bookingId={bookingId}
        amount={amount}
        onSuccess={onSuccess}
      />
    </Elements>
  );
}