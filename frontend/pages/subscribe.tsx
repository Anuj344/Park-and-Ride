// pages/subscribe.tsx

import { useState, useEffect } from "react";
import { loadStripe } from "@stripe/stripe-js";
import { useRouter } from "next/router";

const API_URL = process.env.NEXT_PUBLIC_API_URL!;
const stripePromise = loadStripe(
  process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!
);

export default function SubscribePage() {
  const router = useRouter();
  const { success, canceled } = router.query as {
    success?: string;
    canceled?: string;
  };

  const [plate, setPlate] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset form+errors if they navigate back to form
  useEffect(() => {
    if (!success && !canceled) {
      setLoading(false);
      setError(null);
      setPlate("");
    }
  }, [success, canceled]);

  // POST to your backend to create a Stripe session, then redirect
  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(
        `${API_URL}/subscriptions/create-checkout-session`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ plate }),
        }
      );
      const body = await res.json();
      if (!res.ok) throw new Error(body.detail || body.error || "Error");

      const stripe = await stripePromise;
      await stripe!.redirectToCheckout({ sessionId: body.sessionId });
    } catch (err: any) {
      setError(err.message || "Failed to start checkout");
      setLoading(false);
    }
  }

  // —— Render success screen ——
  if (success) {
    return (
      <div className="container">
        <h1> Subscription Successful</h1>
        <p>Thanks for subscribing! You can now enjoy our subscriber perks.</p>
        <button className="btn primary" onClick={() => router.push("/dashboard")}>
          Go to Dashboard
        </button>
        <style jsx>{`
          .container { max-width: 400px; margin: 4rem auto; text-align: center; }
          .btn { margin-top: 2rem; padding: 0.6rem 1.2rem; }
        `}</style>
      </div>
    );
  }

  // —— Render canceled screen ——
  if (canceled) {
    return (
      <div className="container">
        <h1>⚠️ Payment Canceled</h1>
        <p>You canceled the payment. You can try again below.</p>
        <button className="btn primary" onClick={() => router.replace("/subscribe")}>
          Retry Subscription
        </button>
        <style jsx>{`
          .container { max-width: 400px; margin: 4rem auto; text-align: center; }
          .btn { margin-top: 2rem; padding: 0.6rem 1.2rem; }
        `}</style>
      </div>
    );
  }

  // —— Render default subscribe form ——
  return (
    <div className="container">
      <h1>Become a Subscriber</h1>
      <form onSubmit={handleSubmit}>
        <label>
          Plate Number
          <input
            type="text"
            value={plate}
            onChange={(e) => setPlate(e.target.value.toUpperCase())}
            placeholder="ABC-1234"
            required
          />
        </label>
        <button type="submit" disabled={loading} className="btn primary">
          {loading ? "Redirecting…" : "Pay $200 & Subscribe"}
        </button>
        {error && (
          <div className="message error">
            <p>{error}</p>
          </div>
        )}
      </form>

      <style jsx>{`
        .container {
          max-width: 400px;
          margin: 4rem auto;
          padding: 1rem;
          font-family: sans-serif;
        }
        label {
          display: block;
          margin-bottom: 1rem;
          font-weight: 500;
        }
        input {
          width: 100%;
          padding: 0.5rem;
          margin-top: 0.25rem;
          font-size: 1rem;
          text-transform: uppercase;
        }
        .btn {
          margin-top: 1rem;
          padding: 0.6rem;
          background: #0070f3;
          color: #fff;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }
        .message.error {
          margin-top: 1rem;
          padding: 0.75rem;
          background: #ffe6e6;
          color: #c62828;
          border-radius: 4px;
        }
      `}</style>
    </div>
  );
}
