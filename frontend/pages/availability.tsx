// pages/availability.tsx
import useSWR from "swr";
import { useEffect, useState } from "react";
import { useRouter } from "next/router";

const API_URL = process.env.NEXT_PUBLIC_API_URL;

const fetcher = async (url: string, token: string) => {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to fetch availability");
  return res.json();
};

export default function AvailabilityPage() {
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);

  // controlled input for the datetime-local picker
  const [dateTime, setDateTime] = useState<string>("");

  // only when you SUBMIT do we actually fire the SWR fetch
  const [submittedAt, setSubmittedAt] = useState<string | null>(null);

  useEffect(() => {
    const t = localStorage.getItem("token");
    setToken(t);
    if (!t) {
      router.replace("/login");
    }
  }, [router]);

  // SWR key will be [url, token] or null (to skip fetching)
  const shouldFetch = Boolean(token && submittedAt);
  const { data, error, isValidating } = useSWR(
    shouldFetch
      ? [`${API_URL}/free-slots?at=${encodeURIComponent(submittedAt!)}`, token!]
      : null,
    fetcher,
    { refreshInterval: 10000 }
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!dateTime) return;
    // convert from "yyyy-MM-ddTHH:mm" to full ISO
    const iso = new Date(dateTime).toISOString();
    setSubmittedAt(iso);
  };

  if (!token) return null; // waiting on redirect

  return (
    <div className="container">
      <header className="header">
        <h1>🅿️ Check Slot Availability</h1>
        <button className="btn" onClick={() => router.push("/")}>
          ← Back
        </button>
      </header>

      <form onSubmit={handleSubmit} className="form">
        <label>
          Pick date &amp; time:
          <input
            type="datetime-local"
            value={dateTime}
            onChange={(e) => setDateTime(e.target.value)}
            required
          />
        </label>
        <button className="btn" type="submit">
          Check Availability
        </button>
      </form>

      {submittedAt && (
        <div className="card">
          {error && <p className="error">Error loading availability.</p>}
          {!data && !error && <p>Loading availability…</p>}
          {data && (
            <>
              {/* data: { total: number, free: number } */}
              <h2>Total Slots: {data.total}</h2>
              <h2>Occupied: {data.total - data.free}</h2>
              <h2>Available: {data.free}</h2>
            </>
          )}
          {isValidating && <p>Updating…</p>}
        </div>
      )}

      <style jsx>{`
        .container {
          padding: 1rem;
          max-width: 600px;
          margin: 2rem auto;
          font-family: sans-serif;
        }
        .header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 1rem;
        }
        .form {
          display: flex;
          gap: 1rem;
          align-items: center;
          margin-bottom: 1.5rem;
        }
        .form label {
          flex: 1;
        }
        .form input {
          width: 100%;
          padding: 0.4rem;
          margin-top: 0.25rem;
        }
        .card {
          background: #f9f9f9;
          padding: 1.5rem;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
          text-align: center;
        }
        .btn {
          padding: 0.5rem 1rem;
          background: #0070f3;
          border: none;
          color: white;
          border-radius: 4px;
          cursor: pointer;
        }
        .error {
          color: red;
        }
      `}</style>
    </div>
  );
}