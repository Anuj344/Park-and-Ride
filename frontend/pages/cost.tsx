// pages/cost.tsx

import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import useSWR from "swr";
import { calculateFinalCost } from "../lib/cost";

const API_URL = process.env.NEXT_PUBLIC_API_URL!;

// simple fetcher that sends Bearer token
async function fetcher(url: string, token: string) {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Fetch error");
  return res.json();
}

export default function CostCalculatorPage() {
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);
  const [loadingAuth, setLoadingAuth] = useState(true);

  // — NEW: load subscribers.txt into a Set<string> —
  const [subsSet] = useState<Set<string>>(() => new Set());
  const [plate, setPlate] = useState<string>("");
  useEffect(() => {
    fetch("/subscribers.txt")
      .then((r) => r.text())
      .then((txt) => {
        txt
          .split("\n")
          .map((l) => l.trim().toUpperCase())
          .filter(Boolean)
          .forEach((p) => subsSet.add(p));
      })
      .catch(console.error);
  }, [subsSet]);
  const cleanPlate = plate.trim().toUpperCase();
  const isSubscriber = cleanPlate ? subsSet.has(cleanPlate) : false;
  // — END new subscriber logic —

  // form state
  const [start, setStart] = useState(
    new Date().toISOString().slice(0, 16)
  ); // "yyyy-MM-ddThh:mm"
  const [hours, setHours] = useState(1);
  const [days, setDays] = useState(0);
  const [months, setMonths] = useState(0);

  // get auth token, redirect if missing
  useEffect(() => {
    const t = localStorage.getItem("token");
    setToken(t);
    setLoadingAuth(false);
    if (!t) router.replace("/login");
  }, [router]);

  // fetch occupancy for the selected start time
  const isoStart = new Date(start).toISOString();
  const { data: occ } = useSWR(
    token
      ? [
          `${API_URL}/occupancy?at=${encodeURIComponent(isoStart)}`,
          token,
        ]
      : null,
    fetcher,
    { refreshInterval: 10000 }
  );

  // fetch user profile for subscriber & loyaltyPoints
  const { data: me } = useSWR(
    token ? [`${API_URL}/auth/me`, token] : null,
    fetcher
  );

  if (loadingAuth || !token) return null;

  // default values if data not loaded yet
  const occupied = occ?.occupied ?? 0;
  const total = occ?.total ?? 1; // avoid /0
  const loyaltyPoints = me?.loyaltyPoints ?? 0;

  const cost = calculateFinalCost(
    hours,
    days,
    months,
    new Date(start),
    occupied,
    total,
    isSubscriber,
    loyaltyPoints
  );

  return (
    <div className="container">
      <header className="header">
        <h1>💲 Parking Cost Calculator</h1>
        <button className="btn" onClick={() => router.push("/")}>
          ← Back
        </button>
      </header>

      <div className="card">
        {/* NEW: Plate input & subscriber display */}
        <label>
          Plate Number:
          <input
            type="text"
            value={plate}
            onChange={(e) => setPlate(e.target.value)}
            placeholder="ABC-1234"
          />
        </label>
        {cleanPlate && (
          <p>
            Subscriber? <strong>{isSubscriber ? "Yes ✅" : "No ❌"}</strong>
          </p>
        )}
        {/* END new subscriber part */}

        <label>
          Start Time:
          <input
            type="datetime-local"
            value={start}
            onChange={(e) => setStart(e.target.value)}
          />
        </label>

        <label>
          Duration:
          <input
            type="number"
            min={0}
            value={hours}
            onChange={(e) => setHours(+e.target.value)}
          />{" "}
          hrs
          <input
            type="number"
            min={0}
            value={days}
            onChange={(e) => setDays(+e.target.value)}
          />{" "}
          days
          <input
            type="number"
            min={0}
            value={months}
            onChange={(e) => setMonths(+e.target.value)}
          />{" "}
          months
        </label>

        <hr />

        <p>
          Current Occupancy @{" "}
          <strong>{new Date(isoStart).toLocaleString()}</strong>:{" "}
          {occupied}/{total}
        </p>

        <p>
          Loyalty Points: <strong>{loyaltyPoints}</strong>
        </p>

        <h2>
          Estimated Cost: <span className="cost">${cost}</span>
        </h2>
      </div>

      <style jsx>{`
        .container {
          max-width: 600px;
          margin: 2rem auto;
          font-family: sans-serif;
          padding: 0 1rem;
        }
        .header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 1rem;
        }
        .card {
          background: #fafafa;
          padding: 1.5rem;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        label {
          display: block;
          margin: 0.75rem 0;
          font-weight: 500;
        }
        input[type="text"],
        input[type="datetime-local"],
        input[type="number"] {
          margin-left: 0.5rem;
          padding: 0.4rem;
          border: 1px solid #ccc;
          border-radius: 4px;
        }
        hr {
          margin: 1rem 0;
        }
        .cost {
          color: #0070f3;
        }
        .btn {
          background: #0070f3;
          color: white;
          border: none;
          padding: 0.5rem 1rem;
          border-radius: 4px;
          cursor: pointer;
        }
      `}</style>
    </div>
  );
}