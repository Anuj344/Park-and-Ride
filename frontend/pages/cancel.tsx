import { useRouter } from 'next/router';
import { useEffect, useState } from 'react';
import { useSWRConfig } from 'swr';
import { cancelSpot } from '../lib/api';

export default function CancelPage() {
  const router = useRouter();
  const { mutate } = useSWRConfig();
  const [token, setToken] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState(true);

  // Form state
  const [row, setRow] = useState(0);
  const [col, setCol] = useState(0);
  const [start, setStart] = useState(() => new Date().toISOString().slice(0,16));
  const [end, setEnd] = useState(() => new Date().toISOString().slice(0,16));
  const [plate, setPlate] = useState('');
  const [message, setMessage] = useState<null | { type:'success'|'error'; text:string }>(null);

  useEffect(() => {
    const t = localStorage.getItem('token');
    setToken(t);
    setAuthLoading(false);
    if (!t) router.replace('/login');
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const confirmMsg = 
      'Cancel your booking?\n' +
      'If ≥2 hrs before start ⇒ full refund, else ⇒ no refund.';
    if (!window.confirm(confirmMsg)) return;

    setMessage(null);
    try {
      const startISO = new Date(start).toISOString();
      const endISO = new Date(end).toISOString();
      const now = new Date();
      const hrsDiff = (new Date(start).getTime() - now.getTime())/(1000*60*60);
      const fullRefund = hrsDiff >= 2;

      await cancelSpot(token!, { row, col, start: startISO, end: endISO, plate: plate.trim().toUpperCase() });
      setMessage({
        type: 'success',
        text: fullRefund
          ? '✅ Cancellation successful. Full refund issued.'
          : '✅ Cancellation successful. No refund (less than 2 hrs).'
      });
      // Refresh occupancy if you track it elsewhere
      mutate([`${process.env.NEXT_PUBLIC_API_URL}/occupancy?at=${encodeURIComponent(start)}`, token]);
    } catch (err: any) {
      setMessage({ type:'error', text: err.message || 'Cancellation failed' });
    }
  }

  if (authLoading || !token) return null;

  return (
    <div className="container">
      <header className="header">
        <h1>❌ Cancel Booking</h1>
        <button className="btn" onClick={() => router.push('/')}>
          ← Back
        </button>
      </header>
      
      <form className="card" onSubmit={handleSubmit}>
        <label>
          Slot Row, Col:
          <input type="number" value={row} onChange={e=>setRow(+e.target.value)} required />
          <input type="number" value={col} onChange={e=>setCol(+e.target.value)} required />
        </label>
        <label>
          Start Time:
          <input type="datetime-local" value={start} onChange={e=>setStart(e.target.value)} required />
        </label>
        <label>
          End Time:
          <input type="datetime-local" value={end} onChange={e=>setEnd(e.target.value)} required />
        </label>
        <label>
          Plate:
          <input type="text" value={plate} onChange={e=>setPlate(e.target.value)} required />
        </label>
        <button type="submit" className="btn danger">Confirm Cancel</button>
      </form>

      {message && <section className={`message ${message.type}`}>{message.text}</section>}

      <style jsx>{`
        /* reuse the same styles from Dashboard… */
      `}</style>
    </div>
  );
}
