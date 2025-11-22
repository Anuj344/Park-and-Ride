import { FC, useRef } from "react";
import QRCode from "react-qr-code";
import { toPng } from "html-to-image";

export interface Booking {
  slot: { row: number; col: number };
  start: string;   // ISO timestamp
  end: string;     // ISO timestamp
  qr: string;
  amount: number;  // dollars
}

const BookingSummary: FC<{ booking: Booking }> = ({ booking }) => {
  const qrRef = useRef<HTMLDivElement>(null);

  function downloadQR() {
    if (!qrRef.current) return;
    toPng(qrRef.current).then((dataUrl) => {
      const link = document.createElement("a");
      link.href = dataUrl;
      link.download = "parking_qr.png";
      link.click();
    });
  }

  return (
    <section className="card success-summary">
      <h2>✅ Booking Successful!</h2>
      <p>
        Slot: <strong>({booking.slot.row}, {booking.slot.col})</strong>
      </p>
      <p>
        From: <strong>{new Date(booking.start).toLocaleString()}</strong>
      </p>
      <p>
        To:   <strong>{new Date(booking.end).toLocaleString()}</strong>
      </p>

      <div className="qr-container">
        <h4>Your QR Code</h4>
        <div ref={qrRef} className="qr-box">
          <QRCode value={booking.qr} size={160} />
        </div>
        <button className="btn" onClick={downloadQR}>
          Download QR Code
        </button>
      </div>

      <style jsx>{`
        .success-summary {
          background: #e8f5e9;
          border: 1px solid #4caf50;
          padding: 1.5rem;
          border-radius: 8px;
          margin-top: 1rem;
        }
        .qr-container {
          text-align: center;
          margin: 1rem 0;
        }
        .qr-box {
          display: inline-block;
          background: #fff;
          padding: 1rem;
          border-radius: 8px;
        }
        .btn {
          margin-top: 0.5rem;
          padding: 0.4rem 0.8rem;
          background: #0070f3;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }
      `}</style>
    </section>
  );
};

export default BookingSummary;