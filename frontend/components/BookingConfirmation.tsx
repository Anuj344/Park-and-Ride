import { FC, useRef } from "react";
import QRCode from "react-qr-code";
import { toPng } from "html-to-image";
import PaymentSection from "./PaymentSection";

export interface BookingResult {
  slot: { row: number; col: number };
  start: string;   // ISO timestamp
  end: string;     // ISO timestamp
  qr: string;
  amount: number;  // dollars
}

interface Props {
  result: BookingResult;
}

const BookingConfirmation: FC<Props> = ({ result }) => {
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
        Slot: <strong>({result.slot.row}, {result.slot.col})</strong>
      </p>
      <p>
        From: <strong>{new Date(result.start).toLocaleString()}</strong>
      </p>
      <p>
        To:   <strong>{new Date(result.end).toLocaleString()}</strong>
      </p>
      <p>
        Amount Due: <strong>${result.amount.toFixed(2)}</strong>
      </p>

      <div className="qr-container">
        <h4>Your QR Code</h4>
        <div ref={qrRef} className="qr-box">
          <QRCode value={result.qr} size={160} />
        </div>
        <button className="btn" onClick={downloadQR}>
          Download QR Code
        </button>
      </div>

      <div className="payment-section-wrapper">
        <h4>Complete Your Payment</h4>
        <PaymentSection bookingId={result.qr} amount={result.amount} />
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
          background: white;
          padding: 1rem;
          border-radius: 8px;
        }
        .payment-section-wrapper {
          margin-top: 1.5rem;
        }
      `}</style>
    </section>
  );
};

export default BookingConfirmation;