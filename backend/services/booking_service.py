# utils/logger.py
import os
from datetime import datetime
from collections import namedtuple

# Define Booking namedtuple to store reservation data
Booking = namedtuple("Booking", ["start", "end", "plate"])

# Log file path (can be overridden via environment variable)
LOG_FILE = os.getenv("BOOKING_LOG_FILE", "bookings.log")


def _write_log(record: str) -> None:
    """
    Append a record string to the log file.
    """
    with open(LOG_FILE, "a") as f:
        f.write(record + "\n")


def log_booking(r: int, c: int, plate: str,
                start_year: int, start_month: int, start_day: int,
                start_hour: int, start_minute: int,
                end_year: int, end_month: int, end_day: int,
                end_hour: int, end_minute: int) -> None:
    """
    Log a new booking record.
    Format: BOOKING,r,c,plate,start_iso,end_iso
    """
    start = datetime(start_year, start_month, start_day,
                     start_hour, start_minute).isoformat()
    end = datetime(end_year, end_month, end_day,
                   end_hour, end_minute).isoformat()
    record = f"BOOKING,{r},{c},{plate},{start},{end}"
    _write_log(record)


def log_cancellation(r: int, c: int, plate: str,
                     start_year: int, start_month: int, start_day: int,
                     start_hour: int, start_minute: int,
                     end_year: int, end_month: int, end_day: int,
                     end_hour: int, end_minute: int) -> None:
    """
    Log a cancellation record.
    Format: CANCELLATION,r,c,plate,start_iso,end_iso
    """
    start = datetime(start_year, start_month, start_day,
                     start_hour, start_minute).isoformat()
    end = datetime(end_year, end_month, end_day,
                   end_hour, end_minute).isoformat()
    record = f"CANCELLATION,{r},{c},{plate},{start},{end}"
    _write_log(record)


def replay_reservations() -> dict:
    """
    Replay the log file to reconstruct current reservations.
    Returns a dict mapping (r, c) -> Booking(start: datetime, end: datetime, plate: str).
    """
    reservations = {}
    if not os.path.exists(LOG_FILE):
        return reservations

    with open(LOG_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) != 6:
                continue  # skip malformed lines
            action, r, c, plate, start_iso, end_iso = parts
            r, c = int(r), int(c)
            start = datetime.fromisoformat(start_iso)
            end = datetime.fromisoformat(end_iso)

            if action == "BOOKING":
                reservations[(r, c)] = Booking(start=start, end=end, plate=plate)
            elif action == "CANCELLATION":
                reservations.pop((r, c), None)
    return reservations


# services/booking_service.py
import calendar
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from collections import namedtuple

from utils.logger import log_booking, log_cancellation, replay_reservations

# Define Booking tuple used within service
Booking = namedtuple("Booking", ["start", "end", "plate"])


class BookingError(Exception):
    """Custom exception for booking errors."""
    pass


class BookingService:
    ROWS, COLS = 20, 20
    TOTAL = ROWS * COLS
    MAX_DURATION = timedelta(days=2000)

    def __init__(self):
        # Initialize reservation state from logs
        self.res = replay_reservations()

    def occupancy_at(self, at: datetime) -> int:
        at = at.astimezone(timezone.utc)
        return sum(1 for b in self.res.values() if b.start <= at < b.end)

    def find_slot(self, start: datetime, end: datetime) -> Optional[Tuple[int, int]]:
        for r in range(self.ROWS):
            for c in range(self.COLS):
                b = self.res.get((r, c))
                # No booking or non-overlapping booking
                if not b or not (b.start < end and start < b.end):
                    return (r, c)
        return None

    def _add_months(self, dt: datetime, months: int) -> datetime:
        month = dt.month - 1 + months
        year = dt.year + month // 12
        month = month % 12 + 1
        day = min(dt.day, calendar.monthrange(year, month)[1])
        return dt.replace(year=year, month=month, day=day)

    def generate_qr(self, r: int, c: int, s: datetime, e: datetime, plate: str) -> str:
        t1 = s.strftime("%y%m%d%H%M")
        t2 = e.strftime("%y%m%d%H%M")
        token = uuid.uuid4().hex[:8]
        return f"SLOT-{r:02d}{c:02d}-{t1}-{t2}-{plate}-{token}"

    def is_slot_occupied(self, slot_id: str, at: datetime) -> bool:
        try:
            # Parse slot_id: SLOT-rrcc-...
            parts = slot_id.split("-")
            if len(parts) < 2:
                return False
            r, c = int(parts[1][:2]), int(parts[1][2:4])
        except Exception:
            return False

        at = at.astimezone(timezone.utc)
        b = self.res.get((r, c))
        return bool(b and b.start <= at < b.end)

    def book(self, start: datetime, duration_h: int, duration_d: int,
             duration_m: int, plate: str) -> Tuple[str, datetime, datetime, str]:
        # Validate durations
        if duration_h < 0 or duration_d < 0 or duration_m < 0:
            raise BookingError("Duration parts must be ≥ 0.")
        if duration_h == 0 and duration_d == 0 and duration_m == 0:
            raise BookingError("Duration cannot be zero.")
        
        
        print("Hello I am in this part of the code")

        # Normalize to UTC
        start = start.astimezone(timezone.utc)
        now = datetime.now(timezone.utc)
        if start <= now:
            raise BookingError("Start must be in the future.")

        plate = plate.strip().upper()
        if not plate:
            raise BookingError("Plate cannot be empty.")

        # Compute end time
        mid = self._add_months(start, duration_m)
        end = mid + timedelta(days=duration_d, hours=duration_h)
        if end <= start:
            raise BookingError("Computed end ≤ start.")

        # Enforce maximum booking duration
        if (end - start) > self.MAX_DURATION:
            raise BookingError("Booking duration exceeds allowed maximum.")

        # Check overall occupancy
        if self.TOTAL - self.occupancy_at(start) <= 0:
            raise BookingError("No free slots at that time.")

        # Find a free slot
        slot = self.find_slot(start, end)
        print(slot)
        if slot is None:
            raise BookingError("No non-overlapping slot found.")
        r, c = slot
        
        # Store booking
        self.res[(r, c)] = Booking(start=start, end=end, plate=plate)

        # Log the booking
        log_booking(r, c, plate,
                    start.year, start.month, start.day, start.hour, start.minute,
                    end.year, end.month, end.day, end.hour, end.minute)

        # Generate and return identifiers
        qr = self.generate_qr(r, c, start, end, plate)
        slot_id = f"{r:02d}{c:02d}"
        
        return (r,c), start, end, qr

    def cancel(self, r: int, c: int, start: datetime, end: datetime, plate: str) -> None:
        key = (r, c)
        start = start.astimezone(timezone.utc)
        end = end.astimezone(timezone.utc)
        plate = plate.strip().upper()
        booking = self.res.get(key)

        # Validate cancel request
        if not booking or booking.plate != plate or booking.start != start or booking.end != end:
            raise BookingError("No matching reservation found.")

        # Remove and log cancellation
        self.res.pop(key)
        log_cancellation(r, c, plate,
                         start.year, start.month, start.day, start.hour, start.minute,
                         end.year, end.month, end.day, end.hour, end.minute)

# Shared instance for application
service = BookingService()
