import os
import json
from datetime import datetime
from dateutil.parser import isoparse  # Safer for ISO strings like "2025-06-25T11:33:00Z"

LOG_FILE: str = os.getenv("BOOKING_LOG_FILE", "realtime.log")
TOTAL_SLOTS: int = 20 * 20  # Assuming 20x20 grid

def current_occupancy(at: datetime = None) -> int:
    """Returns number of occupied slots at the given time."""
    at = at or datetime.utcnow()
    reservations: dict[tuple[int, int], tuple[datetime, datetime]] = {}

    if not os.path.exists(LOG_FILE):
        return 0

    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                action = entry["action"].upper()
                row, col = entry["row"], entry["col"]
                start = isoparse(entry["start"])
                end = isoparse(entry["end"])
                key = (row, col)
            except (ValueError, KeyError, TypeError):
                continue  # skip malformed lines

            if action == "BOOKING":
                reservations[key] = (start, end)
            elif action == "CANCEL":
                reservations.pop(key, None)

    return sum(1 for (start, end) in reservations.values() if start <= at < end)

def report_availability() -> None:
    """Prints number of occupied and free slots right now."""
    now = datetime.utcnow()
    occupied = current_occupancy(now)
    free = TOTAL_SLOTS - occupied
    print(f"[{now.isoformat()} UTC]    Occupied: {occupied}/{TOTAL_SLOTS}    Free: {free}")

if __name__ == "__main__":
    report_availability()
