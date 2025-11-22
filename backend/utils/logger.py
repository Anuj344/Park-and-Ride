# utils/logger.py
import os
import logging
from datetime import datetime
from typing import List, Tuple, Dict
from collections import namedtuple

Booking = namedtuple("Booking", ["start", "end", "plate"])
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "realtime.log")

# Ensure log file exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
if not os.path.exists(LOG_FILE):
    open(LOG_FILE, "a").close()

# Setup logger
logger = logging.getLogger("booking_logger")
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# File handler
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S")
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# Add handlers
logger.addHandler(console_handler)
logger.addHandler(file_handler)

def _append_event(fields: List[str]) -> None:
    logger.info(" ".join(fields))

def log_booking(r, c, plate, sy, smo, sd, sh, smin, ey, emo, ed, eh, emin):
    _append_event(["BOOKING", str(r), str(c), plate,
                   str(sy), str(smo), str(sd), str(sh), str(smin),
                   str(ey), str(emo), str(ed), str(eh), str(emin)])

def log_cancellation(r, c, plate, sy, smo, sd, sh, smin, ey, emo, ed, eh, emin):
    _append_event(["CANCEL", str(r), str(c), plate,
                   str(sy), str(smo), str(sd), str(sh), str(smin),
                   str(ey), str(emo), str(ed), str(eh), str(emin)])

def replay_reservations() -> Dict[Tuple[int, int], Booking]:
    reservations = {}
    with open(LOG_FILE, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 5:
                continue
            _, etype, rs, cs, plate, *rest = parts
            if len(rest) != 10:
                continue
            try:
                r, c = int(rs), int(cs)
                times = list(map(int, rest))
                sdt = datetime(*times[:5])
                edt = datetime(*times[5:])
                key = (r, c)
                if etype == "BOOKING":
                    reservations[key] = Booking(start=sdt, end=edt, plate=plate)
                elif etype == "CANCEL":
                    existing = reservations.get(key)
                    if existing and existing.start == sdt and existing.end == edt and existing.plate == plate:
                        reservations.pop(key, None)
            except:
                continue
    return reservations
