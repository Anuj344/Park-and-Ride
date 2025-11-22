# Project Name

## 📌 Overview
This project consists of a **frontend** (Node.js/React) and a **backend** (FastAPI with Python).  
The frontend is started using `npm run dev`, while the backend runs with **Uvicorn** on port **8002**.  
Stripe is integrated, and you need to configure the webhook destination to point to the backend.

---

## 🚀 Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/Anuj344/Park-and-Ride.git
cd ParkandRide

```

---

### 2. Backend Setup (FastAPI + Uvicorn)

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # Mac/Linux
   venv\Scripts\activate      # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the backend with **Uvicorn**:
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8002 --reload
   ```
   > Backend will now run at: **http://localhost:8002**

---

### 3. Frontend Setup (React / Next.js)

1. Navigate to the frontend directory:
   ```bash
   cd ../frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the frontend:
   ```bash
   npm run dev
   ```

4. Access the frontend at:
   ```
   http://localhost:3000
   ```

---

### 4. Stripe Webhook Setup

1. Start your backend first (`localhost:8002`).  
2. Use Stripe CLI to forward webhooks to your backend:
   ```bash
   stripe listen --forward-to localhost:8002/webhook
   ```
3. Update your Stripe Dashboard → **Developers > Webhooks**  
   - Set the destination URL to:  
     ```
     http://localhost:8002/webhook
     ```

---

## ⚡ Running the Full Application

1. Start the **backend** (`uvicorn` on port `8002`).  
2. Run the **frontend** with `npm run dev` (`localhost:3000`).  
3. Ensure Stripe webhooks are pointing to `localhost:8002/webhook`.  

---

## 🛠️ Project Structure
```
project-root/
│── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── ...
│
│── frontend/
│   ├── package.json
│   ├── pages/
│   └── ...
│
└── README.md
```

---

## ✅ Requirements
- **Backend**: Python 3.8+, Uvicorn, FastAPI  
- **Frontend**: Node.js 18+, npm  
- **Payments**: Stripe CLI for webhook testing  

