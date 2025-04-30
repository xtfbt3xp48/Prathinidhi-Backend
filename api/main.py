import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import FastAPI, HTTPException, Depends, Request,APIRouter, File, UploadFile
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi import UploadFile, File
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional
from fastapi.responses import FileResponse





# === CONFIG ===
SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# === APP INITIALIZATION ===
app = FastAPI()
auth_scheme = HTTPBearer()

# === CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === FIREBASE SETUP ===

FIREBASE_CRED_PATH = os.getenv("FIREBASE_CRED_PATH")

if FIREBASE_CRED_PATH:
    cred = credentials.Certificate(FIREBASE_CRED_PATH)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
else:
    raise ValueError("FIREBASE_CRED_PATH environment variable not set")

# === JWT UTILS ===
def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# === SESSION STORE ===
session_tokens = {}

# === DEPENDENCY ===
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    token = credentials.credentials
    user_data = verify_token(token)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    aadhaar = user_data.get("aadhaar")
    if session_tokens.get(aadhaar) != token:
        raise HTTPException(status_code=401, detail="Session expired or logged in elsewhere")
    
    return user_data

# === ROUTES ===

# Custom 404 handler
@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    file_path = os.path.join("static", "er404.html")
    return FileResponse(file_path, status_code=404)

@app.post("/login")
async def login(data: dict):
    aadhaar = data.get("aadhaar")
    mobile = data.get("mobile")
    otp = data.get("otp")

    # Retrieve users from Firebase Firestore
    users_ref = db.collection("users")
    docs = users_ref.stream()

    for doc in docs:
        user = doc.to_dict()
        if user["aadhaar"] == aadhaar and user["mobile"] == mobile and user["otp"] == otp:
            token = create_access_token({"aadhaar": aadhaar})
            session_tokens[aadhaar] = token
            return {"token": token, "message": "Login successful"}
    
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/dashboard")
async def get_dashboard(user=Depends(get_current_user)):
    aadhaar = user.get("aadhaar")
    # Retrieve user from Firebase Firestore
    user_ref = db.collection("users").document(aadhaar)
    user_doc = user_ref.get()
    
    if user_doc.exists:
        return {"user": user_doc.to_dict()}
    else:
        raise HTTPException(status_code=404, detail="User not found")

@app.post("/complaint")
async def file_complaint(data: dict, user=Depends(get_current_user)):
    aadhaar = user.get("aadhaar")
    
    complaint = {
        "applicationType": data.get("applicationType"),
        "receivedThrough": data.get("receivedThrough"),
        "problemSummary": data.get("problemSummary"),
        "religion": data.get("religion"),
        "caste": data.get("caste"),
        "occupation": data.get("occupation"),
        "timestamp": datetime.utcnow().isoformat()
    }

    # Retrieve user from Firebase Firestore
    user_ref = db.collection("users").document(aadhaar)
    user_doc = user_ref.get()
    
    if user_doc.exists:
        user_data = user_doc.to_dict()
        complaints = user_data.get("complaints", [])
        complaints.append(complaint)
        
        # Update the user's complaints in Firebase Firestore
        user_ref.update({"complaints": complaints})
        
        return {"message": "Complaint filed successfully", "complaint": complaint}
    else:
        raise HTTPException(status_code=404, detail="User not found")