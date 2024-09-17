class Config:
    SECRET_KEY = 'your_secret_key_here'
    MONGO_URI = "mongodb://localhost:27017/flaskdb"  # MongoDB URI
    OTP_EXPIRY_TIME = 300  # 5 minutes for OTP expiry
