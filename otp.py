import random
from datetime import datetime, timedelta

otp_store = {}  # Store OTPs temporarily in memory

def generate_otp(user_id):
    otp = random.randint(100000, 999999)
    expiry = datetime.utcnow() + timedelta(seconds=300)  # 5 minutes
    otp_store[user_id] = (otp, expiry)
    return otp

def validate_otp(user_id, input_otp):
    if user_id in otp_store:
        otp, expiry = otp_store[user_id]
        if otp == int(input_otp) and expiry > datetime.utcnow():
            del otp_store[user_id]  # Clear OTP after successful validation
            return True
    return False
