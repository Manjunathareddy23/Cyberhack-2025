import streamlit as st
import google.generativeai as genai
import os
import json
import hashlib
import hmac
import smtplib
import random
import subprocess
from email.message import EmailMessage
from dotenv import load_dotenv
from pydub import AudioSegment

# Check and install FFmpeg if missing
def check_ffmpeg():
    try:
        subprocess.run(["ffmpeg", "-version"], check=True, capture_output=True)
    except FileNotFoundError:
        st.error("FFmpeg is missing! Install it using: sudo apt install ffmpeg")

check_ffmpeg()

# Load environment variables
load_dotenv()
API_KEY = os.getenv('GEMINI_API_KEY')
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

genai.configure(api_key=API_KEY)

# Send email
def send_email(to_email, subject, body):
    try:
        msg = EmailMessage()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.set_content(body)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        st.error(f"Email sending failed: {e}")

# MFA Management
mfa_codes = {}

def generate_mfa(username):
    code = str(random.randint(100000, 999999))
    mfa_codes[username] = code
    return code

def verify_mfa(username, code):
    return mfa_codes.get(username) == code

def load_users():
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

# Password Hashing
def hash_password(password):
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000)
    return (salt + hashed).hex()

def verify_password(password, stored_hash):
    stored_hash = bytes.fromhex(stored_hash)
    salt, hashed = stored_hash[:16], stored_hash[16:]
    return hmac.compare_digest(hashed, hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000))

st.title("🔑 Secure Authentication System")

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_data' not in st.session_state:
    st.session_state.user_data = {}

tab1, tab2, tab3 = st.tabs(["🔓 Login", "📝 Register", "🔑 Reset Password"])

# LOGIN
with tab1:
    st.header("🔑 Login")
    username = st.text_input("📧 Email (Username)", key="login_email")
    password = st.text_input("🔒 Password", type="password", key="login_password")
    if st.button("🔓 Login"):
        users = load_users()
        if username in users and verify_password(password, users[username]['password']):
            mfa_code = generate_mfa(username)
            send_email(username, "Your MFA Code", f"Your MFA code is {mfa_code}")
            user_mfa = st.text_input("🔢 Enter MFA Code", key="login_mfa")
            if st.button("✅ Verify MFA"):
                if verify_mfa(username, user_mfa):
                    st.session_state.authenticated = True
                    st.success("✅ Login successful!")
                else:
                    st.error("❌ Incorrect MFA Code!")
        else:
            st.error("❌ Invalid credentials!")

# REGISTER
with tab2:
    st.header("📝 Register")
    new_username = st.text_input("📧 Email (Username)", key="register_email")
    new_password = st.text_input("🔒 Password", type="password", key="register_password")
    confirm_password = st.text_input("🔑 Confirm Password", type="password", key="register_confirm_password")
    if st.button("📝 Register"):
        users = load_users()
        if new_username in users:
            st.error("⚠️ Email already registered!")
        elif new_password != confirm_password:
            st.error("⚠️ Passwords do not match!")
        else:
            users[new_username] = {'password': hash_password(new_password)}
            save_users(users)
            st.success("✅ Registration successful! Please log in.")

# RESET PASSWORD
with tab3:
    st.header("🔑 Reset Password")
    reset_email = st.text_input("📧 Enter your email", key="reset_email")
    if st.button("📨 Send Reset Code"):
        users = load_users()
        if reset_email in users:
            reset_code = generate_mfa(reset_email)
            send_email(reset_email, "Reset Your Password", f"Your reset code is {reset_code}")
            st.success("📩 Reset code sent to your email!")
        else:
            st.error("❌ Email not registered!")
    
    reset_code_input = st.text_input("🔢 Enter Reset Code", key="reset_code")
    new_reset_password = st.text_input("🔒 New Password", type="password", key="new_reset_password")
    confirm_reset_password = st.text_input("🔑 Confirm New Password", type="password", key="confirm_reset_password")
    
    if st.button("🔄 Reset Password"):
        if verify_mfa(reset_email, reset_code_input):
            if new_reset_password == confirm_reset_password:
                users[reset_email]['password'] = hash_password(new_reset_password)
                save_users(users)
                st.success("✅ Password successfully reset! Please log in.")
            else:
                st.error("⚠️ Passwords do not match!")
        else:
            st.error("❌ Invalid reset code!")
