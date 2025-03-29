import streamlit as st
import google.generativeai as genai
import os
import json
import hashlib
import hmac
import smtplib
import random
from email.message import EmailMessage
from dotenv import load_dotenv

# Ensure required packages are available
try:
    from moviepy.editor import AudioFileClip  # Ensure moviepy is installed
    import imageio
    import imagehash
    import numpy as np
    import cv2
    import pydub
    import streamlit_webrtc
    import email_validator
except ModuleNotFoundError as e:
    st.error(f"Missing module: {e.name}. Please install it using pip.")

# Load environment variables
load_dotenv()
API_KEY = os.getenv('GEMINI_API_KEY')
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

# Validate API key and email credentials
if not API_KEY:
    st.error("❌ Missing GEMINI_API_KEY in .env file.")
if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
    st.error("❌ Missing email credentials in .env file.")

# Configure Generative AI
genai.configure(api_key=API_KEY)

# Function to send email
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
if 'mfa_codes' not in st.session_state:
    st.session_state.mfa_codes = {}

def generate_mfa(username):
    code = str(random.randint(100000, 999999))
    st.session_state.mfa_codes[username] = code
    return code

def verify_mfa(username, code):
    return st.session_state.mfa_codes.get(username) == code

# User Management
def load_users():
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
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

# Streamlit UI
st.title("🔑 Secure Authentication System")

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

tab1, tab2, tab3 = st.tabs(["🔓 Login", "📝 Register", "🔑 Reset Password"])

# LOGIN
with tab1:
    st.header("🔑 Login")
    username = st.text_input("📧 Email (Username)")
    password = st.text_input("🔒 Password", type="password")
    if st.button("🔓 Login"):
        users = load_users()
        if username in users and verify_password(password, users[username]['password']):
            mfa_code = generate_mfa(username)
            send_email(username, "Your MFA Code", f"Your MFA code is {mfa_code}")
            st.session_state.pending_mfa_user = username  # Store pending MFA user
            st.success("✅ MFA Code Sent! Please enter below.")
    
    if 'pending_mfa_user' in st.session_state:
        user_mfa = st.text_input("🔢 Enter MFA Code")
        if st.button("✅ Verify MFA"):
            if verify_mfa(st.session_state.pending_mfa_user, user_mfa):
                st.session_state.authenticated = True
                st.success("✅ Login successful!")
                del st.session_state.pending_mfa_user  # Clear after success
            else:
                st.error("❌ Incorrect MFA Code!")

# REGISTER
with tab2:
    st.header("📝 Register")
    new_username = st.text_input("📧 Email (Username)")
    new_password = st.text_input("🔒 Password", type="password")
    confirm_password = st.text_input("🔑 Confirm Password", type="password")
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
    reset_email = st.text_input("📧 Enter your email")
    if st.button("📨 Send Reset Code"):
        users = load_users()
        if reset_email in users:
            reset_code = generate_mfa(reset_email)
            send_email(reset_email, "Reset Your Password", f"Your reset code is {reset_code}")
            st.session_state.pending_reset_user = reset_email  # Store user for reset
            st.success("📩 Reset code sent to your email!")
        else:
            st.error("❌ Email not registered!")
    
    if 'pending_reset_user' in st.session_state:
        reset_code_input = st.text_input("🔢 Enter Reset Code")
        new_reset_password = st.text_input("🔒 New Password", type="password")
        confirm_reset_password = st.text_input("🔑 Confirm New Password", type="password")
        if st.button("🔄 Reset Password"):
            if verify_mfa(st.session_state.pending_reset_user, reset_code_input):
                if new_reset_password == confirm_reset_password:
                    users[st.session_state.pending_reset_user]['password'] = hash_password(new_reset_password)
                    save_users(users)
                    del st.session_state.pending_reset_user  # Clear session state
                    st.success("✅ Password successfully reset! Please log in.")
                else:
                    st.error("⚠️ Passwords do not match!")
            else:
                st.error("❌ Invalid reset code!")
