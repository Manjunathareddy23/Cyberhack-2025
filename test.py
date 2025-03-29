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

# Load environment variables
load_dotenv()

# Configure API and Email
API_KEY = os.getenv('GEMINI_API_KEY')
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

genai.configure(api_key=API_KEY)

# Function to set background
def set_background():
    background_url =   # Replace with your actual GitHub raw URL
    st.markdown(
        f"""
        <style>
        .stApp {{
            background-image: url('https://raw.githubusercontent.com/Manjunathareddy23/Cyberhack-2025/main/back.jpg');
            background-size: cover;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

set_background()

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

st.title("🔑 Secure Authentication System")

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

login_tab, register_tab, reset_tab = st.tabs(["🔓 Login", "📝 Register", "🔑 Reset Password"])

# LOGIN
with login_tab:
    st.header("🔑 Login")
    username = st.text_input("📧 Email (Username)", key="login_username")
    password = st.text_input("🔒 Password", type="password", key="login_password")
    face_image = st.camera_input("📸 Face Verification", key="login_face")
    voice_recording = st.file_uploader("🎙️ Voice Verification (Upload WAV)", type=["wav"], key="login_voice")
    
    if st.button("🔓 Login"):
        users = load_users()
        if username in users and verify_password(password, users[username]['password']):
            if face_image and voice_recording:
                mfa_code = generate_mfa(username)
                send_email(username, "Your MFA Code", f"Your MFA code is {mfa_code}")
                st.session_state.pending_mfa_user = username
                st.success("✅ MFA Code Sent! Please enter below.")
        else:
            st.error("❌ Invalid email or password!")
    
    if 'pending_mfa_user' in st.session_state:
        user_mfa = st.text_input("🔢 Enter MFA Code", key="mfa_code")
        if st.button("✅ Verify MFA"):
            if verify_mfa(st.session_state.pending_mfa_user, user_mfa):
                st.session_state.authenticated = True
                st.success("✅ Login successful!")
                del st.session_state.pending_mfa_user
            else:
                st.error("❌ Incorrect MFA Code!")

# REGISTER
with register_tab:
    st.header("📝 Register")
    new_username = st.text_input("📧 Email (Username)", key="register_username")
    new_password = st.text_input("🔒 Password", type="password", key="register_password")
    confirm_password = st.text_input("🔑 Confirm Password", type="password", key="confirm_register_password")
    face_image = st.camera_input("📸 Register Face", key="register_face")
    voice_recording = st.file_uploader("🎙️ Record Your Voice (Upload WAV)", type=["wav"], key="register_voice")
    
    if st.button("📝 Register"):
        users = load_users()
        if new_username in users:
            st.error("⚠️ Email already registered!")
        elif new_password != confirm_password:
            st.error("⚠️ Passwords do not match!")
        elif face_image and voice_recording:
            users[new_username] = {'password': hash_password(new_password)}
            save_users(users)
            st.success("✅ Registration successful! Please log in.")
        else:
            st.error("⚠️ Please provide both face and voice data!")

# RESET PASSWORD
with reset_tab:
    st.header("🔑 Reset Password")
    reset_email = st.text_input("📧 Enter your email", key="reset_email")
    
    if st.button("📨 Send Reset Code"):
        users = load_users()
        if reset_email in users:
            reset_code = generate_mfa(reset_email)
            send_email(reset_email, "Reset Your Password", f"Your reset code is {reset_code}")
            st.session_state.pending_reset_user = reset_email
            st.success("📩 Reset code sent to your email!")
        else:
            st.error("❌ Email not registered!")
