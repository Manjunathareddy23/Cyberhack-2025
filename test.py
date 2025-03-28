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

# Configure Gemini API
API_KEY = os.getenv('GEMINI_API_KEY')
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

genai.configure(api_key=API_KEY)

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

# MFA Generation
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

def hash_password(password):
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000)
    return salt + hashed

def verify_password(password, stored_hash):
    salt, hashed = stored_hash[:16], stored_hash[16:]
    return hmac.compare_digest(hashed, hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000))

st.title("🔑 Secure Authentication System")

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_data' not in st.session_state:
    st.session_state.user_data = {}

tab1, tab2, tab3 = st.tabs(["🔓 Login", "📝 Register", "🔑 Reset Password"])

# Login
with tab1:
    st.header("🔑 Login")
    username = st.text_input("📧 Email (Username)")
    password = st.text_input("🔒 Password", type="password")
    face_image = st.camera_input("📸 Face Verification")
    voice_recording = st.file_uploader("🎙️ Voice Verification (Upload WAV)", type=["wav"])
    
    if st.button("🔓 Login"):
        users = load_users()
        if username in users:
            if verify_password(password, bytes.fromhex(users[username]['password'])):
                if face_image and voice_recording:
                    mfa_code = generate_mfa(username)
                    send_email(username, "Your MFA Code", f"Your MFA code is {mfa_code}")
                    
                    user_mfa = st.text_input("🔢 Enter MFA Code")
                    if st.button("✅ Verify MFA"):
                        if verify_mfa(username, user_mfa):
                            st.session_state.authenticated = True
                            st.session_state.user_data['username'] = username
                            st.success("✅ Login successful!")
                        else:
                            st.error("❌ Incorrect MFA Code!")
                            send_email(username, "Unauthorized Login Attempt", "There was an unsuccessful login attempt.")
                else:
                    st.error("⚠️ Please provide both face and voice verification!")
            else:
                st.error("❌ Invalid password!")
                send_email(username, "Unauthorized Login Attempt", "There was an unsuccessful login attempt.")
        else:
            st.error("❌ User not found!")

# Register
with tab2:
    st.header("📝 Register")
    new_username = st.text_input("📧 Email (Username)")
    new_password = st.text_input("🔒 Password", type="password")
    confirm_password = st.text_input("🔑 Confirm Password", type="password")
    face_image = st.camera_input("📸 Register Face")
    voice_recording = st.file_uploader("🎙️ Record Your Voice (Upload WAV)", type=["wav"])
    
    if st.button("📝 Register"):
        users = load_users()
        if new_username in users:
            st.error("⚠️ Email already registered!")
        elif new_password != confirm_password:
            st.error("⚠️ Passwords do not match!")
        elif face_image and voice_recording:
            hashed_password = hash_password(new_password).hex()
            users[new_username] = {'password': hashed_password, 'face_data': "face.jpg", 'voice_data': "voice.wav"}
            save_users(users)
            st.success("✅ Registration successful! Please log in.")
        else:
            st.error("⚠️ Please provide both face and voice data!")

# Reset Password
with tab3:
    st.header("🔑 Reset Password")
    reset_email = st.text_input("📧 Enter your email")
    
    if st.button("📨 Send Reset Code"):
        users = load_users()
        if reset_email in users:
            reset_code = generate_mfa(reset_email)
            send_email(reset_email, "Reset Your Password", f"Your reset code is {reset_code}")
            st.success("📩 Reset code sent to your email!")
        else:
            st.error("❌ Email not registered!")

    reset_code_input = st.text_input("🔢 Enter Reset Code")
    new_reset_password = st.text_input("🔒 New Password", type="password")
    confirm_reset_password = st.text_input("🔑 Confirm New Password", type="password")
    
    if st.button("🔄 Reset Password"):
        if verify_mfa(reset_email, reset_code_input):
            if new_reset_password == confirm_reset_password:
                users[reset_email]['password'] = hash_password(new_reset_password).hex()
                save_users(users)
                st.success("✅ Password successfully reset! Please log in.")
            else:
                st.error("⚠️ Passwords do not match!")
        else:
            st.error("❌ Invalid reset code!")
