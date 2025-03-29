import streamlit as st
import google.generativeai as genai
import os
import json
import hashlib
import hmac
import smtplib
import random
import numpy as np
from email.message import EmailMessage
from dotenv import load_dotenv
from PIL import Image
import imagehash
from pydub import AudioSegment
import ffmpeg

# Load environment variables
load_dotenv()

# Configure Gemini API
API_KEY = os.getenv('GEMINI_API_KEY')
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

genai.configure(api_key=API_KEY)

# Directory for storing user data
DATA_DIR = "user_data"
os.makedirs(DATA_DIR, exist_ok=True)

# Ensure ffmpeg is installed
def check_ffmpeg():
    try:
        ffmpeg.probe("test.wav")
    except:
        st.error("FFmpeg is missing! Install it using: sudo apt install ffmpeg")
check_ffmpeg()

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

# MFA Code Management
mfa_codes = {}

def generate_mfa(username):
    code = str(random.randint(100000, 999999))
    mfa_codes[username] = code
    return code

def verify_mfa(username, code):
    return mfa_codes.get(username) == code

# Load & Save Users
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

# Face Recognition
def compute_image_hash(image):
    img = Image.open(image)
    return str(imagehash.average_hash(img))

# Voice Recognition
def compute_audio_fingerprint(audio):
    try:
        sound = AudioSegment.from_file(audio)
        samples = np.array(sound.get_array_of_samples())
        return hashlib.md5(samples.tobytes()).hexdigest()
    except Exception as e:
        st.error(f"Error processing audio: {e}")
        return None

# Streamlit UI
st.title("🔑 Secure Authentication System")

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_data' not in st.session_state:
    st.session_state.user_data = {}

tab1, tab2 = st.tabs(["🔓 Login", "📝 Register"])

# 🔓 Login
with tab1:
    st.header("🔑 Login")
    username = st.text_input("📧 Email (Username)", key="login_username")
    password = st.text_input("🔒 Password", type="password", key="login_password")
    face_image = st.camera_input("📸 Face Verification", key="login_face")
    voice_recording = st.file_uploader("🎙️ Voice Verification (Upload WAV)", type=["wav"], key="login_voice")

    if st.button("🔓 Login"):
        users = load_users()
        if username in users:
            if verify_password(password, users[username]['password']):
                stored_face_hash = users[username].get('face_hash')
                stored_voice_fingerprint = users[username].get('voice_fingerprint')

                if stored_face_hash and stored_voice_fingerprint:
                    if face_image and voice_recording:
                        uploaded_face_hash = compute_image_hash(face_image)
                        uploaded_voice_fingerprint = compute_audio_fingerprint(voice_recording)
                        
                        if uploaded_voice_fingerprint and uploaded_face_hash == stored_face_hash and uploaded_voice_fingerprint == stored_voice_fingerprint:
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
                            st.error("❌ Face or voice verification failed!")
                    else:
                        st.error("⚠️ Please provide both face and voice verification!")
                else:
                    st.error("⚠️ Face or voice data missing. Please re-register.")
            else:
                st.error("❌ Invalid password!")
        else:
            st.error("❌ User not found!")

# 📝 Register
with tab2:
    st.header("📝 Register")
    new_username = st.text_input("📧 Email (Username)", key="register_username")
    new_password = st.text_input("🔒 Password", type="password", key="register_password")
    confirm_password = st.text_input("🔑 Confirm Password", type="password", key="register_confirm_password")
    face_image = st.camera_input("📸 Register Face", key="register_face")
    voice_recording = st.file_uploader("🎙️ Record Your Voice (Upload WAV)", type=["wav"], key="register_voice")

    if st.button("📝 Register"):
        users = load_users()
        if new_username in users:
            st.error("⚠️ Email already registered!")
        elif new_password != confirm_password:
            st.error("⚠️ Passwords do not match!")
        elif face_image and voice_recording:
            hashed_password = hash_password(new_password)
            face_hash = compute_image_hash(face_image)
            voice_fingerprint = compute_audio_fingerprint(voice_recording)
            
            if voice_fingerprint:
                users[new_username] = {
                    'password': hashed_password,
                    'face_hash': face_hash,
                    'voice_fingerprint': voice_fingerprint
                }
                save_users(users)
                st.success("✅ Registration successful! Please log in.")
            else:
                st.error("⚠️ Error processing voice file!")
