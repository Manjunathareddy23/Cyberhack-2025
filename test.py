import streamlit as st
import google.generativeai as genai
import os
import json
import hashlib
import hmac
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini API
API_KEY = os.getenv('GEMINI_API_KEY')

if not API_KEY:
    st.error("⚠️ GEMINI_API_KEY not found in environment variables!")
else:
    genai.configure(api_key=API_KEY)

def get_model():
    """Retrieve the Generative AI model and handle errors."""
    try:
        return genai.GenerativeModel(name="gemini-pro-vision")  # ✅ Corrected Model Call
    except Exception as e:
        st.error(f"❌ Error initializing AI model: {e}")
        return None

# Streamlit Page Config
st.set_page_config(page_title="🔒 Secure Authentication System", page_icon="🔑", layout="wide")

# Session State
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_data' not in st.session_state:
    st.session_state.user_data = {}

# Constants
USERS_DB = "users.json"

# Load users
def load_users():
    try:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f:
                return json.load(f)
        return {}
    except json.JSONDecodeError:
        return {}

# Save users
def save_users(users):
    with open(USERS_DB, 'w') as f:
        json.dump(users, f, indent=4)

# Hash Password
def hash_password(password):
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000)
    return salt + hashed

# Verify Password
def verify_password(password, stored_hash):
    salt, hashed = stored_hash[:16], stored_hash[16:]
    return hmac.compare_digest(hashed, hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000))

# Face Verification using Gemini Vision
def verify_face(image_path, stored_image_path):
    model = get_model()
    if model is None:
        return False

    try:
        with open(image_path, "rb") as img1, open(stored_image_path, "rb") as img2:
            response = model.generate_content(
                ["Compare these faces and return 'true' if they match, otherwise 'false'."],
                [img1.read(), img2.read()]
            )
        
        return response.text.strip().lower() == 'true'

    except Exception as e:
        st.error(f"⚠️ Face verification error: {e}")
        return False

# Streamlit UI
st.title("🔑 Secure Authentication System")

if not st.session_state.authenticated:
    tab1, tab2 = st.tabs(["🔓 Login", "📝 Register"])

    # 🔑 Login Tab
    with tab1:
        st.header("🔑 Login")
        username = st.text_input("👤 Username")
        password = st.text_input("🔒 Password", type="password")
        face_image = st.camera_input("📸 Face Verification")

        if st.button("🔓 Login"):
            users = load_users()
            if username in users:
                if verify_password(password, bytes.fromhex(users[username]['password'])):
                    if face_image:
                        image_path = f"temp_{username}.jpg"
                        with open(image_path, "wb") as f:
                            f.write(face_image.getbuffer())  # ✅ Fix: Save uploaded image properly

                        if verify_face(image_path, users[username]['face_data']):
                            st.session_state.authenticated = True
                            st.session_state.user_data['username'] = username
                            st.success("✅ Login successful!")
                            st.rerun()
                        else:
                            st.error("❌ Face verification failed!")
                    else:
                        st.error("⚠️ Please provide a face image for verification!")
                else:
                    st.error("❌ Invalid password!")
            else:
                st.error("❌ User not found!")

    # 📝 Registration Tab
    with tab2:
        st.header("📝 Register")
        new_username = st.text_input("👤 New Username")
        new_password = st.text_input("🔒 New Password", type="password")
        confirm_password = st.text_input("🔑 Confirm Password", type="password")
        face_image = st.camera_input("📸 Register Face")

        if st.button("📝 Register"):
            users = load_users()
            if new_username in users:
                st.error("⚠️ Username already exists!")
            elif new_password != confirm_password:
                st.error("⚠️ Passwords do not match!")
            elif face_image:
                hashed_password = hash_password(new_password).hex()
                face_path = f"face_{new_username}.jpg"

                # ✅ Fix: Save the face image properly
                with open(face_path, "wb") as f:
                    f.write(face_image.getbuffer())

                users[new_username] = {'password': hashed_password, 'face_data': face_path}
                save_users(users)
                st.success("✅ Registration successful! You can now log in.")
                st.rerun()
            else:
                st.error("⚠️ Please provide a face image!")

else:
    st.success(f"✅ Welcome, {st.session_state.user_data.get('username', 'User')}!")
    if st.button("🚪 Logout"):
        st.session_state.authenticated = False
        st.rerun()
