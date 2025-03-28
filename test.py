import streamlit as st
import os
from dotenv import load_dotenv
from utils.auth import load_users, save_users, hash_password, verify_password
from utils.face_verification import verify_face

# Load environment variables
load_dotenv()

# Streamlit Page Config
st.set_page_config(
    page_title="🔒 Secure Authentication System", 
    page_icon="🔑", 
    layout="wide"
)

# Session State Initialization
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_data' not in st.session_state:
    st.session_state.user_data = {}
if 'temp_files' not in st.session_state:
    st.session_state.temp_files = []

# Constants
USERS_DB = "users.json"
FACE_STORAGE_DIR = "face_data"

# Create face storage directory if it doesn't exist
if not os.path.exists(FACE_STORAGE_DIR):
    os.makedirs(FACE_STORAGE_DIR)

# Main UI
def main():
    st.title("🔒 Secure Three-Factor Authentication System")
    
    if not st.session_state.authenticated:
        display_authentication_ui()
    else:
        display_authenticated_ui()

def display_authentication_ui():
    tab1, tab2 = st.tabs(["🔓 Login", "📝 Register"])

    # Login Tab
    with tab1:
        st.header("🔓 Login")
        login_username = st.text_input("👤 Username", key="login_username")
        login_password = st.text_input("🔒 Password", type="password", key="login_password")
        
        # Face verification
        face_col1, face_col2 = st.columns([1, 1])
        with face_col1:
            st.markdown("📸 **Face Verification**")
            login_face_image = st.camera_input("Take a photo for verification", key="login_face")
        
        with face_col2:
            st.markdown("### Instructions")
            st.info("""
            1. Position your face clearly in the camera
            2. Ensure good lighting
            3. Remove glasses or items that obscure your face
            4. Click the capture button to take a photo
            """)
        
        if st.button("🔓 Login", use_container_width=True):
            process_login(login_username, login_password, login_face_image)

    # Registration Tab
    with tab2:
        st.header("📝 Register")
        reg_username = st.text_input("👤 New Username", key="reg_username")
        reg_password = st.text_input("🔒 New Password", type="password", key="reg_password")
        confirm_password = st.text_input("🔑 Confirm Password", type="password", key="confirm_password")
        
        # Face registration
        face_col1, face_col2 = st.columns([1, 1])
        with face_col1:
            st.markdown("📸 **Face Registration**")
            reg_face_image = st.camera_input("Take a photo for registration", key="reg_face")
        
        with face_col2:
            st.markdown("### Guidelines")
            st.info("""
            1. Position your face clearly in the camera
            2. Ensure good lighting
            3. Choose a neutral expression
            4. Remember the pose/angle for future logins
            """)
        
        if st.button("📝 Register", use_container_width=True):
            process_registration(reg_username, reg_password, confirm_password, reg_face_image)

def process_login(username, password, face_image):
    """Process the login attempt with three-factor authentication"""
    users = load_users()
    
    # 1. Check username
    if not username:
        st.error("⚠️ Please enter a username")
        return
    
    if username not in users:
        st.error("❌ User not found!")
        return
    
    # 2. Check password
    try:
        if not password:
            st.error("⚠️ Please enter a password")
            return
            
        if not verify_password(password, bytes.fromhex(users[username]['password'])):
            st.error("❌ Invalid password!")
            return
    except Exception as e:
        st.error(f"❌ Error verifying password: {e}")
        return
    
    # 3. Check face verification
    if not face_image:
        st.error("⚠️ Please provide a face image for verification!")
        return
    
    try:
        # Save temporary image
        image_path = os.path.join(FACE_STORAGE_DIR, f"temp_{username}.jpg")
        with open(image_path, "wb") as f:
            f.write(face_image.getbuffer())
        
        # Add to temporary files for cleanup
        st.session_state.temp_files.append(image_path)
        
        # Verify face
        stored_face_path = users[username]['face_data']
        
        with st.spinner("Verifying your face..."):
            if verify_face(image_path, stored_face_path):
                st.session_state.authenticated = True
                st.session_state.user_data['username'] = username
                st.success("✅ Login successful! Redirecting to your dashboard...")
                st.rerun()
            else:
                st.error("❌ Face verification failed! Please try again.")
    except Exception as e:
        st.error(f"⚠️ Face verification error: {e}")

def process_registration(username, password, confirm_password, face_image):
    """Process the registration with all required information"""
    users = load_users()
    
    # Input validation
    if not username:
        st.error("⚠️ Please enter a username")
        return
        
    if username in users:
        st.error("⚠️ Username already exists!")
        return
    
    if not password:
        st.error("⚠️ Please enter a password")
        return
        
    if password != confirm_password:
        st.error("⚠️ Passwords do not match!")
        return
    
    if not face_image:
        st.error("⚠️ Please provide a face image for registration!")
        return
    
    try:
        # Hash password
        hashed_password = hash_password(password).hex()
        
        # Save face image
        face_path = os.path.join(FACE_STORAGE_DIR, f"face_{username}.jpg")
        with open(face_path, "wb") as f:
            f.write(face_image.getbuffer())
        
        # Store user data
        users[username] = {'password': hashed_password, 'face_data': face_path}
        save_users(users)
        
        st.success("✅ Registration successful! You can now log in.")
        # Clear the form
        st.session_state.reg_username = ""
        st.session_state.reg_password = ""
        st.session_state.confirm_password = ""
        st.session_state.reg_face = None
    except Exception as e:
        st.error(f"⚠️ Registration error: {e}")

def display_authenticated_ui():
    """Display the authenticated user interface"""
    st.success(f"✅ Welcome, {st.session_state.user_data.get('username', 'User')}!")
    
    st.markdown("""
    ## 🔐 You are securely authenticated!
    
    Your account is protected by three-factor authentication:
    1. 👤 Something you know (username)
    2. 🔑 Something you know (password)
    3. 📸 Something you are (face verification)
    
    This provides much stronger security than traditional username/password authentication.
    """)
    
    # Cleanup temporary files
    if st.session_state.temp_files:
        for file_path in st.session_state.temp_files:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass
        st.session_state.temp_files = []
    
    # Logout button
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.user_data = {}
        st.rerun()

# Run the application
if __name__ == "__main__":
    main()
