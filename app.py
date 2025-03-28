import streamlit as st
import google.generativeai as genai
from PIL import Image
import os
import json
import hashlib
import hmac
import base64
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini API
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))

# Set page config with custom theme
st.set_page_config(
    page_title="Secure Authentication System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced Custom CSS with Tailwind-like styles
st.markdown("""
    <style>
    /* Main container styles */
    .main {
        @apply max-w-7xl mx-auto px-4 sm:px-6 lg:px-8;
    }

    /* Button styles */
    .stButton>button {
        @apply w-full py-3 px-6 rounded-lg font-semibold text-white transition-all duration-200;
        background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
        box-shadow: 0 4px 6px rgba(76, 175, 80, 0.2);
    }
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 8px rgba(76, 175, 80, 0.3);
    }
    .stButton>button:active {
        transform: translateY(0);
    }

    /* Input field styles */
    .stTextInput>div>div>input {
        @apply w-full px-4 py-3 rounded-lg border border-gray-300 focus:ring-2 focus:ring-green-500 focus:border-transparent;
        transition: all 0.2s ease-in-out;
    }
    .stTextInput>div>div>input:focus {
        box-shadow: 0 0 0 2px rgba(76, 175, 80, 0.2);
    }

    /* Card styles */
    .css-1r6slb0 {  /* Streamlit's default card class */
        @apply bg-white rounded-xl shadow-lg p-6 border border-gray-100;
        backdrop-filter: blur(10px);
    }

    /* Message styles */
    .error-msg {
        @apply bg-red-50 text-red-700 p-4 rounded-lg border border-red-100 mb-4;
    }
    .success-msg {
        @apply bg-green-50 text-green-700 p-4 rounded-lg border border-green-100 mb-4;
    }
    .info-msg {
        @apply bg-blue-50 text-blue-700 p-4 rounded-lg border border-blue-100 mb-4;
    }

    /* Tab styles */
    .stTabs [data-baseweb="tab-list"] {
        @apply gap-2 p-1 rounded-lg bg-gray-100;
    }
    .stTabs [data-baseweb="tab"] {
        @apply px-6 py-2 rounded-lg font-medium transition-all duration-200;
    }
    .stTabs [aria-selected="true"] {
        @apply bg-white text-green-600 shadow-sm;
    }

    /* Sidebar styles */
    .css-1d391kg {  /* Streamlit's sidebar class */
        @apply bg-gray-50 border-r border-gray-200;
    }

    /* Header styles */
    h1 {
        @apply text-4xl font-bold text-gray-900 mb-6;
        background: linear-gradient(135deg, #1a1a1a 0%, #4CAF50 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    h2 {
        @apply text-2xl font-semibold text-gray-800 mb-4;
    }
    h3 {
        @apply text-xl font-medium text-gray-700 mb-3;
    }

    /* Camera input styles */
    .stCamera>div {
        @apply rounded-lg overflow-hidden border-2 border-gray-200 hover:border-green-500 transition-all duration-200;
    }

    /* Expander styles */
    .streamlit-expanderHeader {
        @apply bg-gray-50 hover:bg-gray-100 transition-all duration-200 rounded-lg;
    }

    /* Custom container styles */
    .custom-container {
        @apply bg-white rounded-xl shadow-lg p-8 border border-gray-100 mb-6;
        backdrop-filter: blur(10px);
    }

    /* Progress indicator */
    .progress-indicator {
        @apply flex items-center justify-center gap-4 mb-6;
    }
    .progress-step {
        @apply w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium;
    }
    .progress-step.active {
        @apply bg-green-500 text-white;
    }
    .progress-step.completed {
        @apply bg-green-100 text-green-700;
    }
    .progress-step.pending {
        @apply bg-gray-100 text-gray-500;
    }

    /* Custom animations */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .animate-fadeIn {
        animation: fadeIn 0.5s ease-out;
    }

    /* Responsive adjustments */
    @media (max-width: 768px) {
        .main {
            @apply px-4;
        }
        h1 {
            @apply text-3xl;
        }
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state with additional security features
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_data' not in st.session_state:
    st.session_state.user_data = {}
if 'registration_step' not in st.session_state:
    st.session_state.registration_step = 1
if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = {}
if 'last_activity' not in st.session_state:
    st.session_state.last_activity = time.time()

# Constants
USERS_DB = "users.json"
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION = 300  # 5 minutes
SESSION_TIMEOUT = 1800  # 30 minutes

def check_session_timeout():
    """Check if the session has timed out"""
    if st.session_state.authenticated:
        current_time = time.time()
        if current_time - st.session_state.last_activity > SESSION_TIMEOUT:
            st.session_state.authenticated = False
            st.session_state.user_data = {}
            return True
        st.session_state.last_activity = current_time
    return False

def load_users():
    """Load users from JSON file with error handling"""
    try:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f:
                return json.load(f)
        return {}
    except json.JSONDecodeError:
        st.error("Error loading user database. Please contact support.")
        return {}

def save_users(users):
    """Save users to JSON file with error handling"""
    try:
        with open(USERS_DB, 'w') as f:
            json.dump(users, f)
    except Exception as e:
        st.error(f"Error saving user data: {str(e)}")

def hash_password(password, salt=None):
    """Enhanced password hashing with increased iterations"""
    if salt is None:
        salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000)  # Increased iterations
    return salt + pwdhash

def verify_password(password, hash_value):
    """Secure password verification"""
    try:
        salt = hash_value[:16]
        pwdhash = hash_value[16:]
        return hmac.compare_digest(
            pwdhash,
            hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 150000)
        )
    except Exception:
        return False

def verify_face(image, stored_embedding):
    """Enhanced face verification using Gemini Vision API"""
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        stored_image = Image.open(stored_embedding)
        
        # Enhanced prompt for better accuracy
        response = model.generate_content([
            "Compare these two face images and return ONLY 'true' if they are definitely the same person, "
            "or 'false' if they appear different or if there's any uncertainty. "
            "Consider facial features, lighting, and angle. "
            "Be strict with verification to ensure security.",
            image,
            stored_image
        ])
        
        return response.text.strip().lower() == 'true'
    except Exception as e:
        st.error(f"Face verification error: {str(e)}")
        return False

def process_face_image(image):
    """Enhanced face image processing for registration"""
    try:
        model = genai.GenerativeModel('gemini-pro-vision')
        response = model.generate_content([
            "Analyze this image and return ONLY 'true' if ALL of the following conditions are met:\n"
            "1. Contains a clear, well-lit human face\n"
            "2. Face is centered and fully visible\n"
            "3. No obvious obstructions (masks, sunglasses, etc.)\n"
            "4. Good image quality\n"
            "Return 'false' if ANY condition is not met.",
            image
        ])
        return response.text.strip().lower() == 'true'
    except Exception as e:
        st.error(f"Face processing error: {str(e)}")
        return False

def check_password_strength(password):
    """Check password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    return True, "Password meets requirements"

def main():
    # Check session timeout
    if check_session_timeout():
        st.warning("Session expired. Please log in again.")
        st.rerun()

    st.title("🔒 Secure Authentication System")
    st.markdown("### Multi-Factor Authentication with Facial Recognition")

    # Sidebar with user info and security status
    with st.sidebar:
        if st.session_state.authenticated:
            st.success(f"Logged in as: {st.session_state.user_data['username']}")
            st.info(f"Session expires in: {int((SESSION_TIMEOUT - (time.time() - st.session_state.last_activity)) / 60)} minutes")
            if st.button("Logout", key="logout"):
                st.session_state.authenticated = False
                st.session_state.user_data = {}
                st.rerun()

    if not st.session_state.authenticated:
        tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            st.header("Login")
            login_username = st.text_input("Username", key="login_username")
            login_password = st.text_input("Password", type="password", key="login_password")
            
            # Check if user is locked out
            if login_username in st.session_state.login_attempts:
                attempts, lockout_time = st.session_state.login_attempts[login_username]
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    remaining_time = int(LOCKOUT_DURATION - (time.time() - lockout_time))
                    if remaining_time > 0:
                        st.error(f"Account locked. Try again in {remaining_time} seconds.")
                        st.stop()
                    else:
                        st.session_state.login_attempts[login_username] = (0, 0)

            col1, col2 = st.columns([1, 2])
            with col1:
                face_verification = st.camera_input("Verify Face")
            
            if st.button("Login", key="login"):
                users = load_users()
                if login_username in users:
                    stored_hash = bytes.fromhex(users[login_username]['password'])
                    if verify_password(login_password, stored_hash):
                        if face_verification is not None:
                            image = Image.open(face_verification)
                            if verify_face(image, users[login_username]['face_data']):
                                st.session_state.authenticated = True
                                st.session_state.user_data = {
                                    'username': login_username,
                                    'login_time': time.time()
                                }
                                if login_username in st.session_state.login_attempts:
                                    del st.session_state.login_attempts[login_username]
                                st.success("Login successful!")
                                st.rerun()
                            else:
                                st.error("Face verification failed!")
                                self._increment_login_attempts(login_username)
                        else:
                            st.error("Please provide face verification!")
                    else:
                        st.error("Invalid password!")
                        self._increment_login_attempts(login_username)
                else:
                    st.error("User not found!")
        
        with tab2:
            st.header("Register")
            if st.session_state.registration_step == 1:
                new_username = st.text_input("Choose Username")
                new_password = st.text_input("Choose Password", type="password")
                confirm_password = st.text_input("Confirm Password", type="password")
                
                # Password requirements display
                st.info("""
                Password must contain:
                - At least 8 characters
                - One uppercase letter
                - One lowercase letter
                - One number
                - One special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
                """)
                
                if st.button("Next", key="register_next"):
                    users = load_users()
                    if new_username in users:
                        st.error("Username already exists!")
                    elif new_password != confirm_password:
                        st.error("Passwords don't match!")
                    else:
                        is_strong, msg = check_password_strength(new_password)
                        if not is_strong:
                            st.error(msg)
                        else:
                            st.session_state.user_data = {
                                'username': new_username,
                                'password': hash_password(new_password).hex()
                            }
                            st.session_state.registration_step = 2
                            st.rerun()
            
            elif st.session_state.registration_step == 2:
                st.write("Please take a clear photo of your face")
                st.info("""
                Requirements for face photo:
                - Good lighting
                - Face clearly visible
                - No sunglasses or masks
                - Look directly at the camera
                """)
                
                face_image = st.camera_input("Register Face")
                
                if face_image is not None:
                    image = Image.open(face_image)
                    if process_face_image(image):
                        try:
                            face_path = f"face_{st.session_state.user_data['username']}.jpg"
                            image.save(face_path)
                            
                            users = load_users()
                            users[st.session_state.user_data['username']] = {
                                'password': st.session_state.user_data['password'],
                                'face_data': face_path,
                                'created_at': time.time()
                            }
                            save_users(users)
                            
                            st.success("Registration successful! Please login.")
                            st.session_state.registration_step = 1
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error during registration: {str(e)}")
                    else:
                        st.error("Please provide a clear face photo that meets the requirements!")
    
    else:
        st.header("Welcome to Your Secure Dashboard")
        st.markdown("""
        #### Your account is protected by:
        - Strong password hashing with 150,000 iterations
        - Facial recognition using advanced AI
        - Session management with automatic timeout
        - Account lockout after failed attempts
        - Strict password requirements
        
        This multi-factor authentication system helps prevent unauthorized access even if passwords are compromised.
        """)
        
        # Security recommendations
        with st.expander("Security Recommendations"):
            st.markdown("""
            1. Never share your password
            2. Use a unique password for this account
            3. Enable two-factor authentication on other accounts
            4. Regularly update your facial verification
            5. Log out when using shared devices
            """)

def _increment_login_attempts(username):
    """Helper method to handle login attempts"""
    if username not in st.session_state.login_attempts:
        st.session_state.login_attempts[username] = (1, time.time())
    else:
        attempts, _ = st.session_state.login_attempts[username]
        st.session_state.login_attempts[username] = (attempts + 1, time.time())

if __name__ == "__main__":
    main()
