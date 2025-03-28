import os
import json
import hashlib
import hmac

# Constants
USERS_DB = "users.json"

def load_users():
    """Load users from JSON database file"""
    try:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f:
                return json.load(f)
        return {}
    except json.JSONDecodeError:
        # If the file is corrupted, return an empty dictionary
        return {}
    except Exception as e:
        # Log the error (in a real application)
        print(f"Error loading users: {e}")
        return {}

def save_users(users):
    """Save users to JSON database file"""
    try:
        with open(USERS_DB, 'w') as f:
            json.dump(users, f, indent=4)
        return True
    except Exception as e:
        # Log the error (in a real application)
        print(f"Error saving users: {e}")
        return False

def hash_password(password):
    """
    Hash a password using PBKDF2 with SHA-256 and a random salt
    Returns the salt + hash as bytes
    """
    salt = os.urandom(16)  # 16 bytes for the salt
    iterations = 150000    # Number of iterations - high enough for security
    
    # Generate the hash using PBKDF2
    hashed = hashlib.pbkdf2_hmac(
        'sha256',          # Hash algorithm
        password.encode(), # Convert password to bytes
        salt,              # Salt
        iterations         # Iterations
    )
    
    # Return salt + hashed password
    return salt + hashed

def verify_password(password, stored_hash):
    """
    Verify a password against its stored hash
    stored_hash should be bytes in the format: salt (16 bytes) + hash
    """
    # Extract salt and hashed password
    salt, hashed = stored_hash[:16], stored_hash[16:]
    
    # Generate hash from the provided password using the same salt
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        150000
    )
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(hashed, password_hash)
