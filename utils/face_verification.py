import os
import streamlit as st
import google.generativeai as genai

def get_gemini_model():
    """Initialize and return the Gemini Pro Vision model"""
    API_KEY = os.getenv('GEMINI_API_KEY')
    
    if not API_KEY:
        st.error("⚠️ GEMINI_API_KEY not found in environment variables!")
        return None
        
    try:
        genai.configure(api_key=API_KEY)
        return genai.GenerativeModel(name="gemini-pro-vision")
    except Exception as e:
        st.error(f"❌ Error initializing AI model: {e}")
        return None

def verify_face(image_path, stored_image_path):
    """
    Verify if two face images match using Google's Gemini Pro Vision API
    
    Args:
        image_path (str): Path to the current user's face image
        stored_image_path (str): Path to the stored face image for comparison
        
    Returns:
        bool: True if faces match, False otherwise
    """
    # Check if files exist
    if not os.path.exists(image_path):
        st.error(f"⚠️ Current user image not found: {image_path}")
        return False
        
    if not os.path.exists(stored_image_path):
        st.error(f"⚠️ Stored user image not found: {stored_image_path}")
        return False
        
    # Initialize Gemini model
    model = get_gemini_model()
    if model is None:
        return False

    try:
        # Read both images
        with open(image_path, "rb") as img1, open(stored_image_path, "rb") as img2:
            img1_data = img1.read()
            img2_data = img2.read()
            
        # Create a detailed prompt for the model
        prompt = """
        Compare these two facial images and determine if they are of the same person.
        Focus on facial structure, features, and characteristics that persist despite changes in expression or lighting.
        If they are the same person, respond ONLY with "true".
        If they are different people, respond ONLY with "false".
        """
        
        # Generate content with the model
        response = model.generate_content(
            [prompt, img1_data, img2_data],
            generation_config={
                "temperature": 0,
                "top_p": 0.5,
                "top_k": 32,
                "max_output_tokens": 100,
            }
        )
        
        # Process the response
        result_text = response.text.strip().lower()
        return "true" in result_text
        
    except Exception as e:
        st.error(f"⚠️ Face verification error: {e}")
        return False
