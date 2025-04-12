import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import base64
import os

# Page config
st.set_page_config(page_title="Secure Data Storage", layout="centered")

# Initialize session state
if 'data_store' not in st.session_state:
    st.session_state.data_store = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = True
if 'fernet' not in st.session_state:
    key = base64.urlsafe_b64encode(os.urandom(32))
    st.session_state.fernet = Fernet(key)

# Hash passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(data, passkey):
    fernet = st.session_state.fernet
    return fernet.encrypt(data.encode())

# Decrypt data
def decrypt_data(encrypted_data):
    fernet = st.session_state.fernet
    try:
        return fernet.decrypt(encrypted_data).decode()
    except:
        return None

# Store data
def store_data(user_id, data, passkey):
    hashed_passkey = hash_passkey(passkey)
    encrypted_data = encrypt_data(data, passkey)
    st.session_state.data_store[user_id] = {
        "encrypted_text": encrypted_data,
        "passkey": hashed_passkey
    }

# Retrieve data
def retrieve_data(user_id, passkey):
    hashed_passkey = hash_passkey(passkey)
    if user_id in st.session_state.data_store:
        stored = st.session_state.data_store[user_id]
        if stored["passkey"] == hashed_passkey:
            decrypted = decrypt_data(stored["encrypted_text"])
            if decrypted:
                st.session_state.failed_attempts = 0
                return decrypted
        st.session_state.failed_attempts += 1
    else:
        st.session_state.failed_attempts += 1
    return None

def login_page():
    st.title("🔐 Login")
    st.write("Please authenticate to continue")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "user" and password == "pass":
            st.session_state.is_authenticated = True
            st.session_state.failed_attempts = 0
            st.success("✅ Login successful!")
        else:
            st.error("❌ Invalid credentials")

def insert_data_page():
    st.title("📥 Store Encrypted Data")
    
    user_id = st.text_input("User ID")
    data = st.text_area("Data to Store")
    passkey = st.text_input("Passkey", type="password")
    if st.button("Store"):
        if user_id and data and passkey:
            store_data(user_id, data, passkey)
            st.success("✅ Data stored successfully!")
        else:
            st.error("⚠️ All fields are required!")

def retrieve_data_page():
    st.title("📤 Retrieve Encrypted Data")
    st.write(f"🔁 Failed attempts: {st.session_state.failed_attempts}/3")
    
    user_id = st.text_input("User ID")
    passkey = st.text_input("Passkey", type="password")
    if st.button("Retrieve"):
        if user_id and passkey:
            if st.session_state.failed_attempts >= 3:
                st.session_state.is_authenticated = False
                st.error("🔒 Too many failed attempts. Please reauthenticate.")
            else:
                result = retrieve_data(user_id, passkey)
                if result:
                    st.success("✅ Data retrieved successfully!")
                    st.text_area("Decrypted Data:", value=result, height=150)
                else:
                    st.error("❌ Invalid user ID or passkey")
        else:
            st.error("⚠️ All fields are required!")

def main():
    if not st.session_state.is_authenticated:
        login_page()
    else:
        page = st.sidebar.radio("Navigation", ["Home", "Store Data", "Retrieve Data"])

        if page == "Home":
            st.title("🔐 Secure Data Storage System")
            st.write("Welcome to a secure data encryption and storage app built with Streamlit.")
            st.markdown("""
            - 🔒 Store sensitive data securely with a unique passkey  
            - 🔐 Retrieve it only by providing the correct passkey  
            - ⛔ 3 failed attempts will lock the session and require reauthentication
            """)
        elif page == "Store Data":
            insert_data_page()
        elif page == "Retrieve Data":
            retrieve_data_page()

if __name__ == "__main__":
    main()
