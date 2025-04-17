import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key for Fernet (in real-world, store securely)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
stored_data = {}  # Format: {"user1_data": {"encrypted_text": "...", "passkey": "hashed"}}
failed_attempts = 0  # Global tracker for failed attempts

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed = hash_passkey(passkey)

    for _, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed:
            failed_attempts = 0  # reset on success
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

# UI Starts
st.set_page_config(page_title="Secure Data App", layout="centered")
st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigation", menu)

# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("This app securely **stores** and **retrieves** data using encryption and passkeys.")

# Store Data Page
elif choice == "Store Data":
    st.subheader("📥 Store Your Secret")
    user_data = st.text_area("🔏 Enter Text to Encrypt")
    passkey = st.text_input("🔑 Enter Passkey", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠️ Please fill both fields.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("🔐 Retrieve Your Secret")
    encrypted_input = st.text_area("Paste Encrypted Text")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            decrypted = decrypt_data(encrypted_input, passkey)

            if decrypted:
                st.success("✅ Decryption Successful!")
                st.text_area("Your Decrypted Data", decrypted, height=100)
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts. Redirecting to Login Page...")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Both fields required.")

# Login Page
elif choice == "Login":
    st.subheader("🔐 Reauthorization Required")
    master_key = st.text_input("Enter Admin Password", type="password")

    if st.button("Login"):
        if master_key == "admin123":  # Replace with secure auth in real use
            failed_attempts = 0
            st.success("✅ Reauthorized! Redirecting...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect admin password.")

