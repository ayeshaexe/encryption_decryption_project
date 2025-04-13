# stores & retrieves encrypted data in memory
import hashlib
import streamlit as st
from cryptography.fernet import Fernet
import base64

"username = admin"
"password = admin123"

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

def create_fernet_key(password):
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def encrypt_message(message, password):
    key = create_fernet_key(password)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted_message, password):
    try:
        key = create_fernet_key(password)
        cipher = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_message.encode())
        decrypted = cipher.decrypt(encrypted_bytes)
        return decrypted.decode()
    except:
        return None

def login_page():
    st.title("🔐 Secure Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Invalid credentials")

def main_app():
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.radio("Choose a function", ["Home 🏠","Encrypt 🔒", "Decrypt 🔓"])
    
    st.sidebar.markdown("---")
    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.rerun()
    
    if app_mode == "Home 🏠":
        st.header("🏠 Home Page")
        st.subheader("Welcome to Encryption and Decryption app")
        st.write("Securly encrypt and decrypt your secret messages!")

    elif app_mode == "Encrypt 🔒":
        st.header("🔒 Message Encryption")
        message = st.text_area("Message to encrypt")
        password = st.text_input("Encryption password", type="password")
        
        if st.button("Encrypt"):
            if message and password:
                encrypted = encrypt_message(message, password)
                st.success("Message encrypted successfully!")
                st.code(encrypted)
            else:
                st.warning("Please enter both message and password")
    
    elif app_mode == "Decrypt 🔓":
        st.header("🔓 Message Decryption")
        encrypted = st.text_area("Encrypted Passkey")
        password = st.text_input("Decryption password", type="password")
        
        if st.button("Decrypt"):
            if encrypted and password:
                decrypted = decrypt_message(encrypted, password)
                if decrypted:
                    st.success("Message decrypted successfully!")
                    st.code(decrypted)
                else:
                    st.error("Decryption failed - wrong password or invalid data")
            else:
                st.warning("Please enter both encrypted message and password")
if not st.session_state.authenticated:
    login_page()
else:
    main_app()