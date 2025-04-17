import streamlit as st
import os
import json
import hashlib
import base64
from cryptography.fernet import Fernet


st.set_page_config(page_title="Secure Data App", layout="centered")

def derive_key(pass_key, salt):
    key = hashlib.pbkdf2_hmac("sha256", pass_key.encode(), salt, 100_000)
    return base64.urlsafe_b64encode(key)

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()

def save_user(email, password):
    salt = os.urandom(16)
    hashed = hash_password(password, salt)

    user_data = {
        "email": email,
        "password": hashed,
        "salt": salt.hex()
    }

    try:
        with open("login_data.json", "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        users = []

    if any(u["email"] == email for u in users):
        return False  

    users.append(user_data)
    with open("login_data.json", "w") as f:
        json.dump(users, f, indent=4)

    return True

def check_login(email, password):
    try:
        with open("login_data.json", "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        return False

    for user in users:
        if user["email"] == email:
            salt = bytes.fromhex(user["salt"])
            hashed = hash_password(password, salt)
            return hashed == user["password"]
    return False


def register():
    st.title("📝 Register")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if len(password) < 8:
            st.error("❌ Password must be at least 8 characters long.")
        elif not email:
            st.error("❌ Please enter an email.")
        elif save_user(email, password):
            st.success("✅ Registration successful! Please go to Login.")
        else:
            st.warning("⚠️ Email already registered.")

def login():
    st.title("🔓 Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if len(email) < 8:
            st.error("Password must be 8 characters.")
        
        if check_login(email, password):
            st.session_state.logged_in = True
            st.session_state.user_email = email
            st.sidebar.success(f"You are logged in as {email}")
            st.success("✅ Login successful!")
        else:
            st.error("❌ Invalid credentials")

def encrypt_decrypt():
    st.title("🔐 Encrypt / Decrypt Data")

    menu = ["Encrypt", "Decrypt"]
    choice = st.radio("Select Option:", menu)

    if choice == "Encrypt":
        text = st.text_area("Enter data to encrypt:")
        passkey = st.text_input("Enter encryption key:", type="password")

        if st.button("Encrypt"):
            if text and passkey:
                salt = os.urandom(16)
                key = derive_key(passkey, salt)
                fernet = Fernet(key)

                encrypted = fernet.encrypt(text.encode()).decode()

                data = {
                    "text_data": encrypted,
                    "salt": salt.hex(),
                    "user": st.session_state.user_email
                }

                try:
                    with open("user_data.json", "r") as f:
                        entries = json.load(f)
                except FileNotFoundError:
                    entries = []

                entries.append(data)
                with open("user_data.json", "w") as f:
                    json.dump(entries, f, indent=4)

                st.success("✅ Data encrypted and saved.")

    if choice == "Decrypt":
        try:
            with open("user_data.json", "r") as f:
                entries = json.load(f)
        except FileNotFoundError:
            st.warning("No encrypted data found.")
            return

        user_entries = [e for e in entries if e["user"] == st.session_state.user_email]

        if not user_entries:
            st.warning("No entries found for this user.")
            return

        for i, entry in enumerate(user_entries):
            st.write(f"{i + 1}. Encrypted: `{entry['text_data'][:30]}...`")

        index = st.number_input("Enter entry number to decrypt:", min_value=1, max_value=len(user_entries))
        passkey = st.text_input("Enter encryption key:", type="password")

        if st.button("Decrypt"):
            entry = user_entries[index - 1]
            salt = bytes.fromhex(entry["salt"])
            key = derive_key(passkey, salt)
            fernet = Fernet(key)

            try:
                decrypted = fernet.decrypt(entry["text_data"].encode()).decode()
                st.success(f"🔓 Decrypted Data: {decrypted}")
            except:
                st.error("❌ Incorrect key or corrupted data.")



if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

st.sidebar.title("🔐 Secure Data App")
menu = ["Home", "Register", "Login"]
if st.session_state.logged_in:
    menu.append("Encrypt/Decrypt")
    menu.append("Logout")

choice = st.sidebar.radio("Go to:", menu)

if choice == "Home":
    st.title("🔒 Welcome to Secure Data App")
    st.markdown("""
    Welcome to the **Secure Data App**! This app allows you to **encrypt** and **decrypt** your sensitive data securely.
    
    **Get started** by registering an account, logging in, and then you can use the encryption/decryption features to protect your data.
    """)
    
    st.subheader("How to use the app")
    st.markdown("""
    1. **Register:** Create an account by providing your email and password.
    2. **Login:** Log in to access the encryption and decryption features.
    3. **Encrypt:** Enter your data and an encryption key to securely encrypt and store your data.
    4. **Decrypt:** Retrieve and decrypt your stored data with the correct key.
    """)

    st.subheader("Security Tips")
    st.markdown("""
    **🔐 Always remember:**
    - Use a **strong password** (at least 8 characters long).
    - Keep your **encryption keys safe** and never share them.
    - If you forget your password, you will need to re-register, as there is no password recovery available.
    """)

    st.subheader("Get Started")
    st.markdown("To begin, please **Register** or **Login** from the sidebar to access the app.")

    st.subheader("Features of the App")
    st.markdown("""
    - **Secure Data Storage:** Encrypt and store your sensitive data safely.
    - **Easy-to-Use Interface:** Simple, user-friendly design to help you manage your data.
    - **Multi-User Support:** Each user has their own encrypted data entries, keeping your data private.
    """)

    st.markdown("[Read our Privacy Policy](#) to understand how we handle your data securely.")
elif choice == "Register":
    register()
elif choice == "Login":
    login()
elif choice == "Encrypt/Decrypt":
    if st.session_state.logged_in:
        encrypt_decrypt()
    else:
        st.error("Please login first.")
elif choice == "Logout":
    st.session_state.logged_in = False
    st.session_state.user_email = ""
    st.success("🔒 Logged out successfully!")
