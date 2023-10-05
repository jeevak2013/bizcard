import streamlit as st
from PIL import Image, ImageEnhance
from passlib.hash import bcrypt
import sqlite3
import pytesseract
import numpy as np
import re

# create db for user management
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# user table for credentials
cursor.execute('''
            CREATE TABLE IF NOT EXISTS users(
               id INTEGER PRIMARY KEY,
               username TEXT UNIQUE NOT NULL,
               password TEXT NOT NULL
            )''')
conn.commit()

cursor.execute('''
            CREATE TABLE IF NOT EXISTS business_cards (
               id INTEGER PRIMARY KEY,
               company_name TEXT,
               cardholder_name TEXT,
               designation TEXT,
               mobile_number TEXT,
               email_address TEXT,
               website_url TEXT,
               area TEXT,
               city TEXT,
               state TEXT,
               pincode TEXT,
               image BLOB
            )''')
conn.commit()

# Helper function to create new user
def create_user(username, password):
    hashed_password = bcrypt.hash(password)
    cursor.execute('''INSERT OR IGNORE INTO users (username, password) 
                    VALUES (?, ?)''', 
                   (username, hashed_password))
    conn.commit()

# Helper function to retrieve user by username
def get_user(username):
    cursor.execute("SELECT * FROM users WHERE username=?",
                   (username,))   
    return cursor.fetchone()

# Hepler function to check if user is loggedin
def is_authenticated(session_state):
    return session_state.is_authenticated    

def enhance_image(image):
    """
    Apply image enhancement techniques to improve OCR accuracy
    """
    # resize image to reduce processing time and enhance accuracy
    image = image.resize((600, 400))

    # Apply contrast enhancement
    enhancer = ImageEnhance.Contrast(image)
    image = enhancer.enhance(2.0)   # Increase contrast (adjust as needed)

    return image

def exctract_information(enhanced_image):
    """
    Extract information from processed image
    """
    # convert image to greyscale
    greyscale_image = image.convert('L')

    text = pytesseract.image_to_string(greyscale_image)

    return text

def extract_fields(extracted_text):
    fields = {
        "Company Name" : "",
        "Cardholder Name" : "",
        "Designation" : "",
        "Email Address" : "",
        "Website URL" : "",
        "Area" : "",
        "City" : "",
        "State" : "",
        "Pincode" : "",
    }

    # define regular expression for email and URL 
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
    url_pattern = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

    # Iterate through OCR results and extract relevant fields
    for text in extracted_text.split('\n'):
        text = text.strip()

        if re.match(email_pattern, text):
            fields["Email Address"] = text
        else:
            # Attempt to identify and extract website URLs
            urls = re.findall(url_pattern, text)
            for url, _ in urls:
                if url.startswith("www."):
                    fields["Website URL"] = url[0]
        
        if "Mobile" in text:
            fields["Mobile Number"] = re.sub(r"[^0-9+]", "", text)
        elif "Company" in text:
            fields["Company Name"] = text
        elif "Name" in text:
            fields["Cardholder Name"] = text
        elif "Designation" in text:
            fields["Designation"] = text
        elif "Area" in text:
            fields["Area"] = text
        elif "City" in text:
            fields["City"] = text
        elif "State" in text:
            fields["State"] = text
        elif re.match(r"^\d{6}$", text):
            fields["Pin Code"] = text

    return fields


def save_data(extracted_data, uploaded_image):
    """
    Save extracted data and uploaded image to sqlite db
    """
    name = extracted_data["Company Name"]
    phone = extracted_data["Mobile Number"]
    email = extracted_data["Email Address"]
    website_url = extracted_data["Website URL"]
    area = extracted_data["Area"]
    city = extracted_data["City"]
    state = extracted_data["State"]
    pincode = extracted_data["Pincode"]

    # Convert image to bytes for storage in db
    img_bytes = uploaded_image.read()

    # Insert data into db
    cursor.execute('''
                INSERT INTO business_cards (
                    company_name, cardholder_name, designation,
                    mobile_number, email_address, website_url,
                    area, city, state, pincode, image)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (name, None, None, phone, email, website_url, area, city, state, pincode, img_bytes))
    conn.commit()
    st.success("Data Saved successfully")

def main():
    # set page title and header
    st.title("Business Card Information Extractor")
    st.header("Upload a business card image to extract information")

    # session state to store user authentication status
    class SessionState:
        def __init__(self):
            self.is_authenticated = False

    # initialise session state
    session_state = SessionState()

    # user authentication
    st.sidebar.subheader("User Authentication")
    username = st.sidebar.text_input("Username")        
    password = st.sidebar.text_input("Password", type="password")

    if st.sidebar.button("Sign UP"):
        if username and password:
            create_user(username, password)
            st.sidebar.success("Account created successfully!")

    if st.sidebar.button("Login"):
        user = get_user(username)
        if user and bcrypt.verify(password, user[2]):
            session_state.is_authenticated = True
            st.sidebar.success("Login successful!")
        else:
            st.sidebar.error("Login failed. Please check your credentials.")

    # streamlit content
    if is_authenticated(session_state):
        uploaded_image = st.file_uploader("Upload a business card image", type = ["jpg","png","jpeg"])

        if uploaded_image:
            # display image
            st.image(uploaded_image, caption="Uploaded Image", use_column_width=True)

            # create button for information extraction
            if st.button("Extract Information"):
                image = Image.open(uploaded_image)

                # image processing(resize & enhancement)
                image = enhance_image(image)

                # Extract information using easyocr
                extracted_text = exctract_information(image)

                # split the extracted text into lines for display
                extracted_fields  = extract_fields(extracted_text.split('\n'))

                # Display extracted information
                st.subheader("Extracted Information:")
                # create table to display extracted information
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("### Field")
                    for field, value in extracted_fields.items():
                        st.write(f"{field}")

                with col2:
                    st.markdown("### Value")
                    for field, value in extracted_fields.items():
                        st.write(f"{value}")

                if st.button("save Data"):
                    save_data(extracted_fields, uploaded_image)
                '''
                if st.button("Delete Data"):
                    delete_data()'''
    else:
        st.write("You need to login to use this application")    

if __name__ == "__main__":
    st.title("Business Card Information Extractor")
    st.header("Upload a business card image to extract information")

    # session state to store user authentication status
    class SessionState:
        def __init__(self):
            self.is_authenticated = False

    # initialise session state
    session_state = SessionState()

    # user authentication
    st.sidebar.subheader("User Authentication")
    username = st.sidebar.text_input("Username")        
    password = st.sidebar.text_input("Password", type="password")

    if st.sidebar.button("Sign UP"):
        if username and password:
            create_user(username, password)
            st.sidebar.success("Account created successfully!")

    if st.sidebar.button("Login"):
        user = get_user(username)
        if user and bcrypt.verify(password, user[2]):
            session_state.is_authenticated = True
            st.sidebar.success("Login successful!")
        else:
            st.sidebar.error("Login failed. Please check your credentials.")
    
    uploaded_image = st.file_uploader("Upload a business card image")
    extract_button = st.button("Extract Information")
    store_info = st.button("Store Information")
    # streamlit content
    if is_authenticated(session_state):
        uploaded_image

    if uploaded_image:
        # display image
        st.image(uploaded_image, caption="Uploaded Image", use_column_width=True)
    
    extracted_fields =None

    if extract_button:
        with st.spinner("Processing..."):
            image = Image.open(uploaded_image)

            # image processing(resize & enhancement)
            enhanced_image = enhance_image(image)

            # Extract information using easyocr
            extracted_text = exctract_information(enhanced_image)

        st.write("Extracted Text (Verify and Edit):")
        st.write(extracted_text)
        st.write("Verify values from extracted text")

        fields = extract_fields(extracted_text)
        for k,v in fields.items():
            print(k,v)
        