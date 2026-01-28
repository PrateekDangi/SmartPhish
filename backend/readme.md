🛡️ PhishGuard – AI-Powered Phishing Detection System

PhishGuard is an intelligent browser-based phishing detection system that combines Machine Learning, Deep Learning, and browser security to protect users from malicious and fraudulent websites in real time. It analyzes URLs using multiple lexical, behavioral, and security-based features and predicts phishing risk instantly through a Chrome Extension connected to a Python ML backend.

This system is designed to detect both known phishing URLs and zero-day phishing attacks that traditional blacklist-based systems fail to catch.

🚀 Features

🔍 Real-time phishing detection inside the browser

🧠 Machine-learning based URL analysis

📊 Feature-level risk visualization (entropy, domain age, SSL, etc.)

⚡ Chrome Extension with live risk score

🧪 Supports GAN-generated phishing URL testing

📥 Manual URL scanning

🛑 Whitelist & Blacklist management

🌐 Backend API using Flask

🏗️ System Architecture
User Browser
     |
     | (URL)
     v
Chrome Extension (PhishGuard UI)
     |
     |  JSON Request
     v
Flask Backend (localhost:5000)
     |
     |  Feature Extraction + ML Model
     v
Phishing Risk Score + Parameters
     |
     v
Chrome Extension UI

🧠 How It Works

User opens a website or pastes a URL in the extension

The Chrome extension sends the URL to the backend

The backend extracts features such as:

URL length

Entropy

IP usage

SSL presence

Suspicious keywords

Domain structure

The trained ML model predicts phishing probability

The extension displays:

Risk score

Confidence

Visual parameter breakdown

🛠️ Tech Stack
Frontend

HTML

CSS

JavaScript

Chrome Extension API

Backend

Python

Flask

Flask-CORS

TensorFlow / Scikit-Learn

NumPy, Pandas

📁 Project Structure
PhishGuard_Project/
│
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   ├── lists.json
│   ├── venv/
│   └── model/
│        ├── snn_trained_on_real_v2.keras
│        └── scaler_trained_on_real_v2.save
│
└── frontend/
    ├── manifest.json
    ├── popup.html
    ├── popup.js
    ├── background.js
    ├── content_script.js
    └── options.html

▶️ How to Run
Step 1 — Start Backend

Open PowerShell and go to backend folder:

cd C:\Users\PRATEEK DANGI\Desktop\PhishGuard_Project\backend
venv\Scripts\activate
python app.py


Backend will start at:

http://127.0.0.1:5000

Step 2 — Load Chrome Extension

Open Chrome

Go to:

chrome://extensions/


Enable Developer Mode

Click Load Unpacked

Select the frontend folder

PhishGuard icon will appear in Chrome

🧪 Test the System

Open any website

Click the PhishGuard extension

View:

Phishing risk

Confidence

Feature analysis

Or paste a URL manually and click Check.

🧠 Model Details

PhishGuard uses a Supervised Neural Network (SNN) trained on phishing and legitimate URLs.
The model is evaluated against both real and GAN-generated phishing URLs to ensure robustness against zero-day attacks.

🎯 Use Cases

Browser security

Cyber-security research

Anti-phishing systems

Academic projects

Corporate security tools

🧑‍💻 Author

Prateek Dangi
B.Tech CSE
Cyber Security | Machine Learning | Web Security