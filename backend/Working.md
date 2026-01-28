## 🏗️ System Architecture
```
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
```

---

## 🧠 How It Works

1. User opens a website or pastes a URL in the extension  
2. Chrome extension sends the URL to the backend  
3. Backend extracts features such as:
   - URL length  
   - Entropy  
   - IP usage  
   - SSL presence  
   - Suspicious keywords  
   - Domain structure  
4. Trained ML model predicts phishing probability  
5. Extension displays:
   - Risk score  
   - Confidence  
   - Visual parameter breakdown  

---

## 🛠️ Tech Stack

### Frontend
- HTML  
- CSS  
- JavaScript  
- Chrome Extension API  

### Backend
- Python  
- Flask  
- Flask-CORS  
- TensorFlow / Scikit-Learn  
- NumPy, Pandas  

---

## ▶️ How To Run

### Step 1 — Start Backend

Open PowerShell and navigate to backend folder:

```bash
cd C:\Users\PRATEEK DANGI\Desktop\PhishGuard_Project\backend
venv\Scripts\activate
python app.py
```

Backend will start at:

```
http://127.0.0.1:5000
```

### Step 2 — Load Chrome Extension
1. Open Chrome
2. Go to:
```
chrome://extensions/
```
3. Enable Developer Mode
4. Click Load Unpacked
5. Select the frontend folder

PhishGuard icon will appear in Chrome toolbar.

---

## 🧪 Test The System

1. Open any website
2. Click the PhishGuard extension
3. View:
     - Phishing risk
     - Confidence score
     - Feature analysis
OR

Paste a URL manually and click Check.

---

## 🧠 Model Details

#### PhishGuard uses a Supervised Neural Network (SNN) trained on phishing and legitimate URLs.

#### The model is evaluated against both:
     - Real phishing URLs
     - GAN-generated phishing URLs

This ensures robustness against zero-day phishing attacks.


