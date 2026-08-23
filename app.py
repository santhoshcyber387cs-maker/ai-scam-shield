import os, sqlite3, re
from flask import Flask, render_template, request, jsonify
from pypdf import PdfReader
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

app = Flask(__name__)

# Basic dataset to train in-memory model
sample_texts = [
    "Urgent! Your account is blocked. Click here to verify KYC immediately.",
    "Dear customer, share OTP to unblock your bank account now.",
    "You won a cash prize of $1000! Claim your reward at bit.ly/scam123",
    "Please send your password and PAN card details for verification.",
    "Hello, how are you doing today?",
    "Meeting scheduled for tomorrow at 10 AM.",
    "Please find attached the report for your recent assignment.",
    "Thanks for your purchase! Your invoice is available online."
]
labels = [1, 1, 1, 1, 0, 0, 0, 0]

vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(sample_texts)
model = MultinomialNB()
model.fit(X, labels)

def init_db():
    try:
        conn = sqlite3.connect('/tmp/scam_history.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_input TEXT,
                status TEXT,
                risk_score TEXT,
                reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database Init Error: {e}")

init_db()

def extract_reasons(text):
    reasons = []
    text_lower = text.lower()
    if re.search(r'http[s]?://|www\.|bit\.ly|tinyurl', text_lower):
        reasons.append("Suspicious URL / Phishing link detected")
    if re.search(r'urgent|immediately|today|suspended|blocked', text_lower):
        reasons.append("Urgency & coercion pressure tactics used")
    if re.search(r'otp|password|kyc|pan card|bank account|upi', text_lower):
        reasons.append("Requests sensitive personal/banking information")
    return reasons if reasons else ["Potential suspicious pattern identified"]

def analyze_text(user_text):
    if not user_text or not user_text.strip():
        return {"error": "No text detected"}

    text_vectorized = vectorizer.transform([user_text])
    prediction = model.predict(text_vectorized)[0]
    probability = model.predict_proba(text_vectorized)[0][prediction] * 100
    risk_score = round(probability, 2)

    matched_reasons = extract_reasons(user_text) if prediction == 1 else ["No threat patterns identified"]

    status = "HIGH RISK SCAM" if prediction == 1 else "SAFE"
    action = "BLOCK & ALERT: Do not share OTP or click links." if prediction == 1 else "ALLOW: Content appears safe."
    speech_text = f"Warning! High Risk Scam detected with {risk_score} percent confidence." if prediction == 1 else f"Content appears Safe with {risk_score} percent confidence."

    try:
        conn = sqlite3.connect('/tmp/scam_history.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scan_history (user_input, status, risk_score, reason) VALUES (?, ?, ?, ?)",
            (user_text[:100], status, f"{risk_score}%", ", ".join(matched_reasons))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database Insert Error: {e}")

    return {
        "extracted_text": user_text,
        "status": status,
        "risk_score": f"{risk_score}%",
        "reasons": matched_reasons,
        "action": action,
        "speech_text": speech_text
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        if request.is_json:
            data = request.get_json() or {}
            return jsonify(analyze_text(data.get("text", "")))

        if 'file' in request.files:
            file = request.files['file']
            extracted_text = ""
            filename = file.filename.lower() if file.filename else ""

            if filename.endswith('.pdf'):
                pdf_reader = PdfReader(file.stream)
                for page in pdf_reader.pages:
                    extracted_text += page.extract_text() or ""
            elif filename.endswith('.txt'):
                extracted_text = file.read().decode('utf-8')

            return jsonify(analyze_text(extracted_text))

        return jsonify({"error": "Invalid request"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
