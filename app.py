import os, pickle, sqlite3, re
from flask import Flask, render_template, request, jsonify
from PIL import Image
import easyocr
from pypdf import PdfReader

app = Flask(__name__)
reader = easyocr.Reader(['en'])

def init_db():
    conn = sqlite3.connect('scam_history.db')
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

init_db()

with open('vectorizer.pkl', 'rb') as f:
    vectorizer = pickle.load(f)
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

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
    if not user_text.strip():
        return {"error": "No text detected"}

    text_vectorized = vectorizer.transform([user_text])
    prediction = model.predict(text_vectorized)[0]
    probability = model.predict_proba(text_vectorized)[0][prediction] * 100
    risk_score = round(probability, 2)

    matched_reasons = extract_reasons(user_text) if prediction == 1 else ["No threat patterns identified"]

    status = "HIGH RISK SCAM" if prediction == 1 else "SAFE"
    action = "BLOCK & ALERT: Do not share OTP or click links." if prediction == 1 else "ALLOW: Content appears safe."
    speech_text = f"Warning! High Risk Scam detected with {risk_score} percent confidence." if prediction == 1 else f"Content appears Safe with {risk_score} percent confidence."

    conn = sqlite3.connect('scam_history.db')
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (user_input, status, risk_score, reason) VALUES (?, ?, ?, ?)",
        (user_text[:100], status, f"{risk_score}%", ", ".join(matched_reasons))
    )
    conn.commit()
    conn.close()

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
    if request.is_json:
        return jsonify(analyze_text(request.get_json().get("text", "")))

    if 'file' in request.files:
        file = request.files['file']
        extracted_text = ""
        filename = file.filename.lower()

        if filename.endswith(('.png', '.jpg', '.jpeg', '.webp')):
            image = Image.open(file.stream)
            image.save("temp_img.png")
            results = reader.readtext("temp_img.png", detail=0)
            extracted_text = " ".join(results)
            if os.path.exists("temp_img.png"): os.remove("temp_img.png")
        elif filename.endswith('.pdf'):
            pdf_reader = PdfReader(file.stream)
            for page in pdf_reader.pages:
                extracted_text += page.extract_text() or ""
        elif filename.endswith('.txt'):
            extracted_text = file.read().decode('utf-8')

        return jsonify(analyze_text(extracted_text))

    return jsonify({"error": "Invalid request"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
