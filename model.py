import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

corpus = [
    "Your SBI bank account is blocked. Click here to update KYC immediately",
    "Dear customer, your PAN card is expired. Click link to avoid account suspension",
    "URGENT: Your HDFC netbanking access is restricted. Verify identity now",
    "Your UPI transaction failed. Click link to refund your amount immediately",
    "Electricity bill unpaid. Power cut tonight at 9 PM. Contact officer immediately",
    "Congratulations! You are selected for high paying online job. Earn 5000 daily",
    "URGENT: You won Rs 25,00,000 in KBC Lucky Draw. Send OTP to claim prize now",
    "Dear customer, your UPI transaction of Rs 5000 is successful",
    "Your Amazon order has been dispatched and will be delivered by tomorrow",
    "Your OTP for login is 482910. Do not share it with anyone"
]

labels = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0]

vectorizer = TfidfVectorizer(stop_words='english', ngram_range=(1, 2))
X = vectorizer.fit_transform(corpus)

model = MultinomialNB()
model.fit(X, labels)

with open('vectorizer.pkl', 'wb') as f:
    pickle.dump(vectorizer, f)

with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("ML Model and Vectorizer trained and saved successfully.")
