from flask import Flask, render_template, request
import pickle
import os
import requests

from feature_extraction import extract_features_with_reason

app = Flask(__name__)

# Load model
with open("model/model.pkl", "rb") as f:
    model = pickle.load(f)

API_KEY = os.getenv("GOOGLE_API_KEY")


def check_google_safe_browsing(url):
    if not API_KEY:
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = requests.post(endpoint, json=payload, timeout=3)
        if r.status_code != 200:
            return False
        data = r.json()
        return "matches" in data and len(data.get("matches", [])) > 0
    except requests.exceptions.RequestException:
        return False


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    score = None
    reasons = []
    url = None
    confidence = None
    api_result = None
    is_blacklisted = False

    if request.method == "POST":
        url = request.form["url"].strip()

        # Features
        features, score, reasons = extract_features_with_reason(url)

        # ML
        prediction = model.predict([features])[0]
        prob = model.predict_proba([features])[0]
        confidence = max(round((max(prob) * 100) - 5, 2), 60)

        # API
        is_blacklisted = check_google_safe_browsing(url)
        if is_blacklisted:
            api_result = "🚨 Confirmed dangerous (Google Safe Browsing)"
        else:
            api_result = "⚠️ Not on Google blacklist (AI detected risk)"

        # FINAL HYBRID DECISION
        if is_blacklisted:
            result = "🚨 Phishing Website (Blacklisted)"
            confidence = 99.9
        else:
            if prediction == 1 and score >= 40:
                result = "🚨 Phishing Website"
            elif prediction == 1 or score >= 30:
                result = "⚠️ Suspicious Website"
            else:
                result = "✅ Legitimate Website"

    return render_template(
        "index.html",
        result=result,
        score=score,
        reasons=reasons,
        url=url,
        confidence=confidence,
        api_result=api_result,
        is_blacklisted=is_blacklisted
    )


if __name__ == "__main__":
    app.run(debug=True)