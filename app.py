from flask import Flask, render_template, request
import re
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

# -------------------------
# Trusted Domains
# -------------------------
TRUSTED_DOMAINS = [
    "google.com",
    "paypal.com",
    "amazon.com",
    "microsoft.com"
]

# -------------------------
# Suspicious Keywords
# -------------------------
SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify your account",
    "click immediately",
    "account suspended",
    "password reset",
    "limited time",
    "bank alert",
    "update payment",
    "confirm identity"
]

# -------------------------
# ML Model (Demo Dataset)
# -------------------------
texts = [
    "urgent verify your account now",
    "click immediately to avoid suspension",
    "your account has been suspended",
    "meeting scheduled tomorrow",
    "project update attached",
    "happy birthday wishes"
]

labels = [1, 1, 1, 0, 0, 0]  # 1 = phishing, 0 = safe

vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(texts)

model = LogisticRegression()
model.fit(X, labels)


# -------------------------
# Helper Functions
# -------------------------

def extract_urls(text):
    return re.findall(r'https?://[^\s]+', text)


def check_keywords(text):
    hits = []
    for word in SUSPICIOUS_KEYWORDS:
        if word in text.lower():
            hits.append(word)
    return hits


def check_url(url):
    flags = []

    # Check IP address
    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        flags.append("⚠ Uses IP address instead of domain")

    extracted = tldextract.extract(url)
    domain = extracted.domain + "." + extracted.suffix

    if domain not in TRUSTED_DOMAINS:
        flags.append("⚠ Unknown or misspelled domain")

    return flags


def calculate_risk(keyword_hits, url_flags, ml_prediction):
    score = len(keyword_hits) + len(url_flags)

    if ml_prediction == 1:
        score += 2

    if score >= 4:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    else:
        return "LOW"


# -------------------------
# Main Route
# -------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    content =" "

    if request.method == "POST":
        content = request.form.get("content","").strip()
        if not content:
           return render_template("index.html", result=None)

        # Keyword Detection
        keyword_hits = check_keywords(content)

        # URL Detection
        urls = extract_urls(content)
        url_flags = []
        for url in urls:
            url_flags.extend(check_url(url))

        vector = vectorizer.transform([content])
        prediction = model.predict(vector)[0]
        confidence = model.predict_proba(vector)[0][1]


        # ML Prediction
##        prediction = model.predict(vectorizer.transform([content]))[0]
##        confidence = model.predict_proba(vectorizer.transform([content]))[0][1]

        # Risk Calculation
        risk = calculate_risk(keyword_hits, url_flags, prediction)

        result = {
            "risk": risk,
            "keywords": keyword_hits,
            "url_flags": url_flags,
            "ml_result": "Phishing" if prediction == 1 else "Safe",
            "confidence": round(confidence * 100, 2)
        }

    return render_template("index.html", result=result,content=content)

##@app.route("/test")
##def test():
##    return render_template("index.html")@app.route("/test")
##


if __name__ == "__main__":
    app.run(debug=True, port=8000)
