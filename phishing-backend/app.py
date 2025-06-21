from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import tldextract
import numpy as np

app = Flask(__name__)
CORS(app)
# Load model
model = joblib.load("phishing_model.pkl")

# List of feature column names (must match training data exactly)
feature_columns = [
    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
    'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
    'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
    'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
    'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
    'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
]

# Dummy feature extraction function (replace with real logic)
from urllib.parse import urlparse
import re
import tldextract
import whois
from datetime import datetime
import socket
import pandas as pd
import numpy as np

def extract_features_from_url(url):
    features = {}
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    ext = tldextract.extract(url)
    domain = ".".join(part for part in [ext.domain, ext.suffix] if part)

    # Feature 1: Using IP
    try:
        socket.inet_aton(hostname)
        features["UsingIP"] = 1
    except:
        features["UsingIP"] = -1

    # Feature 2: Long URL
    features["LongURL"] = 1 if len(url) >= 54 else -1

    # Feature 3: Short URL
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co']
    features["ShortURL"] = 1 if any(short in url for short in shorteners) else -1

    # Feature 4: Symbol @
    features["Symbol@"] = 1 if "@" in url else -1

    # Feature 5: Redirecting //
    features["Redirecting//"] = 1 if url.count('//') > 1 else -1

    # Feature 6: PrefixSuffix-
    features["PrefixSuffix-"] = 1 if '-' in hostname else -1

    # Feature 7: SubDomains
    features["SubDomains"] = 1 if hostname.count('.') > 2 else -1

    # Feature 8: HTTPS
    features["HTTPS"] = 1 if parsed.scheme == "https" else -1

    # Feature 9: DomainRegLen (domain registration length)
    try:
        w = whois.whois(domain)
        if w.expiration_date and w.creation_date:
            exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            cre = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            reg_length = (exp - cre).days if exp and cre else 0
            features["DomainRegLen"] = 1 if reg_length >= 365 else -1
        else:
            features["DomainRegLen"] = -1
    except:
        features["DomainRegLen"] = -1

    # Fill remaining features with 0
    for col in feature_columns:
        if col not in features:
            features[col] = 0

    return pd.DataFrame([features], columns=feature_columns)


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        input_url = data.get("url", "")

        # Extract features
        features_df = extract_features_from_url(input_url)

        # Predict
        prediction = model.predict(features_df)[0]

        result = "Phishing" if prediction == -1 else "Safe"
        return jsonify({"result": result})
    except Exception as e:
        print("Error:", e)
        return jsonify({"result": "Error", "message": str(e)})


if __name__ == "__main__":
    app.run(debug=True)
