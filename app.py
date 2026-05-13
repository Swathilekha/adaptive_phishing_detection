import streamlit as st
import joblib
import numpy as np
import pandas as pd
import re
import requests
import tldextract
from urllib.parse import urlparse

# ---------- Load Models ----------
model = joblib.load("phishing_model.pkl")
scaler = joblib.load("scaler.pkl")
email_model = joblib.load("phishing_email_model.pkl")
email_vectorizer = joblib.load("tfidf_vectorizer.pkl")

# ---------- Feature Names ----------
feature_names = [
    'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
    'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
    'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
    'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
    'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
    'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
]

# ---------- Feature Extraction from URL ----------
def extract_features_from_url(url):
    features = []
    reasons = []

    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)

        # Feature 1: UsingIP
        using_ip = 1 if re.match(r"(\d{1,3}\.){3}\d{1,3}", parsed.netloc) else -1
        features.append(using_ip)
        if using_ip == 1:
            reasons.append("Uses IP address instead of domain")

        # Feature 2: LongURL
        long_url = 1 if len(url) > 75 else -1
        features.append(long_url)
        if long_url == 1:
            reasons.append("Very long URL")

        # Feature 3: ShortURL
        features.append(-1 if len(url) < 20 else 1)

        # Feature 4: Symbol@
        symbol_at = 1 if "@" in url else -1
        features.append(symbol_at)
        if symbol_at == 1:
            reasons.append("Contains '@' symbol")

        # Feature 5: Redirecting//
        redirecting = 1 if "//" in url[7:] else -1
        features.append(redirecting)

        # Feature 6: PrefixSuffix-
        prefix_suffix = 1 if '-' in ext.domain else -1
        features.append(prefix_suffix)
        if prefix_suffix == 1:
            reasons.append("Domain name has '-' symbol")

        # Feature 7: SubDomains
        subdomains = 1 if url.count('.') > 3 else -1
        features.append(subdomains)
        if subdomains == 1:
            reasons.append("Too many subdomains")

        # Feature 8: HTTPS
        https = 1 if parsed.scheme == 'https' else -1
        features.append(https)
        if https == -1:
            reasons.append("Does not use HTTPS")

        # Feature 9: DomainRegLen
        features.append(1 if len(ext.domain) > 5 else -1)

        # Feature 10: Favicon
        features.append(1 if "favicon" in url.lower() else -1)

        # Feature 11: NonStdPort
        features.append(1 if parsed.port not in [80, 443, None] else -1)

        # Feature 12: HTTPSDomainURL
        features.append(1 if parsed.netloc in url else -1)

        # Try request content
        try:
            response = requests.get(url, timeout=5)
            content = response.text.lower()
        except:
            content = ""

        # Features from content
        features.append(1 if "src=" in content else -1)  # RequestURL
        features.append(1 if "href=" in content else -1)  # AnchorURL
        features.append(-1 if "<script>" in content else 1)  # LinksInScriptTags
        features.append(-1 if "mailto:" in content else 1)  # ServerFormHandler
        features.append(1 if "@" in content else -1)  # InfoEmail
        features.append(1 if "about:blank" in content else -1)  # AbnormalURL
        features.append(1 if "forward" in content else -1)  # WebsiteForwarding
        features.append(1 if "statusbar" in content else -1)  # StatusBarCust
        features.append(-1 if "right click" in content else 1)  # DisableRightClick
        features.append(1 if "popup" in content else -1)  # UsingPopupWindow
        features.append(1 if "<iframe" in content else -1)  # IframeRedirection

        # Dummy/filler features
        features.append(1)   # AgeofDomain
        features.append(1)   # DNSRecording
        features.append(-1)  # WebsiteTraffic
        features.append(-1)  # PageRank
        features.append(1 if "google" in content else -1)  # GoogleIndex
        features.append(1 if "http" in content else -1)  # LinksPointingToPage
        features.append(0)  # StatsReport

    except:
        features = [-1] * 30
        reasons.append("Error while processing URL")

    return features, reasons

# ---------- Streamlit UI ----------
st.set_page_config(page_title="Phishing Detector", page_icon="🛡️")
st.title("🛡️ Phishing & Spam Detection System")

option = st.selectbox("Choose input method:", ["Enter URL", "Manual Feature Input", "Email Message Input"])

if option == "Enter URL":
    url = st.text_input("Enter the website URL")
    if st.button("Check URL"):
        if url:
            features, reasons = extract_features_from_url(url)
            input_df = pd.DataFrame([features], columns=feature_names)
            scaled_input = scaler.transform(input_df)
            prediction = model.predict(scaled_input)[0]

            st.write("🧠 Raw Prediction Output:", prediction)
            if prediction == -1:
                st.error("🚨 This website is Phishing!")
                if reasons:
                    st.markdown("#### 🚩 Suspicious Characteristics:")
                    for r in reasons:
                        st.markdown(f"- {r}")
            else:
                st.success("✅ This website is Legitimate.")
        else:
            st.warning("Please enter a URL.")

elif option == "Manual Feature Input":
    st.subheader("🔧 Manual Feature Input")
    user_input = []
    for feature in feature_names:
        value = st.selectbox(f"{feature}:", [-1, 0, 1], key=feature)
        user_input.append(value)

    if st.button("Predict"):
        input_df = pd.DataFrame([user_input], columns=feature_names)
        scaled_input = scaler.transform(input_df)
        prediction = model.predict(scaled_input)[0]

        st.write("🧠 Raw Prediction Output:", prediction)
        if prediction == -1:
            st.error("🚨 This website is Phishing!")
        else:
            st.success("✅ This website is Legitimate.")

elif option == "Email Message Input":
    st.subheader("📧 Email Spam/Phishing Detection")
    email_text = st.text_area("Paste the email message here")

    if st.button("Analyze Email"):
        if email_text.strip():
            email_features = email_vectorizer.transform([email_text])
            prediction = email_model.predict(email_features)[0]

            st.write("🧠 Raw Prediction Output:", prediction)
            if prediction == 1:
                st.error("🚨 This email is likely Spam/Phishing!")
            else:
                st.success("✅ This email appears to be Legitimate.")
        else:
            st.warning("Please paste an email message.")
