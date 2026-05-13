# extract_features.py

import tldextract
from urllib.parse import urlparse
import re

def extract_features_from_url(url):
    # Simplified version of feature extraction — you should enhance this with real rules
    features = []

    # Feature 1: UsingIP
    using_ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', urlparse(url).netloc) else -1
    features.append(using_ip)

    # Feature 2: LongURL
    features.append(1 if len(url) >= 75 else -1)

    # Feature 3: ShortURL
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl']
    features.append(1 if any(s in url for s in shorteners) else -1)

    # Add dummy -1 for remaining features for now (you can replace these with real logic)
    while len(features) < 30:
        features.append(-1)

    return features
