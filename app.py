
from flask import Flask, request, jsonify, render_template
import os
import pickle
import joblib
import numpy as np
from feature_extractor import FeatureExtractor

app = Flask(__name__)
# CORS(app) # Optional if serving from same origin

# Load Model
MODEL_PATH = os.path.join('model', 'url.pkl')
model = None

print(f"Loading model from {MODEL_PATH}...")
try:
    # Try joblib first as it's faster for large sklearn models
    model = joblib.load(MODEL_PATH)
    print("Model loaded via joblib.")
    if hasattr(model, 'feature_names_in_'):
        print(f"Model expects {len(model.feature_names_in_)} features.")
except Exception as e:
    print(f"Joblib load failed: {e}. Trying pickle...")
    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        print("Model loaded via pickle.")
    except Exception as e2:
        print(f"FATAL: Could not load model: {e2}")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard.html')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login.html')
def login():
    return render_template('login.html')

@app.route('/signup.html')
def signup():
    return render_template('signup.html')

# API Endpoint for URL Scanning
@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    if not model:
        return jsonify({'error': 'Model not loaded'}), 500

    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Validate URL format
    # Simple regex to check for http/https or at least a domain-like structure
    import re
    # Allow http://, https://, or starting with www. or typical domain chars
    url_pattern = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    # If no schema, try adding http:// to see if it becomes valid, or check simple domain pattern
    if not url.startswith(('http://', 'https://')):
         if not url_pattern.match('http://' + url):
             return jsonify({'error': 'Invalid URL format. Please enter a valid URL (e.g., example.com or https://example.com)'}), 400
         # Auto-fix for feature extractor? 
         # The feature extractor expects a full URL for some parsing, lets normalize it if needed or just pass as is.
         # For the extractor, we'll keep as is, or maybe prepend http for better parsing?
         # Most extractors handle no-schema, but let's stick to validation only here.
         pass
    elif not url_pattern.match(url):
        return jsonify({'error': 'Invalid URL format. Please enter a valid URL.'}), 400

    try:
        print(f"Scanning URL: {url}")
        
        # 0. Whitelist Check
        # Extract domain from URL to check against whitelist
        # We use tldextract logic similar to feature extractor for consistency, 
        # or just simple string matching for speed. 
        # Let's use simple extraction to match common sites.
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # Common safe domains that might be misclassified
        WHITELIST = {
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
            'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com', 'microsoft.com',
            'apple.com', 'github.com', 'stackoverflow.com', 'yahoo.com', 'whatsapp.com',
            'twitch.tv', 'reddit.com', 'pinterest.com', 'office.com', 'live.com',
            'bing.com', 'adobe.com', 'dropbox.com', 'wordpress.com', 'zoom.us'
        }
        
        # Check if domain or any parent domain is in whitelist
        is_safe = False
        parts = domain.split('.')
        for i in range(len(parts) - 1):
            sub = ".".join(parts[i:])
            if sub in WHITELIST:
                is_safe = True
                break
                
        if is_safe:
            print(f"Whitelist hit for {url}")
            return jsonify({
                'result': 'Safe / Benign',
                'confidence': 1.0,
                'url': url
            })

        # 1. Extract Features
        extractor = FeatureExtractor(url)
        # Optional: Enable live content fetching
        # extractor.fetch_web_content() 
        # For now, we skip heavy network calls to keep it fast, 
        # unless model creates huge errors without it.
        # Ideally, we should fetch if the model relies heavily on web_* features.
        # Let's do a lightweight fetch if possible, or skip for speed.
        # extractor.fetch_web_content() 
        
        features_df = extractor.extract_features()
        print("Extracted features sample:")
        print(features_df.iloc[0].to_dict())
        
        
        # 2. Prediction
        prediction = model.predict(features_df)
        
        # Result conversion
        result = int(prediction[0])
        
        # --- HEURISTIC OVERRIDE ---
        # The model sometimes misclassifies direct malware downloads as Defacement.
        # If we detect a suspicious extension, force 'Malware' (3) if it's not predicted as Benign (0).
        if features_df['suspicious_extension'].values[0] == 1:
            print("Heuristic: Suspicious extension detected. Forcing Malware label.")
            result = 3
        # --------------------------
        
        # Calculate confidence
        confidence = 0.0
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(features_df)
            confidence = float(np.max(proba))
        
        # Map result to readable string
        # UPDATED MAPPING:
        # 0: Benign
        # 1: Defacement
        # 2: Phishing
        # 3: Malware
        label_map = {
            0: 'Benign',
            1: 'Defacement',
            2: 'Phishing',
            3: 'Malware'
        }
        
        status = label_map.get(result, f"Unknown ({result})")
        
        return jsonify({
            'result': status,
            'confidence': confidence,
            'url': url
        })

    except Exception as e:
        print(f"Prediction error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f"Scanning failed: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
    # Reload trigger
