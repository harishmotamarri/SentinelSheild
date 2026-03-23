import os
import re
import json
import pickle
import joblib
import numpy as np
import traceback
from urllib.parse import urlparse
from services.feature_extractor import FeatureExtractor

class UrlService:
    def __init__(self, model_path, api_key=None):
        self.model_path = model_path
        self.api_key = api_key
        self.model = None
        self._load_model()
        
        if self.api_key:
            from groq import Groq
            try:
                self.client = Groq(api_key=self.api_key)
            except Exception as e:
                print(f"Failed to initialize Groq client for UrlService: {e}")
                self.client = None
        else:
            self.client = None
        
        # Common safe domains whitelist
        self.WHITELIST = {
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
            'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com', 'microsoft.com',
            'apple.com', 'github.com', 'stackoverflow.com', 'yahoo.com', 'whatsapp.com',
            'twitch.tv', 'reddit.com', 'pinterest.com', 'office.com', 'live.com',
            'bing.com', 'adobe.com', 'dropbox.com', 'wordpress.com', 'zoom.us'
        }
        
        # Regex for URL validation
        self.url_pattern = re.compile(
            r'^(?:http|ftp)s?://' 
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' 
            r'localhost|' 
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' 
            r'(?::\d+)?' 
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    def _load_model(self):
        print(f"Loading URL model from {self.model_path}...")
        try:
            # Try joblib first
            self.model = joblib.load(self.model_path)
            print("URL Model loaded via joblib.")
        except Exception as e:
            print(f"Joblib load failed: {e}. Trying pickle...")
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print("URL Model loaded via pickle.")
            except Exception as e2:
                print(f"FATAL: Could not load URL model: {e2}")
                self.model = None

    def validate_url(self, url):
        """Checks if URL is valid and returns normalized URL or raises ValueError."""
        if not url:
            raise ValueError("No URL provided")
            
        # Add scheme if missing for validation
        check_url = url
        if not url.startswith(('http://', 'https://')):
             check_url = 'http://' + url
             
        if not self.url_pattern.match(check_url):
            raise ValueError("Invalid URL format")
            
        return check_url if url.startswith(('http://', 'https://')) else 'http://' + url

    def scan_url(self, url):
        """Main method to scan a URL using whitelist + ML model."""
        if not self.model:
            return {'error': 'URL Model not loaded', 'status': 500}

        try:
            # 1. Validation
            valid_url = self.validate_url(url)
            
            # 2. Whitelist Check
            parsed = urlparse(valid_url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
                
            is_safe = False
            parts = domain.split('.')
            for i in range(len(parts) - 1):
                sub = ".".join(parts[i:])
                if sub in self.WHITELIST:
                    is_safe = True
                    break
                    
            if is_safe:
                return {
                    'result': 'Safe / Benign',
                    'confidence': 1.0,
                    'url': valid_url
                }

            # 3. Feature Extraction
            extractor = FeatureExtractor(valid_url)
            features_df = extractor.extract_features()
            
            # 4. Prediction
            prediction = self.model.predict(features_df)
            result = int(prediction[0])
            
            # --- HEURISTIC OVERRIDE ---
            if features_df['suspicious_extension'].values[0] == 1:
                result = 3 # Malware
            # --------------------------
            
            confidence = 0.0
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(features_df)
                confidence = float(np.max(proba))
            
            label_map = {
                0: 'Benign',
                1: 'Defacement',
                2: 'Phishing',
                3: 'Malware'
            }
            
            status = label_map.get(result, f"Unknown ({result})")
            reason = ""

            # --- GROQ ENHANCEMENT ---
            if self.client:
                print(f"Requesting Groq AI Analysis for URL: {valid_url}")
                try:
                    prompt = f"""You are a cybersecurity expert.
Analyze this URL for potential security threats: {valid_url}
The local ML model classified it as: {status} (Confidence: {confidence:.2f})

Indicators from feature extraction:
- Suspicious extension: {'Yes' if features_df['suspicious_extension'].values[0] == 1 else 'No'}
- Digits in domain: {features_df['count_digits_domain'].values[0]}
- Special chars in URL: {features_df['count_special_char'].values[0]}

Return a valid JSON response with one key:
1. "reason": A short 1-2 sentence expert explanation for why this URL is {status} or if there's any other risk.

JSON ONLY."""
                    
                    response = self.client.chat.completions.create(
                        messages=[{"role": "user", "content": prompt}],
                        model="llama-3.1-8b-instant",
                        temperature=0.1,
                        max_completion_tokens=150,
                    )
                    content = response.choices[0].message.content.strip().replace('```json', '').replace('```', '').strip()
                    ai_result = json.loads(content)
                    reason = ai_result.get('reason', '')
                except Exception as e:
                    print(f"Groq URL Analysis failed: {e}")
                    reason = f"Automated analysis classified this as {status.lower()}."
            # --------------------------
            
            return {
                'result': status,
                'confidence': confidence,
                'url': valid_url,
                'reason': reason
            }

        except ValueError as ve:
            return {'error': str(ve), 'status': 400}
        except Exception as e:
            print(f"URL Scan Error: {e}")
            traceback.print_exc()
            return {'error': f"Scanning failed: {str(e)}", 'status': 500}
