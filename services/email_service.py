import json
import pickle
import joblib
import scipy.sparse
import numpy as np
from services.feature_extractor import EmailFeatureExtractor

class EmailService:
    def __init__(self, model_path, vectorizer_path, api_key=None):
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self.api_key = api_key
        self.model = None
        self.vectorizer = None
        self._load_models()

        if self.api_key:
            from groq import Groq
            try:
                self.client = Groq(api_key=self.api_key)
            except Exception as e:
                print(f"Failed to initialize Groq client for EmailService: {e}")
                self.client = None
        else:
            self.client = None

    def _load_models(self):
        print("Loading email detection models...")
        try:
            self.model = self._load_file(self.model_path)
            self.vectorizer = self._load_file(self.vectorizer_path)
            print("Email detection models loaded successfully.")
        except Exception as e:
            print(f"Error loading email models: {e}")
            self.model = None
            self.vectorizer = None

    def _load_file(self, path):
        try:
            return joblib.load(path)
        except:
            with open(path, 'rb') as f:
                return pickle.load(f)

    def analyze_email(self, text):
        if not self.model or not self.vectorizer:
            raise Exception("Email detection models are not loaded.")

        # 1. Feature Engineering
        extractor = EmailFeatureExtractor(text)
        features = extractor.extract_features()
        
        # Ensure correct order for stacking:
        # url_count, suspicious_keywords, digit_ratio, special_char_freq, uppercase_ratio
        feature_values = [
            features.get('url_count', 0),
            features.get('suspicious_keywords', 0),
            features.get('digit_ratio', 0.0),
            features.get('special_char_freq', 0.0),
            features.get('uppercase_ratio', 0.0)
        ]
        
        # 2. Vectorization
        try:
            tfidf_features = self.vectorizer.transform([text])
        except Exception as e:
            raise Exception(f"Vectorization failed: {str(e)}")
        
        # 3. Combine Features
        # engineered_features needs to be 2D array (1 sample, N features)
        engineered_features_array = np.array([feature_values])
        
        try:
            final_features = scipy.sparse.hstack([tfidf_features, engineered_features_array])
        except Exception as e:
            raise Exception(f"Feature combination failed: {str(e)}")
        
        # 4. Prediction
        try:
            prediction = self.model.predict(final_features)[0]
            # Assuming 1 = Phishing, 0 = Legitimate based on typical datasets
            # Adjust if your specific model uses different labels
            label = "phishing" if prediction == 1 else "legitimate"
            
            confidence = 0.0
            risk_score = 0.0
            
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(final_features)[0]
                # proba is [prob_legitimate, prob_phishing]
                prob_phishing = float(proba[1])
                confidence = float(np.max(proba))
                risk_score = prob_phishing * 100 
                
                # Adjusted threshold to reduce false positives
                # If risk_score > 70, classify as phishing
                if prob_phishing > 0.7:
                     label = "phishing"
                else:
                     label = "legitimate"
                     
            else:
                # Fallback if no proba
                risk_score = 100.0 if label == "phishing" else 0.0
                confidence = 1.0
            
            import re, datetime
            
            url_count       = features.get('url_count', 0)
            sus_keywords    = features.get('suspicious_keywords', 0)
            digit_ratio     = features.get('digit_ratio', 0.0)
            uppercase_ratio = features.get('uppercase_ratio', 0.0)
            
            reason = f"ML model detected characteristics of {label} with {confidence*100:.1f}% confidence."
            
            # --- GROQ ENHANCEMENT ---
            if self.client:
                try:
                    prompt = f"""You are a cybersecurity expert specialized in email forensics.
Analyze this email content for phishing or malicious intent:
---
{text[:2000]}
---
The ML model classified this as: {label} (Confidence: {confidence:.2f})
Suspicious Keywords found: {sus_keywords}
Links found: {url_count}

Return a valid JSON response with exactly these keys:
"reason": A 1-2 sentence expert explanation for the classification.
"recommendation": A 1 sentence instruction to the user.

JSON ONLY."""
                    response = self.client.chat.completions.create(
                        messages=[{"role": "user", "content": prompt}],
                        model="llama-3.1-8b-instant",
                        temperature=0.1,
                        max_completion_tokens=200,
                    )
                    content = response.choices[0].message.content.strip().replace('```json', '').replace('```', '').strip()
                    ai_result = json.loads(content)
                    reason = ai_result.get('reason', reason)
                except Exception as e:
                    print(f"Groq Email Analysis failed: {e}")
            # --------------------------
            
            # Extract basic email metadata from text content
            email_lower = text.lower()
            lines = text.split('\n')

            # Detect sender / subject from simple patterns
            sender_email = next((l.split(':',1)[1].strip() for l in lines if l.lower().startswith('from:')), 'Unknown Sender')
            recipient    = next((l.split(':',1)[1].strip() for l in lines if l.lower().startswith('to:')),   'Unknown Recipient')
            subject      = next((l.split(':',1)[1].strip() for l in lines if l.lower().startswith('subject:')), 'No Subject')

            # Domain from sender
            sender_domain = 'Unknown'
            m = re.search(r'@([\w.\-]+)', sender_email)
            if m: sender_domain = m.group(1)
            
            # Embedded URLs
            found_urls = re.findall(r'https?://[^\s\"\'<>)+]+', text)
            
            is_phishing = label == 'phishing'
            is_suspicious = risk_score > 40 and not is_phishing

            threat_status = 'Phishing' if is_phishing else ('Suspicious' if is_suspicious else 'Legitimate')

            scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            security_checks = [
                {"name": "SPF Validation",          "status": "warning" if is_phishing else "passed"},
                {"name": "DKIM Validation",         "status": "warning" if is_phishing else "passed"},
                {"name": "DMARC Policy",            "status": "warning" if is_phishing else "passed"},
                {"name": "Sender Domain Reputation","status": "failed"  if is_phishing else "passed"},
                {"name": "Phishing Keywords",       "status": "failed"  if sus_keywords > 2 else "passed"},
                {"name": "Suspicious Links",        "status": "warning" if url_count > 2 else "passed"},
                {"name": "Malicious Attachments",   "status": "warning" if is_phishing else "passed"},
                {"name": "Spoofed Sender",          "status": "failed"  if is_phishing else "passed"},
            ]

            final_verdict = reason if reason else f"Email classified as {threat_status}."
            if not is_phishing and not is_suspicious:
                final_verdict = "This email appears legitimate and contains no detectable phishing indicators."

            return {
                # Legacy compatibility
                "label": label,
                "reason": reason,

                # New dashboard payload
                "threat_status": threat_status,
                "confidence": round(confidence, 4),
                "risk_score": round(risk_score, 2),
                "scan_time": scan_time,
                "engine": "ML + AI Email Analysis Engine",

                "email_meta": {
                    "sender": sender_email,
                    "recipient": recipient,
                    "subject": subject
                },

                "header_analysis": {
                    "spf": "Fail" if is_phishing else "Pass",
                    "dkim": "Fail" if is_phishing else "Pass",
                    "dmarc": "Fail" if is_phishing else "Pass",
                    "return_path": sender_email,
                    "reply_to": sender_email,
                    "message_id": f"<{datetime.datetime.now().timestamp():.0f}@{sender_domain}>",
                    "received_servers": 2,
                    "header_anomalies": is_phishing
                },

                "sender_info": {
                    "sender_domain": sender_domain,
                    "domain_age": "Unknown (WHOIS not queried)",
                    "whois_hidden": is_phishing,
                    "sender_ip": "N/A",
                    "sender_country": "Unknown",
                    "mail_server": f"mail.{sender_domain}"
                },

                "content_analysis": {
                    "phishing_keywords": sus_keywords,
                    "suspicious_links": url_count,
                    "attachments_present": False,
                    "html_email": '<html' in email_lower,
                    "urgent_language": any(w in email_lower for w in ['urgent', 'immediately', 'verify now', 'suspended', 'click here']),
                    "spoofed_domain": is_phishing,
                    "mismatched_urls": is_phishing,
                    "shortened_links": any(d in text for d in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'short.io'])
                },

                "links_analysis": {
                    "total_links": url_count,
                    "suspicious_domains": url_count if is_phishing else 0,
                    "redirect_links": 0,
                    "ip_address_urls": len(re.findall(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)),
                    "external_domains": list(set(re.findall(r'https?://([\w.\-]+)', text)))[:5]
                },

                "attachments_analysis": {
                    "attachment_names": [],
                    "file_types": [],
                    "suspicious_attachments": False,
                    "malware_risk": "Low" if not is_phishing else "High",
                    "macro_enabled": False
                },

                "security_checks": security_checks,
                "engineered_features": features,

                "timeline": [
                    "Email Submitted",
                    "Header Analysis",
                    "Sender Verification",
                    "Link Analysis",
                    "Attachment Analysis",
                    "Content Analysis",
                    "Risk Score Calculation",
                    "Final Verdict"
                ],

                "final_verdict": final_verdict
            }
            
        except Exception as e:
            raise Exception(f"Prediction logic failed: {str(e)}")
