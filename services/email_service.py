import os
import pickle
import joblib
import scipy.sparse
import numpy as np
from services.feature_extractor import EmailFeatureExtractor

class EmailService:
    def __init__(self, model_path, vectorizer_path):
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self.model = None
        self.vectorizer = None
        self._load_models()

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
                
            return {
                "label": label,
                "confidence": round(confidence, 4),
                "risk_score": round(risk_score, 2),
                "engineered_features": features
            }
            
        except Exception as e:
            raise Exception(f"Prediction logic failed: {str(e)}")
