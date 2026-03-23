import json
import pickle
import joblib
import numpy as np

class SmsService:
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
                print(f"Failed to initialize Groq client for SmsService: {e}")
                self.client = None
        else:
            self.client = None

    def _load_models(self):
        print(f"Loading SMS detection models from {self.model_path}...")
        try:
            self.model = self._load_file(self.model_path)
            self.vectorizer = self._load_file(self.vectorizer_path)
            print("SMS detection models loaded successfully.")
        except Exception as e:
            print(f"Error loading SMS models: {e}")
            self.model = None
            self.vectorizer = None

    def _load_file(self, path):
        try:
            return joblib.load(path)
        except:
            with open(path, 'rb') as f:
                return pickle.load(f)

    def analyze_sms(self, text):
        if not self.model or not self.vectorizer:
            raise Exception("SMS detection models are not loaded.")

        try:
            # 1. Vectorization
            # Most SMS models are simpler and might only need TF-IDF
            # Based on the file names provided, it seems like a standard vectorizer/model pair.
            vectorized_text = self.vectorizer.transform([text])
            
            # 2. Prediction
            prediction = self.model.predict(vectorized_text)[0]
            
            # Assuming standard labels: 1 for spam/scam, 0 for ham/legitimate
            # We'll normalize to "scam" and "legitimate"
            label = "scam" if prediction == 1 or str(prediction).lower() == 'spam' else "legitimate"
            
            confidence = 1.0
            risk_score = 100.0 if label == "scam" else 0.0
            
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(vectorized_text)[0]
                # Assuming index 1 is the positive class (scam)
                # This might need adjustment depending on the model's classes_
                if len(proba) > 1:
                    prob_scam = float(proba[1])
                    confidence = float(np.max(proba))
                    risk_score = prob_scam * 100
                    
                    # Apply threshold if needed, default to 0.5
                    label = "scam" if prob_scam > 0.5 else "legitimate"
                else:
                    confidence = float(proba[0])
            
            reason = ""
            # --- GROQ ENHANCEMENT ---
            if self.client:
                print(f"Requesting Groq AI Analysis for SMS Content")
                try:
                    prompt = f"""You are a cybersecurity expert.
Analyze this SMS/message for potential scam or phishing threats.
The local ML model classified it as: {label} (Confidence: {confidence:.2f})

--- MESSAGE CONTENT ---
{text}

Return a valid JSON response with one key:
1. "reason": A short 1-2 sentence expert explanation for why this message is {label} or identifying specific scam tactics.

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
                    print(f"Groq SMS Analysis failed: {e}")
                    reason = f"Automated analysis classified this message as {label}."
            # --------------------------

            return {
                "label": label,
                "confidence": round(confidence, 4),
                "risk_score": round(risk_score, 2),
                "reason": reason
            }
            
        except Exception as e:
            print(f"SMS analysis failed: {e}")
            raise Exception(f"SMS analysis failed: {str(e)}")
