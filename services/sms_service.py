import datetime
import json
import re

from groq import Groq


class SmsService:
    def __init__(self, model_path=None, vectorizer_path=None, api_key=None):
        # Kept for backward compatibility with app initialization.
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self.api_key = api_key
        self.model = None
        self.vectorizer = None

        if self.api_key:
            try:
                self.client = Groq(api_key=self.api_key)
                print("SMS service initialized in Groq-only mode.")
            except Exception as e:
                print(f"Failed to initialize Groq client for SmsService: {e}")
                self.client = None
        else:
            self.client = None

    @staticmethod
    def _safe_json_loads(text):
        if not text:
            return None
        cleaned = text.strip().replace("```json", "").replace("```", "").strip()
        try:
            return json.loads(cleaned)
        except Exception:
            pass

        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(cleaned[start:end + 1])
            except Exception:
                return None
        return None

    @staticmethod
    def _clamp_confidence(value, default=0.65):
        try:
            v = float(value)
        except Exception:
            v = default
        return max(0.0, min(1.0, v))

    def analyze_sms(self, text):
        if not self.client:
            raise Exception("Groq client not initialized (missing API key)")

        message = (text or "").strip()
        if not message:
            raise Exception("SMS text must be a non-empty string")

        link_count = len(re.findall(r"https?://\S+|www\.\S+", message, flags=re.IGNORECASE))
        phone_count = len(re.findall(r"\+?\d[\d\s\-]{7,}\d", message))
        amount_count = len(re.findall(r"\$\s?\d+|\b\d+\s?(usd|inr|eur|gbp)\b", message, flags=re.IGNORECASE))
        urgency_hits = len(re.findall(r"\burgent\b|\bimmediately\b|\bnow\b|\bverify\b|\bact fast\b", message, flags=re.IGNORECASE))

        prompt = f"""You are a cybersecurity analyst for SMS and messaging scams.
Analyze this message and classify risk.

Message:
{message[:2500]}

Extracted context:
- links_detected: {link_count}
- phone_numbers_detected: {phone_count}
- amount_mentions: {amount_count}
- urgency_terms: {urgency_hits}

Return ONLY valid JSON with exactly these keys:
1. \"label\": one of \"Legitimate\", \"Suspicious\", or \"Scam\"
2. \"confidence\": number between 0.0 and 1.0
3. \"reason\": short 1-2 sentence explanation
4. \"recommendation\": short 1 sentence next step for user
"""

        response = self.client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant",
            temperature=0.1,
            max_completion_tokens=220,
        )

        parsed = self._safe_json_loads(response.choices[0].message.content)
        if not parsed:
            parsed = {
                "label": "Suspicious",
                "confidence": 0.6,
                "reason": "Unable to parse complete AI output; message treated as suspicious by default.",
                "recommendation": "Avoid clicking links or sharing personal details until verified."
            }

        label = str(parsed.get("label", "Suspicious")).strip().title()
        if label not in ("Legitimate", "Suspicious", "Scam"):
            label = "Suspicious"

        confidence = self._clamp_confidence(parsed.get("confidence", 0.65))
        reason = str(parsed.get("reason", "No explanation provided.")).strip()
        recommendation = str(parsed.get("recommendation", "Use caution with this message.")).strip()

        if label == "Legitimate":
            risk_score = min(25.0, max(0.0, (1.0 - confidence) * 100.0))
            threat_status = "Legitimate"
        elif label == "Scam":
            risk_score = max(70.0, confidence * 100.0)
            threat_status = "Scam"
        else:
            risk_score = max(45.0, confidence * 100.0)
            threat_status = "Suspicious"

        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        security_checks = [
            {"name": "Suspicious Links", "status": "warning" if link_count > 0 else "passed"},
            {"name": "Urgency Language", "status": "warning" if urgency_hits > 0 else "passed"},
            {"name": "Money Request Pattern", "status": "warning" if amount_count > 0 else "passed"},
            {"name": "Sender Trust Context", "status": "failed" if label == "Scam" else ("warning" if label == "Suspicious" else "passed")},
        ]

        indicators = [
            {"name": "AI Classification", "value": threat_status, "status": "danger" if label == "Scam" else ("warning" if label == "Suspicious" else "safe")},
            {"name": "Links Detected", "value": str(link_count), "status": "warning" if link_count > 0 else "safe"},
            {"name": "Urgency Terms", "value": str(urgency_hits), "status": "warning" if urgency_hits > 0 else "safe"},
            {"name": "Money Mentions", "value": str(amount_count), "status": "warning" if amount_count > 0 else "safe"},
        ]

        final_verdict = reason or f"Message classified as {threat_status}."

        return {
            "label": threat_status.lower(),
            "result": threat_status,
            "threat_status": threat_status,
            "confidence": round(confidence, 4),
            "risk_score": round(risk_score, 2),
            "reason": reason,
            "engine": "Groq AI SMS Analysis Engine",
            "scan_time": scan_time,
            "ai_analysis": {
                "summary": f"Message appears {threat_status.lower()} based on linguistic and intent signals.",
                "reason": reason,
                "recommendation": recommendation,
            },
            "indicators": indicators,
            "security_checks": security_checks,
            "final_verdict": final_verdict,
        }
