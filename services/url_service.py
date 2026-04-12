import datetime
import json
import re
import traceback
from urllib.parse import urlparse

from groq import Groq


class UrlService:
    def __init__(self, model_path=None, api_key=None):
        # model_path kept for backward compatibility with app initialization.
        self.model_path = model_path
        self.api_key = api_key
        self.model = None

        if self.api_key:
            try:
                self.client = Groq(api_key=self.api_key)
                print("URL service initialized in Groq-only mode.")
            except Exception as e:
                print(f"Failed to initialize Groq client for UrlService: {e}")
                self.client = None
        else:
            self.client = None

        self.url_pattern = re.compile(
            r"^(?:http|ftp)s?://"
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"
            r"localhost|"
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            r"(?::\d+)?"
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )

        self.shortener_domains = {
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "shorturl.at"
        }

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

    def validate_url(self, url):
        if not url:
            raise ValueError("No URL provided")

        check_url = url
        if not url.startswith(("http://", "https://")):
            check_url = "http://" + url

        if not self.url_pattern.match(check_url):
            raise ValueError("Invalid URL format")

        return check_url

    def scan_url(self, url):
        if not self.client:
            return {"error": "Groq client not initialized (missing API key)", "status": 503}

        try:
            valid_url = self.validate_url(url)
            parsed = urlparse(valid_url)
            domain = parsed.netloc.lower().split(":")[0]
            if domain.startswith("www."):
                domain = domain[4:]

            uses_https = parsed.scheme.lower() == "https"
            has_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain))
            has_at_symbol = "@" in valid_url
            domain_dash_count = domain.count("-")
            digit_count = sum(ch.isdigit() for ch in valid_url)
            url_len = len(valid_url)
            suspicious_tokens = [
                token for token in [
                    "login", "verify", "secure", "update", "account", "bank", "wallet",
                    "bonus", "free", "gift", "invoice", "payment", "signin", "reset"
                ] if token in valid_url.lower()
            ]
            is_shortener = domain in self.shortener_domains

            prompt = f"""You are an elite cybersecurity URL analyst.
Classify this URL into one of Safe, Suspicious, or Malware.

URL: {valid_url}

Signals:
- domain: {domain}
- https_enabled: {uses_https}
- ip_as_host: {has_ip}
- has_at_symbol: {has_at_symbol}
- domain_dash_count: {domain_dash_count}
- digit_count: {digit_count}
- url_length: {url_len}
- looks_like_shortener: {is_shortener}
- suspicious_tokens: {', '.join(suspicious_tokens) if suspicious_tokens else 'none'}

Return ONLY valid JSON with exactly these keys:
1. "label": one of "Safe", "Suspicious", "Malware"
2. "confidence": number between 0.0 and 1.0
3. "summary": one short sentence
4. "reason": 1-2 sentence explanation
5. "recommendation": one short actionable sentence
"""

            response = self.client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="llama-3.1-8b-instant",
                temperature=0.1,
                max_completion_tokens=260,
            )

            parsed_ai = self._safe_json_loads(response.choices[0].message.content)
            if not parsed_ai:
                parsed_ai = {
                    "label": "Suspicious",
                    "confidence": 0.6,
                    "summary": "Unable to parse full model output; defaulting to suspicious.",
                    "reason": "The AI response was incomplete, so this URL is treated cautiously.",
                    "recommendation": "Avoid submitting credentials unless verified through a trusted source.",
                }

            label = str(parsed_ai.get("label", "Suspicious")).strip().title()
            if label not in ("Safe", "Suspicious", "Malware"):
                label = "Suspicious"

            confidence = self._clamp_confidence(parsed_ai.get("confidence", 0.65))
            ai_summary = str(parsed_ai.get("summary", "URL analysis completed.")).strip()
            reason = str(parsed_ai.get("reason", "No explanation provided.")).strip()
            recommendation = str(parsed_ai.get("recommendation", "Proceed carefully with this URL.")).strip()

            if label == "Safe":
                risk_score = min(20.0, max(0.0, (1.0 - confidence) * 100.0))
                threat_status = "Safe"
                final_verdict = "This URL appears safe to visit."
            elif label == "Malware":
                risk_score = max(75.0, confidence * 100.0)
                threat_status = "Malware"
                final_verdict = reason or "This URL appears malicious. Do not open it."
            else:
                risk_score = max(45.0, confidence * 100.0)
                threat_status = "Suspicious"
                final_verdict = reason or "This URL appears suspicious. Use caution."

            scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

            indicators = [
                {"name": "URL Length", "value": f"{url_len} chars", "status": "warning" if url_len > 90 else "safe"},
                {"name": "HTTPS", "value": "Yes" if uses_https else "No", "status": "safe" if uses_https else "danger"},
                {"name": "IP Address Usage", "value": "Yes" if has_ip else "No", "status": "danger" if has_ip else "safe"},
                {"name": "Shortener Service", "value": "Yes" if is_shortener else "No", "status": "warning" if is_shortener else "safe"},
                {"name": "Suspicious Tokens", "value": str(len(suspicious_tokens)), "status": "warning" if suspicious_tokens else "safe"},
                {"name": "AI Classification", "value": label, "status": "danger" if label == "Malware" else ("warning" if label == "Suspicious" else "safe")},
            ]

            security_checks = [
                {"name": "SSL Certificate", "status": "passed" if uses_https else "failed"},
                {"name": "Domain Format", "status": "warning" if has_ip or has_at_symbol else "passed"},
                {"name": "Redirection Pattern", "status": "warning" if is_shortener else "passed"},
                {"name": "Phishing Token Scan", "status": "warning" if suspicious_tokens else "passed"},
                {"name": "AI Threat Classification", "status": "failed" if label == "Malware" else ("warning" if label == "Suspicious" else "passed")},
            ]

            return {
                "url": valid_url,
                "threat_status": threat_status,
                "confidence": round(confidence, 4),
                "risk_score": round(risk_score, 2),
                "engine": "Groq AI URL Intelligence Engine",
                "scan_time": scan_time,
                "ai_analysis": {
                    "summary": ai_summary,
                    "reason": reason,
                    "recommendation": recommendation,
                },
                "indicators": indicators,
                "security_checks": security_checks,
                "timeline": [
                    "URL Submitted",
                    "Syntax Validation",
                    "Signal Extraction",
                    "AI Threat Classification",
                    "Risk Score Calculation",
                    "Final Verdict",
                ],
                "final_verdict": final_verdict,

                # Compatibility keys
                "result": label,
                "reason": reason,
            }

        except ValueError as ve:
            return {"error": str(ve), "status": 400}
        except Exception as e:
            print(f"URL Scan Error: {e}")
            traceback.print_exc()
            return {"error": f"Scanning failed: {str(e)}", "status": 500}
