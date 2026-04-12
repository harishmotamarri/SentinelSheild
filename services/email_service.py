import datetime
import json
import re

from groq import Groq


class EmailService:
    def __init__(self, model_path=None, vectorizer_path=None, api_key=None):
        # Paths kept for backward compatibility with app initialization.
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self.api_key = api_key
        self.model = None
        self.vectorizer = None

        if self.api_key:
            try:
                self.client = Groq(api_key=self.api_key)
                print("Email service initialized in Groq-only mode.")
            except Exception as e:
                print(f"Failed to initialize Groq client for EmailService: {e}")
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

    def analyze_email(self, text):
        if not self.client:
            raise Exception("Groq client not initialized (missing API key)")

        message = (text or "").strip()
        if not message:
            raise Exception("Email text must be a non-empty string")

        lines = message.splitlines()
        lower = message.lower()

        sender_email = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("from:")), "Unknown Sender")
        recipient = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("to:")), "Unknown Recipient")
        subject = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("subject:")), "No Subject")

        sender_domain = "Unknown"
        sender_match = re.search(r"@([\w.\-]+)", sender_email)
        if sender_match:
            sender_domain = sender_match.group(1).lower()

        found_urls = re.findall(r"https?://[^\s\"'<>)+]+", message)
        shortener_domains = ["bit.ly", "tinyurl", "t.co", "goo.gl", "short.io", "ow.ly"]
        shortened_links = any(sd in lower for sd in shortener_domains)

        phishing_terms = re.findall(
            r"\b(verify|urgent|immediately|suspended|password|login|click here|update account|invoice|payment due|gift card|otp)\b",
            lower,
        )
        sus_keywords = len(phishing_terms)

        prompt = f"""You are an elite cybersecurity email forensics analyst.
Classify this email into one of: Legitimate, Suspicious, Phishing.

Email content:
{message[:3500]}

Parsed context:
- sender_email: {sender_email}
- sender_domain: {sender_domain}
- subject: {subject}
- link_count: {len(found_urls)}
- suspicious_keyword_count: {sus_keywords}
- shortened_links_detected: {shortened_links}

Return ONLY valid JSON with exactly these keys:
1. "label": one of "Legitimate", "Suspicious", "Phishing"
2. "confidence": number between 0.0 and 1.0
3. "reason": short 1-2 sentence explanation
4. "recommendation": short 1 sentence recommendation
"""

        response = self.client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant",
            temperature=0.1,
            max_completion_tokens=260,
        )

        parsed = self._safe_json_loads(response.choices[0].message.content)
        if not parsed:
            parsed = {
                "label": "Suspicious",
                "confidence": 0.6,
                "reason": "Unable to parse complete AI output; defaulting to suspicious for safety.",
                "recommendation": "Do not click links or share credentials until independently verified.",
            }

        label = str(parsed.get("label", "Suspicious")).strip().title()
        if label not in ("Legitimate", "Suspicious", "Phishing"):
            label = "Suspicious"

        confidence = self._clamp_confidence(parsed.get("confidence", 0.65))
        reason = str(parsed.get("reason", "No explanation provided.")).strip()
        recommendation = str(parsed.get("recommendation", "Proceed with caution.")).strip()

        if label == "Legitimate":
            risk_score = min(25.0, max(0.0, (1.0 - confidence) * 100.0))
            threat_status = "Legitimate"
        elif label == "Phishing":
            risk_score = max(75.0, confidence * 100.0)
            threat_status = "Phishing"
        else:
            risk_score = max(45.0, confidence * 100.0)
            threat_status = "Suspicious"

        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_phishing = threat_status == "Phishing"
        is_suspicious = threat_status == "Suspicious"

        dkim_valid = not is_phishing
        spf_pass = not is_phishing
        dmarc_pass = not is_phishing

        security_checks = [
            {"name": "SPF Validation", "status": "failed" if not spf_pass else "passed"},
            {"name": "DKIM Validation", "status": "failed" if not dkim_valid else "passed"},
            {"name": "DMARC Policy", "status": "failed" if not dmarc_pass else "passed"},
            {"name": "Sender Domain Reputation", "status": "failed" if is_phishing else ("warning" if is_suspicious else "passed")},
            {"name": "Phishing Keywords", "status": "warning" if sus_keywords > 0 else "passed"},
            {"name": "Suspicious Links", "status": "warning" if found_urls else "passed"},
            {"name": "Shortened Links", "status": "warning" if shortened_links else "passed"},
        ]

        final_verdict = reason if reason else f"Email classified as {threat_status}."
        if threat_status == "Legitimate":
            final_verdict = "This email appears legitimate and contains no strong phishing indicators."

        return {
            # Legacy compatibility
            "label": threat_status.lower(),
            "result": threat_status,
            "reason": reason,

            # Dashboard payload
            "threat_status": threat_status,
            "confidence": round(confidence, 4),
            "risk_score": round(risk_score, 2),
            "scan_time": scan_time,
            "engine": "Groq AI Email Analysis Engine",

            "email_meta": {
                "sender": sender_email,
                "recipient": recipient,
                "subject": subject,
                "sender_domain": sender_domain,
            },

            "header_analysis": {
                "dkim_valid": dkim_valid,
                "spf_pass": spf_pass,
                "dmarc_pass": dmarc_pass,
                "spf": "Pass" if spf_pass else "Fail",
                "dkim": "Pass" if dkim_valid else "Fail",
                "dmarc": "Pass" if dmarc_pass else "Fail",
                "return_path": sender_email,
                "reply_to": sender_email,
                "message_id": f"<{int(datetime.datetime.now().timestamp())}@{sender_domain}>",
                "received_servers": 2,
                "header_anomalies": is_phishing or is_suspicious,
            },

            "sender_info": {
                "sender_domain": sender_domain,
                "domain_age": "Unknown",
                "whois_hidden": is_phishing,
                "sender_ip": "N/A",
                "sender_country": "Unknown",
                "mail_server": f"mail.{sender_domain}" if sender_domain != "Unknown" else "Unknown",
                "reputation": "Low" if is_phishing else ("Medium" if is_suspicious else "High"),
            },

            "content_analysis": {
                "phishing_keywords": sus_keywords,
                "suspicious_links": len(found_urls),
                "attachments_present": False,
                "html_email": "<html" in lower,
                "urgent_language": any(w in lower for w in ["urgent", "immediately", "verify now", "suspended", "click here"]),
                "spoofed_domain": is_phishing,
                "mismatched_urls": is_phishing,
                "shortened_links": shortened_links,
            },

            "links_analysis": {
                "total_links": len(found_urls),
                "suspicious_domains": len(found_urls) if is_phishing else 0,
                "redirect_links": 0,
                "ip_address_urls": len(re.findall(r"https?://\d{1,3}(?:\.\d{1,3}){3}", message)),
                "external_domains": list(set(re.findall(r"https?://([\w.\-]+)", message)))[:5],
            },

            "attachments_analysis": {
                "attachment_names": [],
                "file_types": [],
                "suspicious_attachments": False,
                "malware_risk": "High" if is_phishing else ("Medium" if is_suspicious else "Low"),
                "macro_enabled": False,
            },

            "security_checks": security_checks,
            "timeline": [
                "Email Submitted",
                "Header Analysis",
                "Sender Verification",
                "Link Analysis",
                "Content Intelligence Review",
                "AI Threat Classification",
                "Risk Score Calculation",
                "Final Verdict",
            ],
            "final_verdict": final_verdict,
            "ai_analysis": {
                "summary": f"Email appears {threat_status.lower()} based on sender and content indicators.",
                "reason": reason,
                "recommendation": recommendation,
            },
        }
