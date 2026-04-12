import datetime
import json
import re
import socket
import traceback

import whois
from groq import Groq


class DomainService:
    def __init__(self, api_key):
        self.api_key = api_key
        if not self.api_key:
            print("Warning: GROQ API Key is missing. Domain analysis will fail.")
            self.client = None
        else:
            try:
                self.client = Groq(api_key=self.api_key)
                print("Domain service initialized in Groq-only mode.")
            except Exception as e:
                print(f"Failed to initialize Groq client for DomainService: {e}")
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

    @staticmethod
    def _normalize_domain(domain):
        value = (domain or "").strip().lower()
        value = re.sub(r"^https?://", "", value)
        value = value.split("/")[0].split(":")[0]
        if value.startswith("www."):
            value = value[4:]
        return value

    @staticmethod
    def _to_iso(val):
        if isinstance(val, list):
            val = val[0] if val else None
        if val is None:
            return "Unknown"
        if hasattr(val, "isoformat"):
            return val.isoformat()
        return str(val)

    def check_domain(self, domain):
        if not self.client:
            return {"error": "Groq client not initialized (missing API key)", "status": 503}

        try:
            normalized = self._normalize_domain(domain)
            if not normalized or "." not in normalized:
                return {"error": "Invalid domain format", "status": 400}

            ip_address = "Unable to resolve"
            dns_records = {"A": "Missing", "MX": "Unknown", "NS": "Unknown", "TXT": "Unknown"}

            try:
                ip_address = socket.gethostbyname(normalized)
                dns_records["A"] = "Present"
            except Exception:
                pass

            whois_data = {}
            try:
                w = whois.whois(normalized)
                whois_data = {
                    "registrar": self._to_iso(getattr(w, "registrar", None)),
                    "creation_date": self._to_iso(getattr(w, "creation_date", None)),
                    "expiration_date": self._to_iso(getattr(w, "expiration_date", None)),
                    "country": self._to_iso(getattr(w, "country", None)),
                    "name_servers": getattr(w, "name_servers", None),
                }

                name_servers = whois_data.get("name_servers")
                if isinstance(name_servers, list) and name_servers:
                    dns_records["NS"] = "Present"
                elif isinstance(name_servers, str) and name_servers.strip():
                    dns_records["NS"] = "Present"
            except Exception as e:
                whois_data = {
                    "registrar": "Unknown",
                    "creation_date": "Unknown",
                    "expiration_date": "Unknown",
                    "country": "Unknown",
                    "name_servers": [],
                    "whois_error": str(e),
                }

            registrar = str(whois_data.get("registrar", "Unknown"))
            creation = str(whois_data.get("creation_date", "Unknown"))
            expiry = str(whois_data.get("expiration_date", "Unknown"))
            country = str(whois_data.get("country", "Unknown"))

            name_servers = whois_data.get("name_servers") or []
            if isinstance(name_servers, str):
                name_servers = [name_servers]

            whois_hidden = any(x in registrar.lower() for x in ["privacy", "protect", "redacted", "proxy"])

            prompt = f"""You are a domain reputation analyst.
Classify this domain as Safe, Suspicious, or Malware.

Domain: {normalized}
Resolved IP: {ip_address}
Registrar: {registrar}
Creation Date: {creation}
Expiry Date: {expiry}
Country: {country}
DNS records: {json.dumps(dns_records)}
Name server count: {len(name_servers)}

Return ONLY valid JSON with exactly these keys:
1. "label": one of "Safe", "Suspicious", or "Malware"
2. "confidence": number between 0.0 and 1.0
3. "reason": short 1-2 sentence explanation
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
                    "reason": "Unable to parse complete AI output; defaulting to suspicious for safety.",
                }

            label = str(parsed.get("label", "Suspicious")).strip().title()
            if label not in ("Safe", "Suspicious", "Malware"):
                label = "Suspicious"

            confidence = self._clamp_confidence(parsed.get("confidence", 0.65))
            reason = str(parsed.get("reason", "No explanation provided.")).strip()

            if label == "Safe":
                risk_score = min(20.0, max(0.0, (1.0 - confidence) * 100.0))
            elif label == "Malware":
                risk_score = max(75.0, confidence * 100.0)
            else:
                risk_score = max(45.0, confidence * 100.0)

            scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            security_checks = [
                {"name": "WHOIS Information", "status": "warning" if registrar == "Unknown" else "passed"},
                {"name": "DNS Configured", "status": "passed" if dns_records["A"] == "Present" else "failed"},
                {"name": "Name Servers", "status": "passed" if dns_records["NS"] == "Present" else "warning"},
                {"name": "Domain Privacy Shield", "status": "warning" if whois_hidden else "passed"},
                {"name": "AI Threat Classification", "status": "failed" if label == "Malware" else ("warning" if label == "Suspicious" else "passed")},
            ]

            indicators = [
                {"name": "AI Classification", "value": label, "status": "danger" if label == "Malware" else ("warning" if label == "Suspicious" else "safe")},
                {"name": "Registrar", "value": registrar[:120], "status": "warning" if whois_hidden else "safe"},
                {"name": "Name Servers", "value": f"{len(name_servers)} configured" if name_servers else "None detected", "status": "safe" if name_servers else "warning"},
                {"name": "DNS A Record", "value": dns_records.get("A", "Unknown"), "status": "safe" if dns_records.get("A") == "Present" else "danger"},
                {"name": "DNS NS Record", "value": dns_records.get("NS", "Unknown"), "status": "safe" if dns_records.get("NS") == "Present" else "warning"},
                {"name": "Hosting Country", "value": country, "status": "safe"},
            ]

            final_verdict = reason if reason else f"This domain appears {label.lower()}."

            return {
                "result": label,
                "reason": reason,
                "domain": normalized,
                "threat_status": label,
                "confidence": round(confidence, 4),
                "risk_score": round(risk_score, 2),
                "scan_time": scan_time,
                "engine": "Groq AI Domain Intelligence Engine",
                "domain_info": {
                    "registrar": registrar,
                    "creation_date": creation,
                    "expiry_date": expiry,
                    "domain_age": "Unknown" if creation == "Unknown" else "Known",
                    "whois_hidden": whois_hidden,
                },
                "hosting_info": {
                    "ip_address": ip_address,
                    "hosting_provider": "Unknown External",
                    "country": country,
                },
                "dns_records": dns_records,
                "security_checks": security_checks,
                "indicators": indicators,
                "final_verdict": final_verdict,
            }

        except Exception as e:
            print(f"Domain Check Error: {e}")
            traceback.print_exc()
            return {"error": f"Domain check failed: {str(e)}", "status": 500}
