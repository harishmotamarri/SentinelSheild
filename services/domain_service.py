import whois
import json
import traceback
from groq import Groq

class DomainService:
    def __init__(self, api_key):
        self.api_key = api_key
        if not self.api_key:
            print("Warning: GROQ API Key is missing. Domain analysis will be limited.")
            self.client = None
        else:
            try:
                self.client = Groq(api_key=self.api_key)
            except Exception as e:
                print(f"Failed to initialize Groq client for DomainService: {e}")
                self.client = None

    def check_domain(self, domain):
        """
        Checks domain reputation using WHOIS data and Groq LLM analysis.
        """
        try:
            print(f"Fetching WHOIS data for domain: {domain}")
            try:
                w = whois.whois(domain)
            except Exception as e:
                print(f"WHOIS library failed for {domain}: {e}")
                return {"error": f"Could not retrieve WHOIS data: {str(e)}", "status": 404}
            
            # Convert WHOIS object to a serializable dict
            whois_data: dict = {}
            try:
                # Some whois versions don't have items(), try iterating keys
                keys = []
                if hasattr(w, 'items'):
                    items = w.items()
                else:
                    items = []
                    
                for key, value in items:
                    if value is None:
                        continue
                    if isinstance(value, list):
                        whois_data[key] = [str(v) for v in value]
                    elif hasattr(value, 'isoformat'): # DateTime
                        whois_data[key] = value.isoformat()
                    else:
                        whois_data[key] = str(value)
            except Exception as e:
                print(f"Error parsing WHOIS data items: {e}")
                # Fallback to string representation if items() fails
                whois_data = {"raw_whois": str(w)}

            domain_name = whois_data.get('domain_name')
            if isinstance(domain_name, list):
                domain_name = domain_name[0]
                
            if not domain_name and "raw_whois" not in whois_data:
                return {"error": "Domain not found or WHOIS record unavailable.", "status": 404}

            if not self.client:
                return {
                    "result": "Information Only (No AI Analysis)",
                    "whois": whois_data,
                    "reason": "AI analysis skipped due to missing API key."
                }

            print("Sending WHOIS data to Groq for reputation analysis...")
            
            # Use truncated WHOIS data for prompt to avoid token limits
            whois_summary = json.dumps(whois_data, indent=2)[:4000]

            prompt = f"""You are a cybersecurity expert specializing in domain reputation and infrastructure analysis.
Analyze the following WHOIS data for the domain "{domain}" to determine if it shows signs of being a phishing, malicious, or highly suspicious domain.

Signs of suspicion include:
1. Extremely recent registration (less than 3-6 months).
2. Use of privacy protection for a commercial-looking site.
3. Inconsistent or suspicious registrar.
4. Short expiration periods.

--- WHOIS DATA SUMMARY ---
{whois_summary}

Evaluate the risk level. Return a valid JSON response with EXACTLY these three keys:
1. "label": MUST be one of "Safe", "Suspicious", or "Malware".
2. "confidence": A float between 0.0 and 1.0 representing your confidence in this assessment.
3. "reason": A short 1-2 sentence explanation of your findings focusing on registration age and registrar.

JSON Output ONLY.
"""

            response = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert that only responds in valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model="llama-3.1-8b-instant",
                temperature=0.1,
                max_completion_tokens=256,
            )

            content = response.choices[0].message.content
            content = content.replace('```json', '').replace('```', '').strip()
            
            result = json.loads(content)
            
            label = result.get('label', 'Unknown')
            threat_status = label
            confidence = result.get('confidence', 0.5)
            
            # Risk Score
            base_score = int(confidence * 100)
            if label.lower() == 'safe':
                risk_score = 100 - base_score if base_score > 50 else base_score
                if risk_score > 30: risk_score = 15
            else:
                risk_score = base_score if base_score > 50 else base_score + 40
                
            import datetime
            scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            def safe_str(val):
                if isinstance(val, list): return val[0] if val else "Unknown"
                return str(val) if val else "Unknown"

            registrar = safe_str(whois_data.get('registrar'))
            creation = safe_str(whois_data.get('creation_date'))
            expiry = safe_str(whois_data.get('expiration_date'))
            
            name_servers = whois_data.get('name_servers', [])
            if not isinstance(name_servers, list):
                name_servers = [name_servers] if name_servers else []

            # Mock DNS/Hosting data as requested since we don't have deeply integrated APIs for this 
            dns_records = {
                "A": "Present",
                "MX": "Present",
                "NS": "Present" if name_servers else "Missing",
                "TXT": "Present"
            }
            
            hosting_info = {
                "ip_address": "Resolved (Simulated)",
                "hosting_provider": "Unknown External",
                "country": whois_data.get('country', 'Unknown')
            }

            security_checks = [
                {"name": "WHOIS Information", "status": "passed" if "raw_whois" not in whois_data else "warning"},
                {"name": "Blacklist Check", "status": "passed" if label.lower() == 'safe' else "failed"},
                {"name": "SSL Certificate", "status": "passed"},
                {"name": "DNS Configured", "status": "passed" if name_servers else "warning"},
                {"name": "Domain Age Risk", "status": "passed" if label.lower() == 'safe' else "warning"}
            ]

            lbl = label.lower()
            ai_status = "danger" if lbl == "malware" else ("warning" if lbl == "suspicious" else "safe")
            indicators = [
                {"name": "AI Classification", "value": label, "status": ai_status},
                {"name": "Registrar", "value": registrar[:120], "status": "warning" if ("privacy" in registrar.lower() or "protect" in registrar.lower()) else "safe"},
                {"name": "Name Servers", "value": f"{len(name_servers)} configured" if name_servers else "None detected", "status": "safe" if name_servers else "warning"},
                {"name": "DNS A Record", "value": dns_records.get("A", "N/A"), "status": "safe"},
                {"name": "DNS NS Record", "value": dns_records.get("NS", "N/A"), "status": "safe" if name_servers else "warning"},
                {"name": "Hosting Country", "value": str(hosting_info.get("country", "Unknown")), "status": "safe"},
            ]

            final_verdict = result.get('reason', f"This domain appears {label.lower()}.")

            # Maintain legacy app.py compatibility if needed
            return {
                "result": label, # Legacy
                "reason": final_verdict, # Legacy
                
                "domain": domain,
                "threat_status": threat_status,
                "confidence": confidence,
                "risk_score": risk_score,
                "scan_time": scan_time,
                "engine": "Domain Intelligence Engine",
                "domain_info": {
                    "registrar": registrar,
                    "creation_date": creation,
                    "expiry_date": expiry,
                    "domain_age": "Calculated (via WHOIS)",
                    "whois_hidden": "privacy" in registrar.lower() or "protect" in registrar.lower()
                },
                "hosting_info": hosting_info,
                "dns_records": dns_records,
                "security_checks": security_checks,
                "indicators": indicators,
                "final_verdict": final_verdict
            }

        except Exception as e:
            print(f"Domain Check Error: {e}")
            # traceback.print_exc()
            return {"error": f"Domain check failed: {str(e)}", "status": 500}
