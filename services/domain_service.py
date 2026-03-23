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
            if label.lower() == 'safe':
                 label = 'Safe / Benign'
                 
            return {
                "result": label,
                "confidence": result.get('confidence', 0.5),
                "reason": result.get('reason', ''),
                "domain": domain,
                "registrar": whois_data.get('registrar', 'Unknown'),
                "creation_date": whois_data.get('creation_date', 'Unknown')
            }

        except Exception as e:
            print(f"Domain Check Error: {e}")
            # traceback.print_exc()
            return {"error": f"Domain check failed: {str(e)}", "status": 500}
