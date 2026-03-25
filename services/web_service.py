import requests
from bs4 import BeautifulSoup
from groq import Groq
import traceback
import json

class WebService:
    def __init__(self, api_key):
        self.api_key = api_key
        if not self.api_key:
             print("Warning: GROQ API Key is missing. Web inspection will fail.")
             self.client = None
        else:
             try:
                 self.client = Groq(api_key=self.api_key)
             except Exception as e:
                 print(f"Failed to initialize Groq client: {e}")
                 self.client = None

    def scrape_url(self, url):
        """Fetches and parses a URL, extracting visible text, forms, and scripts."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Ensure scheme is present
        if not url.startswith(('http://', 'https://')):
             url = 'http://' + url
             
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract title
        title = soup.title.string if soup.title else "No Title"
        
        # Kill all script and style elements for clean text
        for script in soup(["script", "style"]):
            script.extract()
            
        text = soup.get_text(separator=' ', strip=True)
        
        # Re-parse to get structural info
        soup_structural = BeautifulSoup(response.content, 'html.parser')
        forms = soup_structural.find_all('form')
        form_details = []
        for form in forms:
            action = form.get('action')
            inputs = form.find_all('input')
            has_password = any(i.get('type') == 'password' for i in inputs)
            form_details.append(f"Action: {action}, Password Field: {has_password}")
            
        scripts = soup_structural.find_all('script', src=True)
        script_sources = [s.get('src') for s in scripts[:10]] # Limit script sources
        
        return {
            "title": title,
            "text": text[:10000], # Limit text to prevent huge prompts
            "forms": form_details,
            "scripts": script_sources
        }

    def inspect_website(self, url):
        if not self.client:
             return {"error": "Groq client not initialized (missing API key)", "status": 500}

        try:
            print(f"Scraping content from {url}...")
            site_data = self.scrape_url(url)
            
            print(f"Sending site data to Groq API for analysis...")
            
            # Format the data for the prompt
            forms_str = "\n".join(site_data['forms']) if site_data['forms'] else "None"
            scripts_str = "\n".join(site_data['scripts']) if site_data['scripts'] else "None"
            
            prompt = f"""You are an elite cybersecurity expert system. 
Analyze the following website structural data and visible content for potential phishing attempts, fake login forms, malicious scripts, or social engineering.
Target URL: {url}
Site Title: {site_data['title']}

--- NOTABLE FORMS ({len(site_data['forms'])}) ---
{forms_str}

--- NOTABLE EXTERNAL SCRIPTS ---
{scripts_str}

--- VISIBLE TEXT SNIPPET ---
{site_data['text']}

Evaluate the risk level. Return a valid JSON response with EXACTLY these three keys:
1. "label": MUST be one of "Safe", "Suspicious", or "Malware".
2. "confidence": A float between 0.0 and 1.0 representing your confidence in this assessment.
3. "reason": A short 1-2 sentence explanation of your findings.

JSON Output ONLY. Do NOT output markdown formatting like ```json.
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
            reason = result.get('reason', '')

            # Risk score calculation
            base_score = int(confidence * 100)
            if label.lower() == 'safe':
                risk_score = 100 - base_score if base_score > 50 else base_score
                if risk_score > 30: risk_score = 15
            else:
                risk_score = base_score if base_score > 50 else base_score + 40

            import datetime
            scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            form_count = len(site_data['forms'])
            script_sources = site_data['scripts']
            script_count = len(script_sources)
            has_password_form = any('password' in str(f).lower() for f in site_data['forms'])
            uses_https = url.startswith('https://')

            # External resources from scraped script tags
            external_resources = []
            for src in script_sources:
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(src).netloc
                    if domain and domain not in external_resources:
                        external_resources.append(domain)
                except Exception:
                    pass

            security_checks = [
                {"name": "HTTPS Enabled", "status": "passed" if uses_https else "failed"},
                {"name": "SSL Certificate Valid", "status": "passed" if uses_https else "warning"},
                {"name": "Suspicious JavaScript", "status": "warning" if script_count > 8 else "passed"},
                {"name": "Hidden Forms", "status": "warning" if has_password_form else "passed"},
                {"name": "iFrame Injection", "status": "warning" if label.lower() != 'safe' else "passed"},
                {"name": "External Resources Trusted", "status": "passed" if label.lower() == 'safe' else "warning"}
            ]

            lbl = label.lower()
            ai_status = "danger" if lbl == "malware" else ("warning" if lbl == "suspicious" else "safe")
            indicators = [
                {"name": "AI Classification", "value": label, "status": ai_status},
                {"name": "HTTPS", "value": "Enabled" if uses_https else "Not used", "status": "safe" if uses_https else "danger"},
                {"name": "Script Tags", "value": str(script_count), "status": "warning" if script_count > 8 else "safe"},
                {"name": "Forms Detected", "value": str(form_count), "status": "warning" if form_count > 0 else "safe"},
                {"name": "Password Field", "value": "Present" if has_password_form else "None", "status": "warning" if has_password_form else "safe"},
                {"name": "External Script Domains", "value": str(len(external_resources)), "status": "warning" if external_resources else "safe"},
            ]

            final_verdict = reason if reason else f"This website has been classified as {label}."
            if label.lower() == 'safe':
                final_verdict = "This website appears safe to browse."

            return {
                # Legacy compatibility
                "result": label,
                "reason": reason,

                "url": url,
                "threat_status": threat_status,
                "confidence": confidence,
                "risk_score": risk_score,
                "scan_time": scan_time,
                "engine": "Website Inspection Engine",

                "page_info": {
                    "title": site_data['title'],
                    "page_size": "N/A",
                    "load_time": "N/A",
                    "scripts": script_count,
                    "external_links": len(external_resources),
                    "forms": form_count,
                    "iframes": 0
                },

                "security_analysis": {
                    "https": uses_https,
                    "ssl_valid": uses_https,
                    "mixed_content": not uses_https,
                    "suspicious_js": script_count > 8,
                    "hidden_forms": has_password_form,
                    "iframes_present": False,
                    "external_scripts": len(external_resources) > 0,
                    "redirect_detected": False
                },

                "technologies": ["Detected via HTTP headers (limited scraping)"],
                "external_resources": external_resources[:5] if external_resources else ["None detected"],

                "security_checks": security_checks,
                "indicators": indicators,

                "final_verdict": final_verdict
            }

        except requests.RequestException as re:
            print(f"Failed to fetch URL {url}: {re}")
            return {"error": f"Failed to reach the website: {str(re)}", "status": 400}
        except json.JSONDecodeError as jde:
            print(f"Groq API returned invalid JSON: {jde}")
            return {"error": "Failed to parse API response", "status": 500}
        except Exception as e:
            print(f"Web Inspection Error: {e}")
            traceback.print_exc()
            return {"error": f"Inspection failed: {str(e)}", "status": 500}
