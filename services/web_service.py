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
            if label.lower() == 'safe':
                 label = 'Safe / Benign'
                 
            return {
                "result": label,
                "confidence": result.get('confidence', 0.5),
                "reason": result.get('reason', '')
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
