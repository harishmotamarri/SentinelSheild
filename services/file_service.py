import os
import io
from groq import Groq
import traceback

class FileService:
    def __init__(self, api_key):
        self.api_key = api_key
        # Check if the API key is not simply empty or a placeholder
        if not self.api_key:
             print("Warning: GROQ API Key is missing. File analysis will fail.")
             self.client = None
        else:
             try:
                 self.client = Groq(api_key=self.api_key)
             except Exception as e:
                 print(f"Failed to initialize Groq client: {e}")
                 self.client = None

    def extract_text_from_file(self, file_stream, filename):
        """Extracts text from a file stream based on extension."""
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        text_content = ""

        try:
            if ext in ['txt', 'py', 'js', 'html', 'css', 'json', 'csv', 'md', 'sh', 'bat', 'ps1']:
                # Read as simple text
                text_content = file_stream.read().decode('utf-8', errors='ignore')

            elif ext == 'pdf':
                try:
                    import PyPDF2
                    pdf_reader = PyPDF2.PdfReader(file_stream)
                    for page in pdf_reader.pages:
                        text_content += page.extract_text() + "\n"
                except ImportError:
                    raise Exception("PyPDF2 is not installed. PDF extraction failed.")

            elif ext == 'docx':
                try:
                    import docx
                    doc = docx.Document(file_stream)
                    for para in doc.paragraphs:
                        text_content += para.text + "\n"
                except ImportError:
                     raise Exception("python-docx is not installed. DOCX extraction failed.")
            else:
                 raise Exception(f"Unsupported file type: .{ext}. Attempted default text decode failed.")
                 
        except Exception as e:
            print(f"Error extracting text from {filename}: {e}")
            raise Exception(f"Could not extract readable text from {filename}: {str(e)}")

        return text_content[:15000] # Limit text length to avoid token limits

    def analyze_file(self, file_stream, filename):
        """Analyzes a file using the Groq LLaMA model."""
        if not self.client:
             return {"error": "Groq client not initialized (missing API key)", "status": 500}

        try:
            print(f"Extracting text from {filename}...")
            text_content = self.extract_text_from_file(file_stream, filename)
            
            if not text_content or not text_content.strip():
                 return {"error": "No readable text found in the file", "status": 400}

            print(f"Sending text to Groq API for analysis...")
            prompt = f"""You are an elite cybersecurity expert system. 
Analyze the following file snippet for potential malware, malicious macros, reverse shells, suspicious scripts, or phishing content.
File Name: {filename}
--- FILE CONTENT BEGIN ---
{text_content}
--- FILE CONTENT END ---

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
                model="llama-3.1-8b-instant", # Defaulting to the fast 8b model
                temperature=0.1,
                max_completion_tokens=256,
            )

            # Try to parse the JSON response
            import json
            content = response.choices[0].message.content
            # Clean up potential markdown blocks if the model ignored instructions
            content = content.replace('```json', '').replace('```', '').strip()
            
            result = json.loads(content)
            
            # Map to standard interface expected by UI
            label = result.get('label', 'Unknown')
            # Normalize label
            if label.lower() == 'safe':
                 label = 'Safe / Benign'
                 
            return {
                "result": label,
                "confidence": result.get('confidence', 0.5),
                "reason": result.get('reason', '')
            }

        except json.JSONDecodeError as jde:
            print(f"Groq API returned invalid JSON: {jde}")
            return {"error": "Failed to parse API response", "status": 500}
        except Exception as e:
            print(f"File Scan Error: {e}")
            traceback.print_exc()
            return {"error": f"Scanning failed: {str(e)}", "status": 500}
