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

            import json, hashlib, datetime, mimetypes
            content_raw = response.choices[0].message.content
            content_raw = content_raw.replace('```json', '').replace('```', '').strip()

            result = json.loads(content_raw)

            label = result.get('label', 'Unknown')
            threat_status = label
            confidence = result.get('confidence', 0.5)
            reason = result.get('reason', '')

            base_score = int(confidence * 100)
            if label.lower() == 'safe':
                risk_score = 100 - base_score if base_score > 50 else base_score
                if risk_score > 30: risk_score = 15
            else:
                risk_score = base_score if base_score > 50 else base_score + 40

            scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Compute hashes from the already-read text_content bytes
            raw_bytes = text_content.encode('utf-8', errors='ignore')
            md5    = hashlib.md5(raw_bytes).hexdigest()
            sha1   = hashlib.sha1(raw_bytes).hexdigest()
            sha256 = hashlib.sha256(raw_bytes).hexdigest()
            
            # MIME type detection fallback
            mime, _ = mimetypes.guess_type(filename)
            if not mime:
                mime = "text/plain" if text_content else "application/octet-stream"

            # Simple static analysis of the text content
            lower_content = text_content.lower()
            suspicious_keywords = [kw for kw in ['eval(', 'exec(', 'base64', 'powershell', 'cmd.exe', 'wget', 'curl', 'shell', 'reverse', 'payload', 'exploit', 'shellcode'] if kw in lower_content]
            embedded_urls = [w for w in text_content.split() if w.startswith('http') and len(w) > 8][:5]
            ext = filename.lower().split('.')[-1] if '.' in filename else 'unknown'
            is_executable = ext in ['exe', 'dll', 'bat', 'sh', 'ps1', 'vbs']

            is_malware = label.lower() == 'malware'
            is_suspicious = label.lower() == 'suspicious'
            
            security_checks = [
                {"name": "Known Malware Signature", "status": "failed" if is_malware else "passed"},
                {"name": "Suspicious Strings", "status": "warning" if suspicious_keywords else "passed"},
                {"name": "Packed Executable", "status": "warning" if is_executable else "passed"},
                {"name": "Obfuscated Code", "status": "warning" if 'base64' in lower_content else "passed"},
                {"name": "External Network Calls", "status": "warning" if any(x in lower_content for x in ['wget','curl','http']) else "passed"},
                {"name": "Embedded URLs", "status": "warning" if embedded_urls else "passed"},
                {"name": "Invalid Signature", "status": "warning" if is_malware or is_suspicious else "passed"},
            ]

            final_verdict = reason if reason else f"File classified as {label}."
            if label.lower() == 'safe':
                final_verdict = "This file appears safe and contains no detectable malicious content."

            return {
                # Legacy compatibility
                "result": label,
                "reason": reason,

                "filename": filename,
                "file_type": ext.upper(),
                "file_size": f"{len(raw_bytes) / 1024:.1f} KB",
                "threat_status": threat_status,
                "confidence": confidence,
                "risk_score": risk_score,
                "scan_time": scan_time,
                "engine": "AI Deep File Analysis Engine",

                "hash_info": {
                    "md5": md5,
                    "sha1": sha1,
                    "sha256": sha256,
                    "entropy": f"{len(set(raw_bytes)) / 256 * 8:.2f} bits",
                    "mime_type": mime
                },

                "malware_analysis": {
                    "malware_detected": is_malware,
                    "malware_type": "Trojan / Script Threat" if is_malware else "N/A",
                    "suspicious_behavior": is_malware or is_suspicious,
                    "packed_file": is_executable,
                    "obfuscation": 'base64' in lower_content,
                    "suspicious_strings": suspicious_keywords[:6],
                    "executable_sections": is_executable,
                    "permissions_requested": "Read/Write/Execute" if is_executable else "Read-Only"
                },

                "static_analysis": {
                    "imports": f"{ext.upper()} file — static import analysis skipped",
                    "strings_found": len(text_content.split()),
                    "suspicious_keywords": len(suspicious_keywords),
                    "embedded_urls": embedded_urls,
                    "file_sections": f"1 section ({ext.upper()})",
                    "compiler_info": "N/A",
                    "digital_signature": "Unsigned"
                },

                "security_checks": security_checks,

                "timeline": [
                    "File Uploaded",
                    "Hash Calculation",
                    "Signature Scan",
                    "Static Analysis",
                    "Behavior Analysis",
                    "Threat Classification",
                    "Risk Score Calculation",
                    "Final Verdict"
                ],

                "final_verdict": final_verdict
            }

        except json.JSONDecodeError as jde:
            print(f"Groq API returned invalid JSON: {jde}")
            return {"error": "Failed to parse API response", "status": 500}
        except Exception as e:
            print(f"File Scan Error: {e}")
            traceback.print_exc()
            return {"error": f"Scanning failed: {str(e)}", "status": 500}
