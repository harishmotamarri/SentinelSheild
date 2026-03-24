import os
import requests
import json
import re
from io import BytesIO
from services.report_generator import ReportGenerator

class WhatsAppService:
    def __init__(self, access_token, phone_number_id, verify_token, scanners):
        self.access_token = access_token
        self.phone_number_id = phone_number_id
        self.verify_token = verify_token
        self.scanners = scanners # Dict containing initialized scanner services
        self.api_url = f"https://graph.facebook.com/v17.0/{self.phone_number_id}/messages"
        self.media_url_base = "https://graph.facebook.com/v17.0/"

    def verify_webhook(self, args):
        """Verifies the webhook for Meta Cloud API."""
        mode = args.get('hub.mode')
        token = args.get('hub.verify_token')
        challenge = args.get('hub.challenge')

        if mode and token:
            if mode == 'subscribe' and token == self.verify_token:
                print("Webhook Verified Successfully.")
                return challenge, 200
            else:
                return "Verification Failed", 403
        return "Invalid Request", 400

    def handle_webhook(self, data):
        """Processes incoming messages from Meta Webhook."""
        try:
            entry = data.get('entry', [])[0]
            change = entry.get('changes', [])[0]
            value = change.get('value', {})
            message = value.get('messages', [])[0]
            
            from_number = message.get('from')
            msg_type = message.get('type')
            
            print(f"DEBUG: Received WhatsApp message of type {msg_type} from {from_number}")

            if msg_type == 'text':
                body = message.get('text', {}).get('body')
                self.process_text_message(from_number, body)
            
            elif msg_type == 'image':
                media_id = message.get('image', {}).get('id')
                self.process_media(from_number, media_id, 'QR')
                
            elif msg_type == 'document':
                doc = message.get('document', {})
                media_id = doc.get('id')
                filename = doc.get('filename', 'unknown_file')
                self.process_media(from_number, media_id, 'File', filename)

            return "OK", 200
        except Exception as e:
            print(f"WhatsApp Webhook Error: {e}")
            return "Error", 500

    def process_text_message(self, from_number, text):
        """Analyzes text input (URL, Domain, or Message)."""
        # 1. Check if it's a URL
        url_pattern = re.compile(r'https?://[^\s]+')
        urls = url_pattern.findall(text)
        
        if urls:
            url = urls[0]
            print(f"DEBUG: Scanning URL from WhatsApp: {url}")
            result = self.scanners['url'].scan_url(url)
            report = ReportGenerator.format_scan_report('URL Scanner', url, result)
            self.send_message(from_number, report)
        
        # 2. Check if it's a domain (simple check)
        elif re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$', text.strip()):
            domain = text.strip()
            print(f"DEBUG: Checking Domain from WhatsApp: {domain}")
            result = self.scanners['domain'].check_domain(domain)
            report = ReportGenerator.format_scan_report('Domain Integrity', domain, result)
            self.send_message(from_number, report)
            
        # 3. Otherwise, treat as an SMS/Message content scan
        else:
            print(f"DEBUG: Analyzing text content from WhatsApp")
            result = self.scanners['sms'].analyze_sms(text)
            report = ReportGenerator.format_scan_report('Threat Analysis', text, result)
            self.send_message(from_number, report)

    def process_media(self, from_number, media_id, scan_type, filename=None):
        """Handles downloading and scanning media files."""
        try:
            media_url = self._get_media_url(media_id)
            media_content = self._download_media(media_url)
            
            if not media_content:
                self.send_message(from_number, "❌ Failed to download media for scanning.")
                return

            file_stream = BytesIO(media_content)
            
            if scan_type == 'QR':
                result = self.scanners['qr'].scan_qr(file_stream)
                # If QR contains a URL and was scanned, format accordingly
                content = result.get('content', 'Unknown Data')
                threat = result.get('threat_analysis')
                if threat:
                    report = ReportGenerator.format_scan_report('QR Link Scanner', content, threat)
                else:
                    report = f"📸 *QR Code Decoded*\n\n*Content:* {content}\n\n_No threat analysis performed as it wasn't a URL._"
                self.send_message(from_number, report)
                
            elif scan_type == 'File':
                result = self.scanners['file'].analyze_file(file_stream, filename)
                report = ReportGenerator.format_scan_report('File Security', filename, result)
                self.send_message(from_number, report)

        except Exception as e:
            print(f"Media Processing Error: {e}")
            self.send_message(from_number, f"❌ An error occurred during media analysis: {str(e)}")

    def send_message(self, to_number, text):
        """Sends a text message back to the user via Meta API."""
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "messaging_product": "whatsapp",
            "to": to_number,
            "type": "text",
            "text": { "body": text }
        }
        try:
            response = requests.post(self.api_url, headers=headers, json=payload)
            response.raise_for_status()
            print(f"DEBUG: Message sent to {to_number}")
        except Exception as e:
            print(f"Error sending WhatsApp message: {e}")

    def _get_media_url(self, media_id):
        """Fetches the actual media download URL from Meta."""
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = requests.get(f"{self.media_url_base}{media_id}", headers=headers)
        response.raise_for_status()
        return response.json().get('url')

    def _download_media(self, url):
        """Downloads the media file content."""
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.content
