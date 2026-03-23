import cv2
import numpy as np
from PIL import Image
import io
import traceback

class QrService:
    def __init__(self, url_service=None):
        self.url_service = url_service
        self.detector = cv2.QRCodeDetector()

    def scan_qr(self, image_file):
        """
        Decodes a QR code from an image file stream.
        Returns a dictionary with result and optionally threat analysis if it's a URL.
        """
        try:
            # Read image from stream
            image_bytes = image_file.read()
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            if img is None:
                return {"error": "Could not decode image", "status": 400}

            # Detect and decode
            data, points, straight_qrcode = self.detector.detectAndDecode(img)

            if not data:
                return {"error": "No QR code detected in the image", "status": 404}

            result = {
                "content": data,
                "is_url": False
            }

            # Check if it's a URL
            if data.startswith(('http://', 'https://')):
                result["is_url"] = True
                if self.url_service:
                    print(f"QR content is a URL: {data}. Running threat scan...")
                    url_scan_result = self.url_service.scan_url(data)
                    result["threat_analysis"] = url_scan_result

            return result

        except Exception as e:
            print(f"QR Scan Error: {e}")
            traceback.print_exc()
            return {"error": f"QR scanning failed: {str(e)}", "status": 500}
