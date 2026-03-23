from flask import Flask, request, jsonify, render_template
import os
import traceback
from dotenv import load_dotenv

from services.url_service import UrlService
from services.email_service import EmailService
from services.sms_service import SmsService
from services.file_service import FileService
from services.web_service import WebService
from services.qr_service import QrService
from services.domain_service import DomainService

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Basic CORS via after_request
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# --- Model Paths ---
URL_MODEL_PATH = os.path.join('model', 'url.pkl')
EMAIL_MODEL_PATH = os.path.join('model', 'email.pkl')
EMAIL_VECTORIZER_PATH = os.path.join('model', 'email_vectorizer.pkl')
SMS_MODEL_PATH = os.path.join('model', 'sms_model (1).pkl')
SMS_VECTORIZER_PATH = os.path.join('model', 'sms_vectorizer (1).pkl')

# --- Service Instances ---
url_service = None
email_service = None
sms_service = None
file_service = None
web_service = None
qr_service = None
domain_service = None

# --- Initialize All Services ---
try:
    print("Initializing Services...")
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")

    if not GROQ_API_KEY:
        print("WARNING: GROQ_API_KEY not set. AI analysis features will be disabled.")

    url_service = UrlService(URL_MODEL_PATH, api_key=GROQ_API_KEY)
    email_service = EmailService(EMAIL_MODEL_PATH, EMAIL_VECTORIZER_PATH, api_key=GROQ_API_KEY)
    sms_service = SmsService(SMS_MODEL_PATH, SMS_VECTORIZER_PATH, api_key=GROQ_API_KEY)
    file_service = FileService(GROQ_API_KEY)
    web_service = WebService(GROQ_API_KEY)
    qr_service = QrService(url_service)
    domain_service = DomainService(GROQ_API_KEY)
    print("Services Initialized Successfully.")
except Exception as e:
    print(f"FATAL: Service Initialization Failed: {e}")
    traceback.print_exc()

# --- Page Routes ---

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard.html')
def dashboard():
    return render_template('dashboard.html')

@app.route('/login.html')
def login():
    return render_template('login.html')

@app.route('/signup.html')
def signup():
    return render_template('signup.html')

# --- API Endpoints ---

@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    if not url_service or not url_service.model:
        return jsonify({'error': 'URL Analysis Service Unavailable'}), 503

    try:
        data = request.json
        if not data or 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400

        result = url_service.scan_url(data['url'])

        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status', 500)

        return jsonify(result)

    except Exception as e:
        print(f"[scan-url] Error: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    if not email_service or not email_service.model:
        return jsonify({'error': 'Email Analysis Service Unavailable'}), 503

    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'Missing "text" field'}), 400

        text = data['text']
        if not isinstance(text, str) or not text.strip():
            return jsonify({'error': 'Email text must be a non-empty string'}), 400

        return jsonify(email_service.analyze_email(text))

    except Exception as e:
        print(f"[analyze-email] Error: {e}")
        return jsonify({'error': f"Analysis failed: {str(e)}"}), 500


@app.route('/api/scan-sms', methods=['POST'])
def scan_sms():
    if not sms_service or not sms_service.model:
        return jsonify({'error': 'SMS Analysis Service Unavailable'}), 503

    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'Missing "text" field'}), 400

        text = data['text']
        if not isinstance(text, str) or not text.strip():
            return jsonify({'error': 'SMS text must be a non-empty string'}), 400

        return jsonify(sms_service.analyze_sms(text))

    except Exception as e:
        print(f"[scan-sms] Error: {e}")
        return jsonify({'error': f"Analysis failed: {str(e)}"}), 500


@app.route('/api/scan-file', methods=['POST'])
def scan_file():
    if not file_service:
        return jsonify({'error': 'File Analysis Service Unavailable'}), 503

    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        result = file_service.analyze_file(file, file.filename)
        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status', 500)

        return jsonify(result)

    except Exception as e:
        print(f"[scan-file] Error: {e}")
        return jsonify({'error': f"Analysis failed: {str(e)}"}), 500


@app.route('/api/inspect-web', methods=['POST'])
def inspect_web():
    if not web_service:
        return jsonify({'error': 'Web Inspection Service Unavailable'}), 503

    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'No URL provided in JSON payload'}), 400

        url = data['url']
        if not url or not isinstance(url, str):
            return jsonify({'error': 'Invalid URL provided'}), 400

        result = web_service.inspect_website(url)
        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status', 500)

        return jsonify(result)

    except Exception as e:
        print(f"[inspect-web] Error: {e}")
        return jsonify({'error': f"Web inspection failed: {str(e)}"}), 500


@app.route('/api/scan-qr', methods=['POST'])
def scan_qr():
    if not qr_service:
        return jsonify({'error': 'QR Analysis Service Unavailable'}), 503

    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No QR image provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        result = qr_service.scan_qr(file)
        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status', 500)

        return jsonify(result)

    except Exception as e:
        print(f"[scan-qr] Error: {e}")
        return jsonify({'error': f"QR analysis failed: {str(e)}"}), 500


@app.route('/api/check-domain', methods=['POST'])
def check_domain():
    if not domain_service:
        return jsonify({'error': 'Domain Check Service Unavailable'}), 503

    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({'error': 'No domain provided'}), 400

        domain = data['domain']
        if not domain or not isinstance(domain, str):
            return jsonify({'error': 'Invalid domain provided'}), 400

        result = domain_service.check_domain(domain)
        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status', 500)

        return jsonify(result)

    except Exception as e:
        print(f"[check-domain] Error: {e}")
        return jsonify({'error': f"Domain check failed: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
