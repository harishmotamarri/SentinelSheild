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
from services.database_service import DatabaseService

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Basic CORS via after_request
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-User-Id')
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
db_service = None

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
    
    # Initialize Database
    db_service = DatabaseService()
    
    print("Services Initialized Successfully.")
except Exception as e:
    print(f"FATAL: Service Initialization Failed: {e}")
    traceback.print_exc()

# --- Helper to Log Scans ---
def _log_to_db(scan_type, input_data, result_dict):
    user_id = request.headers.get('X-User-Id')
    if user_id and db_service:
        # Determine the best result string to store
        # 1. Look for 'result' or 'label'
        # 2. For QR, if it's a URL and has threat_analysis, use that result
        result_str = result_dict.get('result') or result_dict.get('label')
        
        if scan_type == 'QR':
            content = result_dict.get('content', '')
            threat = result_dict.get('threat_analysis')
            if threat and isinstance(threat, dict):
                result_str = threat.get('result') or threat.get('label') or 'Link Detected'
            else:
                result_str = 'Decoded Content'
            input_data = f"QR: {content}"[:500]

        db_service.log_scan(
            user_id=user_id,
            scan_type=scan_type,
            input_data=input_data,
            result=result_str or 'Unknown',
            confidence=result_dict.get('confidence') or (result_dict.get('threat_analysis', {}).get('confidence') if isinstance(result_dict.get('threat_analysis'), dict) else 0.0) or 0.0,
            reason=result_dict.get('reason') or (result_dict.get('threat_analysis', {}).get('reason') if isinstance(result_dict.get('threat_analysis'), dict) else '') or ''
        )

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

# --- Auth Endpoints ---

@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    if not db_service:
        return jsonify({'error': 'Database service unavailable'}), 503
    
    data = request.json
    print(f"DEBUG: Signup request data: {data}")
    
    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name')
    
    if not email or not password:
        print(f"DEBUG: Missing email ({email}) or password ({'set' if password else 'missing'})")
        return jsonify({'error': 'Email and password required'}), 400
        
    result = db_service.signup(email, password, full_name)
    if 'error' in result:
        return jsonify(result), 400
    
    # Supabase user/session objects aren't directly JSON serializable usually
    # Return IDs and tokens
    return jsonify({
        "message": "Signup successful",
        "user_id": result['user'].id,
        "email": result['user'].email
    })

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    if not db_service:
        return jsonify({'error': 'Database service unavailable'}), 503
    
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    result = db_service.login(email, password)
    if 'error' in result:
        print(f"DEBUG: Login failed: {result['error']}")
        return jsonify(result), 401
    
    return jsonify({
        "message": "Login successful",
        "user_id": result['user'].id,
        "access_token": result['session'].access_token
    })

# --- API Scan Endpoints ---
# Consolidated dashboard stats for home charts and recent list
@app.route('/api/dashboard-stats', methods=['GET'])
def get_dashboard_stats_api():
    user_id = request.headers.get('X-User-Id')
    if not user_id:
        return jsonify({"error": "User ID missing"}), 401
    
    if not db_service:
        return jsonify({"error": "Database service not initialized"}), 500
        
    stats = db_service.get_dashboard_stats(user_id)
    return jsonify(stats)

@app.route('/api/user-scans', methods=['GET'])
def get_scans():
    user_id = request.args.get('user_id') or request.headers.get('X-User-Id')
    if not user_id or not db_service:
        return jsonify({'error': 'User ID missing or DB unavailable'}), 400
    
    scans = db_service.get_user_scans(user_id)
    return jsonify(scans)

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

        _log_to_db('URL', data['url'], result)
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

        result = email_service.analyze_email(text)
        _log_to_db('Email', text[:50], result)
        return jsonify(result)

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

        result = sms_service.analyze_sms(text)
        _log_to_db('SMS', text[:50], result)
        return jsonify(result)

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

        _log_to_db('File', file.filename, result)
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

        _log_to_db('Web', url, result)
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

        _log_to_db('QR', file.filename, result)
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

        _log_to_db('Domain', domain, result)
        return jsonify(result)

    except Exception as e:
        print(f"[check-domain] Error: {e}")
        return jsonify({'error': f"Domain check failed: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
