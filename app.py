from flask import Flask, request, jsonify, render_template, make_response
import os
import traceback

from services.url_service import UrlService
from services.email_service import EmailService

app = Flask(__name__)

# Basic CORS via after_request
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Initialize Services
URL_MODEL_PATH = os.path.join('model', 'url.pkl')
EMAIL_MODEL_PATH = os.path.join('model', 'email.pkl')
EMAIL_VECTORIZER_PATH = os.path.join('model', 'email_vectorizer.pkl')

url_service = None
email_service = None

try:
    print("Initializing Services...")
    url_service = UrlService(URL_MODEL_PATH)
    email_service = EmailService(EMAIL_MODEL_PATH, EMAIL_VECTORIZER_PATH)
    print("Services Initialized Successfully.")
except Exception as e:
    print(f"FATAL: Service Initialization Failed: {e}")
    traceback.print_exc()

# --- Routes ---

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

# API Endpoints

@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    if not url_service or not url_service.model:
        return jsonify({'error': 'URL Analysis Service Unavailable'}), 503

    try:
        data = request.json
        if not data or 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400
            
        url = data['url']
        result = url_service.scan_url(url)
        
        if 'error' in result:
             status = result.get('status', 500)
             return jsonify({'error': result['error']}), status
             
        return jsonify(result)

    except Exception as e:
        print(f"Endpoint Error: {e}")
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
        return jsonify(result)
        
    except Exception as e:
        print(f"Endpoint Error: {e}")
        return jsonify({'error': f"Analysis failed: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
