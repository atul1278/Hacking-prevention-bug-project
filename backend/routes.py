from flask import Blueprint, request, jsonify, make_response, current_app
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from extensions import csrf
from flask_mail import Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
from io import StringIO
import re
import requests
import csv

from extensions import db, mail, socketio
from models import User, ThreatLog
from forms import ContactForm

auth_bp = Blueprint('auth', __name__)
api = Blueprint('api', __name__)
limiter = Limiter(key_func=get_remote_address)



# ---------------------- Helper Functions ---------------------- #
def send_welcome_email(user_email, user_name):
    try:
        msg = Message(
            subject='Welcome to Web Security Scanner!',
            sender=current_app.config.get('MAIL_USERNAME'),
            recipients=[user_email]
        )
        msg.body = f"""Hello {user_name},

✅ Your registration to Web Security Scanner was successful!

Explore vulnerabilities, track logs, and stay secure. 💻🛡️

Thanks,
Web Security Scanner Team"""
        mail.send(msg)
    except Exception as e:
        current_app.logger.error(f"⚠️ Email not sent: {e}")

def check_input_data(data, required_fields):
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return jsonify({'error': f'Missing fields: {", ".join(missing_fields)}'}), 400
    return None

def validate_url(url):
    url_regex = re.compile(r'^(https?|ftp)://[^\s/$.?#].[^\s]*$')
    if not re.match(url_regex, url):
        return jsonify({'error': 'Invalid URL format'}), 400
    return None

def is_admin(user_id):
    user = User.query.get(user_id)
    return getattr(user, 'is_admin', False)

# ---------------------- Register API ---------------------- #
@auth_bp.route('/register', methods=['POST'])
@csrf.exempt
def register():
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400

        data = request.get_json()
        validation_error = check_input_data(data, ['name', 'email', 'password'])
        if validation_error:
            return validation_error

        name, email, password = data['name'], data['email'], data['password']

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400

        hashed_password = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        send_welcome_email(email, name)

        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        current_app.logger.error(f"⚠️ Registration error: {e}")
        return jsonify({'error': 'Server error'}), 500

# ---------------------- Login API ---------------------- #
@auth_bp.route('/login', methods=['POST'])
@csrf.exempt
def login():
    try:
        data = request.get_json()
        validation_error = check_input_data(data, ['email', 'password'])
        if validation_error:
            return validation_error

        email, password = data['email'], data['password']
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            return jsonify({'error': 'Invalid credentials'}), 401

        token = create_access_token(identity=user.id)
        return jsonify({'access_token': token, 'message': 'Login successful'}), 200
    except Exception as e:
        current_app.logger.error(f"⚠️ Login error: {e}")
        return jsonify({'error': 'Server error'}), 500

# ---------------------- Scan API ---------------------- #
@auth_bp.route('/scan', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
def scan():
    try:
        # Validate and parse JSON payload
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Missing or invalid JSON data'}), 422

        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'Missing "url" field in JSON'}), 422

        validation_error = validate_url(url)
        if validation_error:
            return validation_error

        # Initialize threat detection
        issues = []
        severity = "Low"

        sql_patterns = [
            r"(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b)",
            r"('|--|;|#)",
            r"\bOR\b\s+\d+=\d+",
            r"\b1\s*=\s*1\b"
        ]
        xss_patterns = [
            r"<script.*?>.*?</script>",
            r"on\w+=['\"].*?['\"]",
            r"javascript:"
        ]

        # Pattern matching for threats
        if any(re.search(p, url, re.IGNORECASE) for p in sql_patterns):
            issues.append("SQL Injection")
            severity = "High"
        if any(re.search(p, url, re.IGNORECASE) for p in xss_patterns):
            issues.append("XSS Attack")
            if severity != "High":
                severity = "Medium"

        try:
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                issues.append("Possible DoS/DDoS Attack")
                if severity != "High":
                    severity = "Medium"
        except requests.RequestException:
            issues.append("Unreachable site - Possible DoS/DDoS")
            if severity != "High":
                severity = "Medium"

        # Log threat in the database
        timestamp = datetime.now()
        user_id = get_jwt_identity()
        new_log = ThreatLog(
            user_id=user_id,
            url=url,
            threats=", ".join(issues) if issues else "None",
            severity=severity if issues else "None",
            timestamp=timestamp,
            details=str({
                "url": url,
                "issues_detected": issues,
                "severity": severity,
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })
        )
        db.session.add(new_log)
        db.session.commit()

        # Emit real-time log to frontend
        socketio.emit("new_threat_log", {
            "id": new_log.id,
            "url": new_log.url,
            "threats": new_log.threats,
            "severity": new_log.severity,
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })

        # Return response
        return jsonify({
            "message": "⚠️ Threats detected" if issues else "✅ No known vulnerabilities detected.",
            "card": {
                "id": new_log.id,
                "url": new_log.url,
                "threats": issues if issues else ["None"],
                "severity": severity,
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S")
            }
        }), 400 if issues else 200

    except Exception as e:
        current_app.logger.error(f"⚠️ Scan error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ---------------------- Get Logs (with Filtering) ---------------------- #
@csrf.exempt
@auth_bp.route('/logs', methods=['GET'])
@jwt_required()
def get_logs():
    try:
        user_id = get_jwt_identity()
        admin = is_admin(user_id)

        start_date = request.args.get('start')
        end_date = request.args.get('end')

        query = ThreatLog.query
        if not admin:
            query = query.filter_by(user_id=user_id)
        if start_date:
            query = query.filter(ThreatLog.timestamp >= datetime.fromisoformat(start_date))
        if end_date:
            query = query.filter(ThreatLog.timestamp <= datetime.fromisoformat(end_date))

        logs = query.order_by(ThreatLog.timestamp.desc()).all()
        return jsonify([{
            "id": log.id,
            "url": log.url,
            "threats": log.threats.split(', '),
            "severity": log.severity,
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        } for log in logs]), 200
    except Exception as e:
        current_app.logger.error(f"⚠️ Log fetch error: {e}")
        return jsonify({'error': 'Server error'}), 500

# ---------------------- Export Logs as CSV ---------------------- #
@auth_bp.route('/logs/export', methods=['GET'])
@jwt_required()
def export_logs():
    try:
        user_id = get_jwt_identity()
        admin = is_admin(user_id)

        start_date = request.args.get('start')
        end_date = request.args.get('end')

        query = ThreatLog.query
        if not admin:
            query = query.filter_by(user_id=user_id)
        if start_date:
            query = query.filter(ThreatLog.timestamp >= datetime.fromisoformat(start_date))
        if end_date:
            query = query.filter(ThreatLog.timestamp <= datetime.fromisoformat(end_date))

        logs = query.order_by(ThreatLog.timestamp.desc()).all()

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "URL", "Threats", "Severity", "Timestamp"])
        for log in logs:
            writer.writerow([log.id, log.url, log.threats, log.severity, log.timestamp.strftime("%Y-%m-%d %H:%M:%S")])

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=threat_logs.csv"
        response.headers["Content-type"] = "text/csv"
        return response
    except Exception as e:
        current_app.logger.error(f"⚠️ Log export error: {e}")
        return jsonify({'error': 'Server error'}), 500

# ---------------------- Contact Form ---------------------- #
@auth_bp.route('/contact', methods=['POST'])
@csrf.exempt  # Exempt CSRF for this route
def contact():
    try:
        form = ContactForm(request.form)
        if form.validate():
            name = form.name.data
            email = form.email.data
            message = form.message.data

            # reCAPTCHA validation
            recaptcha_response = request.form.get('g-recaptcha-response')
            if not recaptcha_response:
                return jsonify({'error': 'reCAPTCHA verification failed'}), 400

            recaptcha_secret = current_app.config.get('RECAPTCHA_SECRET_KEY')
            recaptcha_payload = {
                'secret': recaptcha_secret,
                'response': recaptcha_response
            }
            recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
            recaptcha_result = requests.post(recaptcha_url, data=recaptcha_payload).json()

            if not recaptcha_result.get('success'):
                return jsonify({'error': 'Invalid reCAPTCHA'}), 400

            # Send contact email to admin
            msg = Message(
                subject="📬 New Contact Form Submission",
                sender=current_app.config.get('MAIL_USERNAME'),
                recipients=[current_app.config.get('ADMIN_EMAIL')]
            )
            msg.body = f"""
📢 New Contact Request Received

From: {name} <{email}>

Message:
{message}

📅 Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            mail.send(msg)
            return jsonify({'message': 'Thank you for contacting us!'}), 200
        else:
            return jsonify({'error': 'Invalid form submission'}), 400
    except Exception as e:
        current_app.logger.error(f"⚠️ Contact form error: {e}")
        return jsonify({'error': 'Server error'}), 500
