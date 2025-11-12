from flask import Flask, jsonify, request, send_file, render_template ,request, redirect,flash,url_for
from flask_cors import CORS
from config import Config
from extensions import db, jwt, mail
from models import bcrypt, ThreatLog
from routes import auth_bp
from flask_socketio import SocketIO, emit
from flask_jwt_extended import jwt_required
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFProtect
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import BadRequest
from functools import wraps
from datetime import datetime
from io import StringIO, BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from forms import ContactForm
from routes import api
import logging
import csv
import os

# Load environment variables
load_dotenv()

# App initialization
app = Flask(__name__)
app.config.from_object(Config)

# Email setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
CORS(app, supports_credentials=True)
db.init_app(app)
bcrypt.init_app(app)
jwt.init_app(app)
mail.init_app(app)

# ✅ Add this BEFORE initializing CSRF
app.config['WTF_CSRF_ENABLED'] = False

# Initialize CSRF protection
csrf = CSRFProtect()
csrf.init_app(app)


# Initialize SocketIO (with threading mode)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Initialize Limiter
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Setup logging
logging.basicConfig(level=logging.INFO)

@app.before_request
def log_request():
    logging.info(f"Request received: {request.method} {request.url} from {request.remote_addr}")

# Register blueprints
app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(api)

# Create tables
with app.app_context():
    db.create_all()

# ─────────────────────────────────────────────────────────────
# Helper: Admin-only access
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        from flask_jwt_extended import get_jwt
        claims = get_jwt()
        if not claims.get('is_admin', False):
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper

# ─────────────────────────────────────────────────────────────
# WebSocket: Connect event
@socketio.on('connect')
def handle_connect():
    print("Client connected")
    emit('connected', {'message': 'WebSocket connected'})

# WebSocket: New log broadcast
@socketio.on('new_log')
def handle_new_log(data):
    emit('log_added', {'log': data}, broadcast=True)

# ─────────────────────────────────────────────────────────────
# Export logs to CSV
@app.route('/api/export/csv', methods=['GET'])
@limiter.limit("10 per minute")
@jwt_required()
@admin_required
def export_csv():
    try:
        logs = ThreatLog.query.all()
        if not logs:
            return jsonify({"error": "No logs found"}), 404

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Name', 'Email', 'Message', 'Status', 'Severity', 'Timestamp'])
        for log in logs:
            writer.writerow([log.id, log.name, log.email, log.message, log.status, log.severity, log.timestamp])

        output.seek(0)
        return send_file(output, mimetype='text/csv', as_attachment=True, download_name="threat_logs.csv")
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────────────────────
# Export logs to PDF
@app.route('/api/export/pdf', methods=['GET'])
@jwt_required()
@admin_required
def export_pdf():
    try:
        logs = ThreatLog.query.all()
        if not logs:
            return jsonify({"error": "No logs found"}), 404

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.setFont("Helvetica", 12)
        y = 750
        c.drawString(100, y, "Threat Logs")
        y -= 20

        for log in logs:
            c.drawString(100, y, f"{log.id} | {log.name} | {log.email} | {log.message} | {log.status} | {log.severity} | {log.timestamp}")
            y -= 20
            if y < 100:
                c.showPage()
                y = 750

        c.save()
        buffer.seek(0)
        return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name="threat_logs.pdf")

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────────────────────
# Get logs by date range (paginated)
@app.route('/api/logs', methods=['GET'])
@limiter.limit("20 per minute")
@jwt_required()
def get_logs_by_date():
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))

        if not start_date or not end_date:
            raise BadRequest("Please provide both start_date and end_date in 'YYYY-MM-DD' format")

        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d')

        logs = ThreatLog.query.filter(ThreatLog.timestamp >= start_date,
                                      ThreatLog.timestamp <= end_date) \
                              .paginate(page=page, per_page=per_page, error_out=False)

        logs_data = [{
            "id": log.id,
            "name": log.name,
            "email": log.email,
            "message": log.message,
            "status": log.status,
            "severity": log.severity,
            "timestamp": log.timestamp
        } for log in logs.items]

        return jsonify({
            "total": logs.total,
            "pages": logs.pages,
            "current_page": logs.page,
            "logs": logs_data
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# ─────────────────────────────────────────────────────────────    
app.secret_key = 'THIS_IS_SECRET_KEY' 
   
app.config['RECAPTCHA_PUBLIC_KEY'] ='6LeNRjQrAAAAADXTcmjuc1zTf3p9sp_ZtYXWcLbO'
app.config['RECAPTCHA_PRIVATE_KEY'] ='6LeNRjQrAAAAAMCrCKmQ-BxDRVuBhsXyO_smyZxM' 

@app.route('/contact',methods=['GET','POST'])
def contact():
    form = ContactForm()
    
    if request.method =='POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
      # add server -side validation or processing here
        flash('Thank you for submitting you message!')
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)
      
    
    

# ─────────────────────────────────────────────────────────────
# Start the app
if __name__ == '__main__':
   socketio.run(app, debug=True, host='0.0.0.0', port=5000)