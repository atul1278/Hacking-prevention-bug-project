from flask_bcrypt import Bcrypt  
from extensions import db  # shared instance from extensions.py
from datetime import datetime
from sqlalchemy.orm import validates
from flask_security import RoleMixin

bcrypt = Bcrypt()  # Will be initialized in app.py

# -------------------- Role Model --------------------
class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __repr__(self):
        return f"<Role {self.name}>"

# -------------------- User Model with Roles --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    roles = db.relationship('Role', secondary='user_roles')

    @staticmethod
    def hash_password(password):
        """Hash the password using bcrypt"""
        return bcrypt.generate_password_hash(password).decode('utf-8')

    @staticmethod
    def check_password(hashed_password, password):
        """Check if the given password matches the hashed password"""
        return bcrypt.check_password_hash(hashed_password, password)

    @validates('email')
    def validate_email(self, key, email):
        """Ensure email format is valid"""
        if '@' not in email:
            raise ValueError("Invalid email format.")
        return email

    def __repr__(self):
        return f"<User {self.name}>"

# -------------------- UserRoles (Many-to-Many Relationship) --------------------
class UserRoles(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete="CASCADE"), primary_key=True)

# -------------------- Report Model --------------------
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    screenshot = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(50), default="Pending")

    @validates('email')
    def validate_email(self, key, email):
        """Ensure email format is valid"""
        if '@' not in email:
            raise ValueError("Invalid email format.")
        return email

# -------------------- ThreatLog Model --------------------
class ThreatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    url = db.Column(db.String(500), nullable=False)
    threats = db.Column(db.Text, nullable=False)  # comma-separated list of threats
    severity = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    details = db.Column(db.Text, nullable=True)  # Additional info about the log

    user = db.relationship('User', backref=db.backref('threat_logs', lazy=True))

    @validates('url')
    def validate_url(self, key, url):
        """Ensure the URL is valid"""
        if not url.startswith("http"):
            raise ValueError("Invalid URL format. URL must start with 'http' or 'https'.")
        return url

    @validates('threats')
    def validate_threats(self, key, threats):
        """Ensure that threats are properly formatted (comma-separated values)"""
        threats_list = threats.split(',')
        if not all(isinstance(threat.strip(), str) for threat in threats_list):
            raise ValueError("Threats should be a comma-separated list of strings.")
        return threats

    # Method to export threat logs to a dictionary (for CSV/JSON/PDF export)
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'url': self.url,
            'threats': self.threats,
            'severity': self.severity,
            'timestamp': self.timestamp,
            'details': self.details,
        }

    def __repr__(self):
        return f"<ThreatLog {self.url}>"

# -------------------- Optional: For CSV Export --------------------
def export_logs_to_csv():
    """Export all threat logs to a CSV file."""
    logs = ThreatLog.query.all()
    
    # Prepare CSV content
    headers = ['ID', 'User ID', 'URL', 'Threats', 'Severity', 'Timestamp', 'Details']
    rows = [log.to_dict().values() for log in logs]
    
    # Path to save the CSV file
    export_file_path = 'exports/threat_logs.csv'

    # Writing CSV to file
    import csv
    with open(export_file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)
    
    return export_file_path

# -------------------- Optional: For PDF Export --------------------
def export_logs_to_pdf():
    """Export all threat logs to a PDF file."""
    from fpdf import FPDF

    # Get all threat logs from database
    logs = ThreatLog.query.all()

    # Create PDF instance
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 12)

    # Title
    pdf.cell(200, 10, txt="Threat Logs", ln=True, align='C')
    pdf.ln(10)

    # Add log entries
    for log in logs:
        log_data = log.to_dict()
        pdf.cell(200, 10, txt=f"ID: {log_data['id']} | URL: {log_data['url']} | Severity: {log_data['severity']}", ln=True)
        pdf.multi_cell(200, 10, txt=f"Threats: {log_data['threats']}")
        pdf.multi_cell(200, 10, txt=f"Timestamp: {log_data['timestamp']}")
        pdf.multi_cell(200, 10, txt=f"Details: {log_data['details']}")
        pdf.ln(5)

    # Path to save PDF
    export_file_path = 'exports/threat_logs.pdf'
    pdf.output(export_file_path)

    return export_file_path
