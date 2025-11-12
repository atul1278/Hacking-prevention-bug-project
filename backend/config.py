import os
from dotenv import load_dotenv  # Load environment variables from .env file

# Load environment variables
load_dotenv()

class Config:
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', 'sqlite:///db.sqlite')  # Default to SQLite if not set
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your_default_jwt_secret')  # Fallback to a default value if not set
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))  # 1 hour expiration default

    # Mail configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')  # Fallback to Gmail if not set
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))  # Fallback to 587 if not set
    MAIL_USE_TLS = bool(os.getenv('MAIL_USE_TLS', True))  # Default to True if not set
    MAIL_USE_SSL = bool(os.getenv('MAIL_USE_SSL', False))  # Default to False if not set
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')  # Ensure you set this in .env
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')  # Ensure you set this in .env
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', MAIL_USERNAME)  # Default to MAIL_USERNAME if not set

    # File Uploads configuration
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')  # Default upload folder
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image formats
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB limit by default

    # File Exports configuration (for CSV, PDF)
    EXPORT_FOLDER = os.getenv('EXPORT_FOLDER', 'exports')  # Folder for exported files
    os.makedirs(EXPORT_FOLDER, exist_ok=True)  # Ensure export folder exists

    # Secret Key for CSRF protection, session management, etc.
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')  # For CSRF or other security features

    # Logging configuration
    LOGGING_LEVEL = os.getenv('LOGGING_LEVEL', 'DEBUG')  # Set default log level if not set
    LOGGING_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOGGING_FILE = os.getenv('LOGGING_FILE', 'app.log')  # Log to a file by default

    # Set up logging
    if LOGGING_FILE:
        LOGGING_PATH = os.path.join(os.getcwd(), LOGGING_FILE)
    else:
        LOGGING_PATH = None

    # Application name for branding
    APP_NAME = os.getenv('APP_NAME', 'Web Security Scanner')

    # Flask-SocketIO configuration for event handling
    SOCKETIO_MESSAGE_QUEUE = os.getenv('SOCKETIO_MESSAGE_QUEUE', None)  # For scaling across multiple workers if needed
    SOCKETIO_ALLOW_CORS = os.getenv('SOCKETIO_ALLOW_CORS', 'false').lower() == 'true'

    # Rate Limiting Configuration (for DoS/DDoS Protection)
    RATE_LIMIT = os.getenv('RATE_LIMIT', '100/hour')  # Default rate limit is 100 requests per hour

    # Enable/Disable Debug mode
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'

    # Security Configurations (e.g., Content Security Policy)
    CSP_POLICY = os.getenv('CSP_POLICY', 'default-src \'self\'')
    CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data:",
    }

    # Logging configuration for Flask to a file (enhanced)
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'default': {
                'format': LOGGING_FORMAT
            },
        },
        'handlers': {
            'file': {
                'level': LOGGING_LEVEL,
                'class': 'logging.FileHandler',
                'filename': LOGGING_PATH,
                'formatter': 'default'
            },
        },
        'loggers': {
            'flask': {
                'handlers': ['file'],
                'level': LOGGING_LEVEL,
                'propagate': False,
            },
        }
    }

    # Enable HTTPS for production (default to False for development)
    USE_HTTPS = os.getenv('USE_HTTPS', 'False').lower() == 'true'
    
    # Flask CORS Configuration (for cross-origin resource sharing settings)
    CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS', '*')  # Default to all origins for now
