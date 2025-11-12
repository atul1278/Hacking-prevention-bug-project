from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_socketio import SocketIO
from flask_wtf import CSRFProtect
import logging

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()
mail = Mail()
socketio = SocketIO(cors_allowed_origins="*")  # SocketIO with CORS support
csrf = CSRFProtect()

# Set up logging configuration
def setup_logging(app):
    """Set up the logging configuration."""
    log_level = app.config.get('LOGGING_LEVEL', 'DEBUG').upper()
    logging.basicConfig(level=log_level,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)

    # File handler for logging to a file
    log_file = app.config.get('LOG_FILE', 'app.log')
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))

    app.logger.addHandler(file_handler)

    return app.logger

# Setup function to initialize the app with extensions
def init_extensions(app):
    """Initialize extensions with the Flask app."""
    db.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    socketio.init_app(app)
    csrf.init_app(app)

    # Set up logging
    app.logger = setup_logging(app)

    return app
