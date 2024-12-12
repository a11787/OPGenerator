from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import pyodbc
import json
import csv
from io import StringIO
from flask_wtf.csrf import CSRFProtect
import logging
from logging.handlers import RotatingFileHandler
import os
import secrets
from dotenv import load_dotenv
from flask_restful import Api, Resource, reqparse
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from flask_apispec.extension import FlaskApiSpec
from flask_apispec.views import MethodResource
from flask_apispec import marshal_with, doc, use_kwargs
from marshmallow import Schema, fields
import io
import csv
from flask import Response
import socket
import re
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
import time
from urllib.parse import urlparse, urljoin

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY') or secrets.token_hex(32)
csrf = CSRFProtect(app)

# Set up logging
LOG_FORMAT = '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s'
JSON_LOG_FORMAT = {
    'timestamp': '%(asctime)s',
    'level': '%(levelname)s',
    'logger': '%(name)s',
    'message': '%(message)s',
    'path': '%(pathname)s',
    'line': '%(lineno)d',
    'function': '%(funcName)s'
}

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {}
        for k, v in JSON_LOG_FORMAT.items():
            log_obj[k] = self._format_value(record, v)
        
        if hasattr(record, 'user'):
            log_obj['user'] = record.user
        if hasattr(record, 'ip'):
            log_obj['ip'] = record.ip
        if hasattr(record, 'action'):
            log_obj['action'] = record.action
        
        return json.dumps(log_obj)
    
    def _format_value(self, record, format_string):
        return logging.Formatter(format_string).format(record)

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure app logger
app_handler = RotatingFileHandler('logs/app.log', maxBytes=10485760, backupCount=10)
app_handler.setFormatter(JsonFormatter())
app_logger = logging.getLogger('app')
app_logger.setLevel(logging.INFO)
app_logger.addHandler(app_handler)

# Configure security events logger with JSON formatting
security_handler = RotatingFileHandler('logs/security.log', maxBytes=10485760, backupCount=10)
security_handler.setFormatter(JsonFormatter())
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)
security_logger.addHandler(security_handler)

# Configure error logger
error_handler = RotatingFileHandler('logs/error.log', maxBytes=10485760, backupCount=10)
error_handler.setFormatter(JsonFormatter())
error_logger = logging.getLogger('error')
error_logger.setLevel(logging.ERROR)
error_logger.addHandler(error_handler)

# Use environment variable for secret key, or generate a secure random one
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
app.config['WTF_CSRF_SSL_STRICT'] = True

@app.after_request
def add_security_headers(response):
    """Add security headers to each response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.context_processor
def utility_processor():
    def get_user_fullname():
        if 'user_id' in session:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT full_name FROM users WHERE username = ?", (session['user_id'],))
                result = cursor.fetchone()
                return result[0] if result else ''
            except Exception as e:
                app_logger.error(f"Error getting user full name: {str(e)}")
                return ''
            finally:
                cursor.close()
                conn.close()
        return ''
        
    return {
        'current_year': datetime.now().year,
        'user_fullname': get_user_fullname
    }

# Load API token from environment
api_token = os.getenv('API_TOKEN')
if not api_token:
    api_token = 'your-secret-api-token'
    app_logger.warning(f"API_TOKEN not found in .env file. Using default token: {api_token}")
else:
    app_logger.info(f"Loaded API token from .env: {api_token}")

app.config['API_TOKEN'] = api_token
app.config.update({
    'APISPEC_SPEC': APISpec(
        title='OP Generator API',
        version='v1',
        plugins=[MarshmallowPlugin()],
        openapi_version='2.0',
    ),
    'APISPEC_SWAGGER_URL': '/api/swagger.json',
    'APISPEC_SWAGGER_UI_URL': '/api/docs'
})

api = Api(app)
docs = FlaskApiSpec(app)

# API Schemas
class RecordSchema(Schema):
    name = fields.Str(required=True, metadata={'description': 'Name of the record'})
    id1 = fields.Str(required=True, metadata={'description': 'First identifier'})
    id2 = fields.Str(required=True, metadata={'description': 'Second identifier'})
    op_number = fields.Int(metadata={'description': 'Operation number'})

class RecordResponseSchema(Schema):
    success = fields.Bool()
    data = fields.Nested(RecordSchema)

class RecordListResponseSchema(Schema):
    success = fields.Bool()
    count = fields.Int()
    data = fields.List(fields.Nested(RecordSchema))

class TokenRequestSchema(Schema):
    username = fields.Str(required=True, metadata={'description': 'Username'})
    password = fields.Str(required=True, metadata={'description': 'Password'})

class TokenSchema(Schema):
    token = fields.Str(required=True, metadata={'description': 'API token'})

class TokenResponseSchema(Schema):
    success = fields.Bool()
    token = fields.Str()
    message = fields.Str()

class UserRequestSchema(Schema):
    username = fields.Str(required=True, metadata={'description': 'Username'})
    password = fields.Str(required=True, metadata={'description': 'Password'})
    full_name = fields.Str(required=True, metadata={'description': 'Full Name'})

class UserResponseSchema(Schema):
    success = fields.Bool()
    message = fields.Str()

# Database connection
def get_db_connection():
    server = os.getenv("DB_SERVER", "localhost")
    database = os.getenv("DB_NAME", "master")  # Using master database initially
    conn_str = (
        f"Driver={{ODBC Driver 17 for SQL Server}};"
        f"Server={server};"
        f"Database={database};"
        "Trusted_Connection=yes;"
        "MARS_Connection=yes;"  # Allow multiple active result sets
    )
    conn = pyodbc.connect(conn_str, autocommit=False)
    return conn

# Create database if not exists
def init_db():
    """Initialize the database with tables and initial data."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Create tables if they don't exist
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='users' AND xtype='U')
            CREATE TABLE users (
                username VARCHAR(50) PRIMARY KEY,
                password VARCHAR(255) NOT NULL,
                is_admin BIT NOT NULL DEFAULT 0,
                full_name VARCHAR(100),
                is_approved BIT NOT NULL DEFAULT 0,
                is_disabled BIT NOT NULL DEFAULT 0,
                vacation_start DATE,
                vacation_end DATE
            )
        """)

        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='sessions' AND xtype='U')
            CREATE TABLE sessions (
                session_id INT IDENTITY(1,1) PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                ip_address VARCHAR(45),
                computer_name VARCHAR(100),
                login_time DATETIME DEFAULT GETDATE(),
                logout_time DATETIME,
                FOREIGN KEY (username) REFERENCES users(username)
            )
        """)

        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='records' AND xtype='U')
            CREATE TABLE records (
                op_number INT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                id1 VARCHAR(50) NOT NULL,
                id2 VARCHAR(50) NOT NULL,
                created_by VARCHAR(50) NOT NULL,
                created_at DATETIME DEFAULT GETDATE(),
                FOREIGN KEY (created_by) REFERENCES users(username)
            )
        """)

        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='groups' AND xtype='U')
            CREATE TABLE groups (
                group_id INT IDENTITY(1,1) PRIMARY KEY,
                group_name VARCHAR(50) NOT NULL UNIQUE
            )
        """)

        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='permissions' AND xtype='U')
            CREATE TABLE permissions (
                permission_id INT IDENTITY(1,1) PRIMARY KEY,
                permission_name VARCHAR(50) NOT NULL UNIQUE
            )
        """)

        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='group_permissions' AND xtype='U')
            CREATE TABLE group_permissions (
                group_id INT,
                permission_id INT,
                PRIMARY KEY (group_id, permission_id),
                FOREIGN KEY (group_id) REFERENCES groups(group_id),
                FOREIGN KEY (permission_id) REFERENCES permissions(permission_id)
            )
        """)

        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='user_groups' AND xtype='U')
            CREATE TABLE user_groups (
                username VARCHAR(50),
                group_id INT,
                PRIMARY KEY (username, group_id),
                FOREIGN KEY (username) REFERENCES users(username),
                FOREIGN KEY (group_id) REFERENCES groups(group_id)
            )
        """)

        # Create sequence if it doesn't exist
        cursor.execute("""
            IF NOT EXISTS (SELECT * FROM sys.sequences WHERE name = 'op_number_seq')
            CREATE SEQUENCE op_number_seq
            START WITH 1
            INCREMENT BY 1
        """)

        # Insert default permissions if they don't exist
        cursor.execute("""
            IF NOT EXISTS (SELECT 1 FROM permissions WHERE permission_name = 'generate_op')
            INSERT INTO permissions (permission_name) VALUES ('generate_op');
            
            IF NOT EXISTS (SELECT 1 FROM permissions WHERE permission_name = 'search_op')
            INSERT INTO permissions (permission_name) VALUES ('search_op');
            
            IF NOT EXISTS (SELECT 1 FROM permissions WHERE permission_name = 'manage_users')
            INSERT INTO permissions (permission_name) VALUES ('manage_users');
            
            IF NOT EXISTS (SELECT 1 FROM permissions WHERE permission_name = 'manage_groups')
            INSERT INTO permissions (permission_name) VALUES ('manage_groups');
            
            IF NOT EXISTS (SELECT 1 FROM permissions WHERE permission_name = 'export_results')
            INSERT INTO permissions (permission_name) VALUES ('export_results');
        """)

        # Insert admin group if it doesn't exist
        cursor.execute("""
            IF NOT EXISTS (SELECT 1 FROM groups WHERE group_name = 'admin')
            INSERT INTO groups (group_name) VALUES ('admin')
        """)

        # Get admin group ID
        cursor.execute("SELECT group_id FROM groups WHERE group_name = 'admin'")
        admin_group_id = cursor.fetchone()[0]

        # Get all permission IDs
        cursor.execute("SELECT permission_id FROM permissions")
        permission_ids = [row[0] for row in cursor.fetchall()]

        # Assign all permissions to admin group
        for permission_id in permission_ids:
            cursor.execute("""
                IF NOT EXISTS (
                    SELECT 1 FROM group_permissions 
                    WHERE group_id = ? AND permission_id = ?
                )
                INSERT INTO group_permissions (group_id, permission_id) 
                VALUES (?, ?)
            """, admin_group_id, permission_id, admin_group_id, permission_id)

        # Insert admin user if they don't exist
        admin_password = generate_password_hash('admin')
        cursor.execute("""
            IF NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin')
            INSERT INTO users (username, password, is_admin, full_name, is_approved) 
            VALUES ('admin', ?, 1, 'Administrator', 1)
        """, admin_password)

        # Assign admin user to admin group
        cursor.execute("""
            IF NOT EXISTS (
                SELECT 1 FROM user_groups 
                WHERE username = 'admin' AND group_id = ?
            )
            INSERT INTO user_groups (username, group_id) 
            VALUES ('admin', ?)
        """, admin_group_id, admin_group_id)

        conn.commit()
        app_logger.info("Database initialized successfully with admin user")

    except Exception as e:
        error_logger.exception("Database initialization error")
        raise
    finally:
        cursor.close()
        conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            audit_logger.log_action('unauthorized_access', 
                                  details={'endpoint': request.endpoint},
                                  status='failed')
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE username = ?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()

        if not user or not user[0]:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# API Authentication
def require_api_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-API-Token')
        app_logger.info(f"Received token: {token}")
        
        if not token:
            app_logger.warning("No token provided")
            return {'error': 'API token required'}, 401
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM api_users WHERE api_token = ?', (token,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user:
            app_logger.warning("Invalid token provided")
            return {'error': 'Invalid API token'}, 401
            
        return f(*args, **kwargs)
    return decorated

# API Resources
class RecordResource(MethodResource, Resource):
    @doc(description='Get a record by its OP number', tags=['Records'],
         params={'X-API-Token': {'in': 'header', 'type': 'string', 'required': True, 
                                'description': 'API authentication token'}})
    @marshal_with(RecordResponseSchema)
    @require_api_token
    def get(self, op_number):
        """Get a record by its OP number"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT name, id1, id2, op_number FROM records WHERE op_number = ?', (op_number,))
            record = cursor.fetchone()
            
            if not record:
                return {'error': 'Record not found'}, 404
                
            return {
                'success': True,
                'data': {
                    'name': record[0],
                    'id1': record[1],
                    'id2': record[2],
                    'op_number': record[3]
                }
            }
        except Exception as e:
            return {'error': str(e)}, 500
        finally:
            cursor.close()
            conn.close()

class RecordSearchResource(MethodResource, Resource):
    @doc(description='Search for records using various criteria', tags=['Records'],
         params={'X-API-Token': {'in': 'header', 'type': 'string', 'required': True, 
                                'description': 'API authentication token'}})
    @use_kwargs({
        'name': fields.Str(required=False, metadata={'description': 'Name to search for'}),
        'id1': fields.Str(required=False, metadata={'description': 'First identifier to search for'}),
        'id2': fields.Str(required=False, metadata={'description': 'Second identifier to search for'})
    }, location='query')
    @marshal_with(RecordListResponseSchema)
    @require_api_token
    def get(self, **kwargs):
        """Search for records using various criteria"""
        name = request.args.get('name')
        id1 = request.args.get('id1')
        id2 = request.args.get('id2')
        
        conditions = []
        params = []
        
        if name:
            conditions.append('name = ?')
            params.append(name)
        if id1:
            conditions.append('id1 = ?')
            params.append(id1)
        if id2:
            conditions.append('id2 = ?')
            params.append(id2)
        
        query = 'SELECT name, id1, id2, op_number FROM records'
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(query, params)
            records = cursor.fetchall()
            
            results = [{
                'name': record[0],
                'id1': record[1],
                'id2': record[2],
                'op_number': record[3]
            } for record in records]
            
            return {
                'success': True,
                'count': len(results),
                'data': results
            }
        except Exception as e:
            return {'error': str(e)}, 500
        finally:
            cursor.close()
            conn.close()

class TokenResource(MethodResource):
    @doc(description='Generate API token', tags=['Authentication'])
    @use_kwargs(TokenRequestSchema, location='json')
    @marshal_with(TokenResponseSchema)
    def post(self, **kwargs):
        username = kwargs.get('username')
        password = kwargs.get('password')
        
        # Verify credentials
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, password FROM api_users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if not user or not check_password_hash(user[1], password):
            cursor.close()
            conn.close()
            return {'success': False, 'message': 'Invalid credentials'}, 401
        
        # Generate a new token
        token = secrets.token_urlsafe(32)
        
        # Store the token in the database
        cursor.execute('''
            UPDATE api_users 
            SET api_token = ? 
            WHERE id = ?
        ''', (token, user[0]))
        conn.commit()
        cursor.close()
        conn.close()
        
        return {'success': True, 'token': token, 'message': 'Token generated successfully'}

class UserResource(MethodResource):
    @doc(description='Register new API user', tags=['Authentication'])
    @use_kwargs(UserRequestSchema, location='json')
    @marshal_with(UserResponseSchema)
    def post(self, **kwargs):
        username = kwargs.get('username')
        password = kwargs.get('password')
        full_name = kwargs.get('full_name')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute('SELECT id FROM api_users WHERE username = ?', (username,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return {'success': False, 'message': 'Username already exists'}, 400
            
        # Create new API user
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO api_users (username, password, full_name)
            VALUES (?, ?, ?)
        ''', (username, password_hash, full_name))
        conn.commit()
        cursor.close()
        conn.close()
        
        return {'success': True, 'message': 'API user registered successfully'}

# Register API routes
api.add_resource(RecordResource, '/api/record/<int:op_number>')
api.add_resource(RecordSearchResource, '/api/search')
api.add_resource(TokenResource, '/api/token')
api.add_resource(UserResource, '/api/user')

# Register documentation
docs.register(RecordResource)
docs.register(RecordSearchResource)
docs.register(TokenResource)
docs.register(UserResource)

def get_computer_name():
    ip_address = request.remote_addr
    try:
        return socket.gethostbyaddr(ip_address)[0]  # Resolves the hostname
    except socket.herror:
        return "Unknown"

def get_user_permissions(username):
    """Get all permissions for a user based on their group memberships"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT DISTINCT p.permission_name
        FROM permissions p
        JOIN group_permissions gp ON p.permission_id = gp.permission_id
        JOIN groups g ON gp.group_id = g.group_id
        JOIN user_groups ug ON g.group_id = ug.group_id
        WHERE ug.username = ?
    ''', (username,))
    
    permissions = [row[0] for row in cursor.fetchall()]
    
    cursor.close()
    conn.close()
    
    return permissions

def get_user_groups(username):
    """Get all groups a user belongs to"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT g.group_name
        FROM groups g
        JOIN user_groups ug ON g.group_id = ug.group_id
        WHERE ug.username = ?
    ''', (username,))
    
    groups = [row[0] for row in cursor.fetchall()]
    
    cursor.close()
    conn.close()
    
    return groups

def has_permission(permission_name):
    """Decorator to check if user has the required permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                audit_logger.log_action('permission_check',
                                      details={'permission': permission_name,
                                              'endpoint': request.endpoint,
                                              'error': 'No user session'},
                                      status='failed')
                return redirect(url_for('login'))
                
            # Admin users have all permissions
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT is_admin FROM users WHERE username = ?", (session['user_id'],))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and user[0]:  # is_admin
                audit_logger.log_action('permission_check',
                                      details={'permission': permission_name,
                                              'endpoint': request.endpoint,
                                              'granted_by': 'admin_status'},
                                      status='success')
                return f(*args, **kwargs)
            
            # Check specific permission
            user_permissions = get_user_permissions(session['user_id'])
            if permission_name not in user_permissions:
                audit_logger.log_action('permission_check',
                                      details={'permission': permission_name,
                                              'endpoint': request.endpoint,
                                              'user_permissions': list(user_permissions),
                                              'error': 'Permission not granted'},
                                      status='failed')
                return jsonify({
                    'success': False,
                    'message': 'You do not have permission to perform this action'
                }), 403
            
            audit_logger.log_action('permission_check',
                                  details={'permission': permission_name,
                                          'endpoint': request.endpoint,
                                          'granted_by': 'explicit_permission'},
                                  status='success')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class AuditLogger:
    def __init__(self):
        self.logger = logging.getLogger('audit')
        if not self.logger.handlers:  # Only add handler if none exists
            self.logger.setLevel(logging.INFO)
            audit_handler = RotatingFileHandler('logs/audit.log', maxBytes=10485760, backupCount=10)
            audit_handler.setFormatter(JsonFormatter())
            self.logger.addHandler(audit_handler)
    
    def log_action(self, action, user=None, details=None, status='success'):
        # First try to get user from parameter
        current_user = user
        
        # If no user provided, try to get from session
        if not current_user:
            current_user = session.get('user_id')  # Changed from username to user_id
            
        # If still no user and we're in a request context, this is unexpected
        if not current_user and request:
            error_logger.warning(f"Audit log called without user for action: {action}")
            if session:
                error_logger.warning(f"Session contents: {session}")
        
        extra = {
            'user': current_user or 'anonymous',
            'ip': request.remote_addr,
            'action': action,
            'details': details,
            'status': status,
            'user_agent': request.user_agent.string
        }
        
        record = logging.LogRecord(
            name='audit',
            level=logging.INFO,
            pathname=__file__,
            lineno=0,
            msg=f"User action: {action}",
            args=(),
            exc_info=None
        )
        
        for key, value in extra.items():
            setattr(record, key, value)
        
        self.logger.handle(record)

# Initialize audit logger
audit_logger = AuditLogger()

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/')
def root():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('index'))

@app.route('/index')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # Get next URL from either URL parameters or form data
    next_url = request.args.get('next') or request.form.get('next')
    # Validate next URL
    if next_url and not is_safe_url(next_url):
        next_url = None
    
    if request.method == 'GET':
        return render_template('login.html', form=form)
        
    if form.validate_on_submit():
        try:
            username = form.username.data
            password = form.password.data
            
            # Log login attempt
            audit_logger.log_action('login_attempt', username)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT username, password, is_admin, full_name, is_approved, is_disabled, 
                       vacation_start, vacation_end 
                FROM users 
                WHERE username = ?
            """, username)
            
            user = cursor.fetchone()
            
            if not user or not check_password_hash(user[1], password):
                audit_logger.log_action('login_failed', username, details='Invalid credentials', status='failed')
                flash('Invalid username or password', 'danger')
                return redirect(url_for('login', next=next_url))
                
            if not user[4]:
                audit_logger.log_action('login_failed', username, details='Account not approved', status='failed')
                flash('Your account has not been approved yet', 'warning')
                return redirect(url_for('login', next=next_url))
                
            if user[5]:
                audit_logger.log_action('login_failed', username, details='Account disabled', status='failed')
                flash('Your account has been disabled. Please contact an administrator', 'danger')
                return redirect(url_for('login', next=next_url))
                
            # Check vacation period
            if user[6] and user[7]:
                current_date = datetime.now().date()
                if user[6] <= current_date <= user[7]:
                    audit_logger.log_action('login_failed', username, details='Vacation period', status='failed')
                    flash('You cannot log in during your vacation period', 'warning')
                    return redirect(url_for('login', next=next_url))
                    
            # Create session record
            computer_name = get_computer_name()
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (username, ip_address, computer_name, login_time)
                OUTPUT INSERTED.session_id
                VALUES (?, ?, ?, ?)
            """, (username, request.remote_addr, computer_name, datetime.now()))
            
            session_id = cursor.fetchone()[0]
            
            # Get user permissions
            cursor.execute("""
                SELECT p.permission_name
                FROM user_groups ug
                JOIN group_permissions gp ON ug.group_id = gp.group_id
                JOIN permissions p ON gp.permission_id = p.permission_id
                WHERE ug.username = ?
            """, username)
            
            user_permissions = [row[0] for row in cursor.fetchall()]
            
            # Update session
            session['user_id'] = username
            session['is_admin'] = user[2]
            session['full_name'] = user[3]
            session['session_id'] = session_id
            session['permissions'] = user_permissions
            
            audit_logger.log_action('login', username)
            audit_logger.log_action('session_create', username, details={'session_id': session_id})
            
            conn.commit()
            
            # Redirect to next URL if provided and valid, otherwise to default page
            if next_url:
                audit_logger.log_action('redirect_after_login', username, 
                                      details={'redirect_url': next_url})
                return redirect(next_url)
            
            if user[2]:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('index'))
            
        except Exception as e:
            error_logger.exception(f"Login error", extra={'user': username if username else 'unknown'})
            flash('An error occurred during login. Please try again.', 'danger')
            return redirect(url_for('login', next=next_url))
        finally:
            cursor.close()
            conn.close()
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    try:
        username = session.get('user_id')
        session_id = session.get('session_id')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Update session end time
            cursor.execute("""
                UPDATE sessions 
                SET logout_time = ? 
                WHERE session_id = ?
            """, (datetime.now(), session_id))
            
            conn.commit()
            
            audit_logger.log_action('logout', username)
            audit_logger.log_action('session_end', username, details={'session_id': session_id})
            
        except Exception as e:
            error_logger.exception(f"Logout error", extra={'user': username})
        finally:
            cursor.close()
            conn.close()
            
        # Clear session
        session.clear()
        flash('You have been logged out', 'info')
        
    except Exception as e:
        error_logger.exception("Error during logout")
        
    return redirect(url_for('login'))

@app.route('/generate', methods=['GET', 'POST'])
@login_required
@has_permission('generate_op')
def generate():
    try:
        # Log attempt
        audit_logger.log_action('generate_op_attempt', 
                              details={'method': request.method})
        
        if not request.is_json:
            audit_logger.log_action('generate_op', 
                                  details={'error': 'Invalid content type'},
                                  status='failed')
            return jsonify({'error': 'Request must be JSON'}), 400
            
        try:
            data = request.get_json()
        except Exception as e:
            audit_logger.log_action('generate_op',
                                  details={'error': 'JSON parse error', 'message': str(e)},
                                  status='failed')
            return jsonify({'error': 'Invalid JSON format'}), 400
            
        if not data:
            audit_logger.log_action('generate_op',
                                  details={'error': 'Empty data'},
                                  status='failed')
            return jsonify({'error': 'No data provided'}), 400
            
        name = data.get('name')
        id1 = data.get('id1')
        id2 = data.get('id2')
        
        # Input validation
        if not all([name, id1, id2]):
            missing_fields = [f for f, v in {'name': name, 'id1': id1, 'id2': id2}.items() if not v]
            audit_logger.log_action('generate_op',
                                  details={'error': 'Missing required fields',
                                          'missing_fields': missing_fields},
                                  status='failed')
            return jsonify({'error': 'All fields (name, id1, id2) are required'}), 400
        
        # Validate ID1 and ID2 are numbers only
        if not id1.isdigit() or not id2.isdigit():
            audit_logger.log_action('generate_op',
                                  details={'error': 'Invalid ID format',
                                          'id1': id1,
                                          'id2': id2},
                                  status='failed')
            return jsonify({'error': 'ID1 and ID2 must contain numbers only'}), 400
            
        # Validate input lengths
        if len(name) > 100 or len(id1) > 20 or len(id2) > 20:
            audit_logger.log_action('generate_op',
                                  details={'error': 'Field length exceeded',
                                          'lengths': {
                                              'name': len(name),
                                              'id1': len(id1),
                                              'id2': len(id2)
                                          }},
                                  status='failed')
            return jsonify({'error': 'Input fields exceed maximum length'}), 400
        
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check if the same data exists
            cursor.execute(
                'SELECT op_number FROM records WHERE name = ? AND id1 = ? AND id2 = ?',
                (name, id1, id2)
            )
            existing_record = cursor.fetchone()
            
            if existing_record:
                audit_logger.log_action('generate_op',
                                      details={'status': 'duplicate',
                                              'op_number': existing_record[0]})
                return jsonify({
                    'op_number': existing_record[0],
                    'message': 'Record already exists'
                })
            
            # Get next OP number with retry logic
            max_retries = 3
            op_number = None
            last_error = None
            
            for attempt in range(max_retries):
                try:
                    cursor.execute("SELECT NEXT VALUE FOR OpNumberSequence")
                    op_number = cursor.fetchone()[0]
                    break
                except pyodbc.Error as e:
                    last_error = str(e)
                    app_logger.warning(f"Retry {attempt + 1} for sequence generation: {last_error}")
                    audit_logger.log_action('generate_op_sequence_retry',
                                          details={'attempt': attempt + 1,
                                                  'error': last_error})
                    if attempt < max_retries - 1:
                        time.sleep(0.5)  # Short delay before retry
            
            if op_number is None:
                error_msg = f"Failed to generate sequence after {max_retries} attempts. Last error: {last_error}"
                audit_logger.log_action('generate_op',
                                      details={'error': error_msg},
                                      status='failed')
                raise Exception(error_msg)
            
            # Insert new record
            cursor.execute(
                'INSERT INTO records (name, id1, id2, op_number, created_by) VALUES (?, ?, ?, ?, ?)',
                (name, id1, id2, op_number, session.get('user_id'))
            )
            conn.commit()
            
            audit_logger.log_action('generate_op',
                                  details={'op_number': op_number,
                                          'name': name,
                                          'created_by': session.get('user_id')})
            return jsonify({
                'op_number': op_number,
                'message': 'New record created'
            })
            
        except pyodbc.Error as e:
            error_msg = str(e)
            app_logger.error(f"Database error during generation: {error_msg}")
            audit_logger.log_action('generate_op',
                                  details={'error': 'Database error',
                                          'message': error_msg},
                                  status='failed')
            if conn:
                try:
                    conn.rollback()
                except:
                    pass  # Ignore rollback errors
            return jsonify({'error': f'Database error occurred: {error_msg}. Please try again.'}), 500
            
        except Exception as e:
            error_msg = str(e)
            audit_logger.log_action('generate_op',
                                  details={'error': 'Unexpected error',
                                          'message': error_msg},
                                  status='failed')
            app_logger.error(f"Unexpected error in generate route: {error_msg}")
            return jsonify({'error': f'An unexpected error occurred: {error_msg}. Please try again.'}), 500
            
        finally:
            if cursor:
                try:
                    cursor.close()
                except:
                    pass  # Ignore cursor close errors
            if conn:
                try:
                    conn.close()
                except:
                    pass  # Ignore connection close errors
                
    except Exception as e:
        error_msg = str(e)
        audit_logger.log_action('generate_op',
                              details={'error': 'Unhandled error',
                                      'message': error_msg},
                              status='failed')
        app_logger.error(f"Unhandled error in generate route: {error_msg}")
        return jsonify({'error': f'An unexpected error occurred. Please try again.'}), 500

@app.route('/search', methods=['GET', 'POST'])
@login_required
@has_permission('search_op')
def search_ops():
    try:
        # Get search parameters
        op_number = request.args.get('op_number', '').strip()
        name = request.args.get('name', '').strip()
        id1 = request.args.get('id1', '').strip()
        id2 = request.args.get('id2', '').strip()
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build the base query
        query = """
            SELECT op_number, name, id1, id2, created_at
            FROM records
            WHERE 1=1
        """
        params = []
        
        # Add search conditions
        if op_number:
            query += " AND CAST(op_number AS VARCHAR) LIKE ?"
            params.append(f'%{op_number}%')
            
        if name:
            query += " AND name LIKE ?"
            params.append(f'%{name}%')
            
        if id1:
            query += " AND id1 LIKE ?"
            params.append(f'%{id1}%')
            
        if id2:
            query += " AND id2 LIKE ?"
            params.append(f'%{id2}%')
            
        if date_from:
            query += " AND created_at >= ?"
            params.append(date_from)
            
        if date_to:
            query += " AND created_at <= ?"
            params.append(date_to)
        
        # Get total count for pagination
        count_query = f"SELECT COUNT(*) FROM ({query}) as count_query"
        cursor.execute(count_query, params)
        total_records = cursor.fetchone()[0]
        
        # Add sorting
        sort_column = {
            'op_number': 'op_number',
            'name': 'name',
            'id1': 'id1',
            'id2': 'id2',
            'created_at': 'created_at'
        }.get(sort_by, 'created_at')
        
        query += f" ORDER BY {sort_column} {sort_order.upper()}"
        
        # Add pagination
        offset = (page - 1) * per_page
        query += f" OFFSET {offset} ROWS FETCH NEXT {per_page} ROWS ONLY"
        
        # Execute final query
        cursor.execute(query, params)
        records = []
        for row in cursor.fetchall():
            records.append({
                'op_number': row[0],
                'name': row[1],
                'id1': row[2],
                'id2': row[3],
                'created_at': row[4].strftime('%Y-%m-%d %H:%M:%S') if row[4] else None
            })
            
        # Calculate pagination info
        total_pages = (total_records + per_page - 1) // per_page
        has_next = page < total_pages
        has_prev = page > 1
        
        return jsonify({
            'success': True,
            'records': records,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_records': total_records,
                'total_pages': total_pages,
                'has_next': has_next,
                'has_prev': has_prev
            }
        })
        
    except Exception as e:
        app_logger.error(f"Search error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An error occurred while searching'
        }), 500
    finally:
        cursor.close()
        conn.close()
        
@app.route('/api/statuses', methods=['GET'])
def get_statuses():
    """Get all possible OP statuses for filtering"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT DISTINCT status FROM records ORDER BY status")
        statuses = [row[0] for row in cursor.fetchall()]
        return jsonify({'statuses': statuses})
    finally:
        cursor.close()
        conn.close()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    
    # Get form data
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    full_name = request.form.get('full_name')
    email = request.form.get('email')
    
    # Validate required fields
    if not all([username, password, confirm_password, full_name, email]):
        flash('All fields are required', 'danger')
        return redirect(url_for('signup'))
    
    # Validate username format
    if not re.match(r'^[a-zA-Z0-9_-]{3,50}$', username):
        flash('Username must be 3-50 characters long and can only contain letters, numbers, underscores, and hyphens', 'danger')
        return redirect(url_for('signup'))
    
    # Validate email format
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        flash('Please enter a valid email address', 'danger')
        return redirect(url_for('signup'))
    
    # Validate password strength
    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
        flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character', 'danger')
        return redirect(url_for('signup'))
    
    # Validate password confirmation
    if password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('signup'))
    
    # Validate full name length
    if not (2 <= len(full_name) <= 100):
        flash('Full name must be between 2 and 100 characters', 'danger')
        return redirect(url_for('signup'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if username already exists
        cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            flash('Username already exists', 'danger')
            return redirect(url_for('signup'))
            
        # Check if email already exists
        cursor.execute('SELECT username FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            flash('Email address already registered', 'danger')
            return redirect(url_for('signup'))
            
        # Create new user with is_approved = 0
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, password, full_name, email, is_admin, is_approved, is_disabled, created_at)
            VALUES (?, ?, ?, ?, 0, 0, 0, GETDATE())
        ''', (username, password_hash, full_name, email))
        
        # Add user to Standard Users group
        cursor.execute('''
            INSERT INTO user_groups (username, group_id)
            SELECT ?, group_id FROM groups WHERE group_name = 'Standard Users'
        ''', (username,))
        
        conn.commit()
        flash('Your account has been created successfully! Please wait for an administrator to approve your account before you can log in.', 'success')
        return redirect(url_for('login'))
    
    except Exception as e:
        app_logger.error(f"Database error during signup: {str(e)}")
        conn.rollback()
        flash('An error occurred while creating your account', 'danger')
        return redirect(url_for('signup'))
    finally:
        cursor.close()
        conn.close()

@app.route('/admin')
@login_required
@has_permission('manage_users')
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Fetch all users with their active session information
        cursor.execute("""
            SELECT 
                u.username, 
                u.full_name, 
                u.is_admin,
                u.is_approved,
                u.is_disabled,
                u.vacation_start,
                u.vacation_end,
                s.ip_address,
                s.computer_name,
                s.login_time
            FROM users u
            LEFT JOIN sessions s ON u.username = s.username
            WHERE u.username != ? And logout_time Is Null
            ORDER BY u.username, s.login_time DESC
        """, (session['user_id'],))
        
        users_data = cursor.fetchall()
        users = []
        current_user = None
        
        # Process users and their sessions
        for row in users_data:
            username = row[0]
            
            # If this is a new user
            if not current_user or current_user['username'] != username:
                if current_user:
                    users.append(current_user)
                
                current_user = {
                    'username': username,
                    'full_name': row[1],
                    'is_admin': row[2],
                    'is_approved': row[3],
                    'is_disabled': row[4],
                    'vacation_start': row[5],
                    'vacation_end': row[6],
                    'sessions': [],
                    'groups': []
                }
                
                # Get user groups
                cursor.execute("""
                    SELECT group_id 
                    FROM user_groups 
                    WHERE username = ?
                """, (username,))
                current_user['groups'] = [row[0] for row in cursor.fetchall()]
            
            # Add session info if it exists
            if row[7] or row[8] or row[9]:  # if any session data exists
                current_user['sessions'].append({
                    'ip_address': row[7],
                    'computer_name': row[8],
                    'login_time': row[9]
                })
        
        # Add the last user
        if current_user:
            users.append(current_user)
        
        # Get all available groups
        cursor.execute("""
            SELECT group_id, group_name, description 
            FROM groups
            ORDER BY group_name
        """)
        all_groups = [{'group_id': row[0], 'group_name': row[1], 'description': row[2]} 
                     for row in cursor.fetchall()]
        
        # Get statistics
        cursor.execute("SELECT COUNT(*) FROM records")
        total_ops = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM records WHERE CAST(created_at AS DATE) = CAST(GETDATE() AS DATE)")
        today_ops = cursor.fetchone()[0]
        
        cursor.execute("SELECT TOP 1 op_number FROM records ORDER BY op_number DESC")
        last_op_row = cursor.fetchone()
        last_op = last_op_row[0] if last_op_row else 0
        
        stats = {
            'total_ops': total_ops,
            'today_ops': today_ops,
            'last_op': last_op
        }
        
        return render_template(
            'admin.html', 
            users=users,
            all_groups=all_groups,
            stats=stats
        )
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<username>/approve', methods=['POST'])
@login_required
@has_permission('manage_users')
def approve_user(username):
    if not request.is_json:
        return jsonify({'error': 'Invalid request format'}), 400

    # Validate CSRF token
    token = request.json.get('csrf_token')
    if not token:
        return jsonify({'error': 'CSRF token is missing'}), 400

    conn = get_db_connection()
    cursor = None
    try:
        cursor = conn.cursor()
        
        # Get user details first
        cursor.execute("SELECT username, is_approved FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        if user[1]:
            return jsonify({'error': 'User is already approved'}), 400
            
        # Update user approval status
        cursor.execute("UPDATE users SET is_approved = 1 WHERE username = ?", (username,))
        conn.commit()
        
        audit_logger.log_action('approve_user', details={'target_user': username})
        return jsonify({'success': True, 'message': f'User {username} has been approved successfully'})
        
    except Exception as e:
        if cursor and conn:
            conn.rollback()
        app_logger.error(f"Error approving user {username}: {str(e)}")
        return jsonify({'error': 'An error occurred while approving the user'}), 500
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/admin/user/<username>/delete', methods=['POST'])
@login_required
@has_permission('manage_users')
def delete_user(username):
    if not request.is_json:
        return jsonify({'error': 'Invalid request format'}), 400

    # Validate CSRF token
    token = request.json.get('csrf_token')
    if not token:
        return jsonify({'error': 'CSRF token is missing'}), 400

    if username == session['user_id']:
        return jsonify({'error': 'Cannot delete your own account'}), 400

    conn = get_db_connection()
    cursor = None
    
    try:
        cursor = conn.cursor()
        
        app_logger.info(f"Starting delete_user process for username: {username}")
        
        # First check if user exists and get current admin status
        check_user_sql = "SELECT is_admin, is_approved FROM users WHERE username = ?"
        cursor.execute(check_user_sql, (username,))
        user = cursor.fetchone()
        app_logger.info(f"User query result for {username}: {user}")
        
        if not user:
            app_logger.warning(f"Attempt to delete non-existent user: {username}")
            return jsonify({'error': 'User not found'}), 404
            
        if user[0]:  # is_admin
            app_logger.warning(f"Attempt to delete admin user: {username}")
            return jsonify({'error': 'Cannot delete admin users'}), 403

        # Check if user is approved
        is_approved = user[1] if user[1] is not None else 0
        app_logger.info(f"User {username} approval status: {is_approved}")
        
        if is_approved == 1:
            app_logger.warning(f"Attempt to delete approved user: {username}")
            return jsonify({'error': 'Cannot delete approved users. Please contact your system administrator.'}), 403

        # Check if user has generated any records
        check_records_sql = "SELECT COUNT(*) FROM records WHERE name = ?"
        cursor.execute(check_records_sql, (username,))
        record_count = cursor.fetchone()[0]
        app_logger.info(f"Record count for user {username}: {record_count}")
        
        if record_count > 0:
            app_logger.warning(f"Cannot delete user {username} because they have {record_count} records")
            return jsonify({
                'error': f'Cannot delete this user because they have generated {record_count} records. ' +
                        'Please contact your system administrator if you need to remove this user.'
            }), 403

        # Start transaction
        app_logger.info(f"Starting deletion transaction for user: {username}")

        try:
            # Delete from user_groups first
            delete_groups_sql = """
                IF EXISTS (SELECT 1 FROM user_groups WHERE username = ?)
                BEGIN
                    DELETE FROM user_groups WHERE username = ?
                END
            """
            cursor.execute(delete_groups_sql, (username, username))
            groups_deleted = cursor.rowcount
            app_logger.info(f"Deleted {groups_deleted} group associations for user: {username}")

            # Delete from sessions
            delete_sessions_sql = """
                IF EXISTS (SELECT 1 FROM sessions WHERE username = ?)
                BEGIN
                    DELETE FROM sessions WHERE username = ?
                END
            """
            cursor.execute(delete_sessions_sql, (username, username))
            sessions_deleted = cursor.rowcount
            app_logger.info(f"Deleted {sessions_deleted} sessions for user: {username}")
            
            # Delete the user
            delete_user_sql = """
                IF EXISTS (SELECT 1 FROM users WHERE username = ?)
                BEGIN
                    DELETE FROM users WHERE username = ?
                END
            """
            cursor.execute(delete_user_sql, (username, username))
            users_deleted = cursor.rowcount
            app_logger.info(f"Deleted user {username}: {users_deleted} rows affected")
            
            if users_deleted == 0:
                raise Exception(f"Failed to delete user {username} from users table")

            # Verify user deletion
            check_user_sql = "SELECT COUNT(*) FROM users WHERE username = ?"
            cursor.execute(check_user_sql, (username,))
            remaining_user = cursor.fetchone()[0]
            app_logger.info(f"Remaining user count after deletion: {remaining_user}")
            
            if remaining_user > 0:
                raise Exception(f"User {username} still exists after deletion")

            # Commit the transaction
            conn.commit()
            app_logger.info(f"Successfully committed deletion of user {username}")
            
            audit_logger.log_action('delete_user', details={'target_user': username})
            return jsonify({
                'success': True,
                'message': 'User deleted successfully',
                'details': {
                    'sessions_deleted': sessions_deleted,
                    'groups_deleted': groups_deleted,
                    'users_deleted': users_deleted
                }
            })
            
        except Exception as e:
            app_logger.error(f"Error during deletion transaction: {str(e)}")
            conn.rollback()
            return jsonify({'error': str(e)}), 500
            
    except Exception as e:
        app_logger.error(f"Error in delete_user for {username}: {str(e)}")
        if cursor:
            try:
                conn.rollback()
            except Exception as rollback_error:
                app_logger.error(f"Error during rollback: {str(rollback_error)}")
        return jsonify({'error': 'An error occurred while deleting the user'}), 500
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/admin/api-user/<username>', methods=['DELETE'])
@login_required
@has_permission('manage_users')
def delete_api_user(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM api_users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/api-user/<username>/token', methods=['POST'])
@login_required
@has_permission('manage_users')
def regenerate_token(username):
    new_token = secrets.token_hex(32)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("UPDATE api_users SET api_token = ? WHERE username = ?", (new_token, username))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/api-user', methods=['POST'])
@login_required
@has_permission('manage_users')
def create_api_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Missing username or password'}), 400
    
    hashed_password = generate_password_hash(password)
    api_token = secrets.token_hex(32)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Print the SQL query and parameters for debugging
        print(f"Executing SQL: INSERT INTO api_users (username, password, api_token) VALUES ('{username}', '{hashed_password}', '{api_token}')")
        
        # Execute the SQL query
        cursor.execute(
            """INSERT INTO api_users 
               (username, password, api_token) 
               VALUES (?, ?, ?)""",
            (username, hashed_password, api_token)
        )
        conn.commit()
        return jsonify({'success': True, 'token': api_token})
    except pyodbc.IntegrityError as e:
        # Handle unique constraint violation (e.g., username already exists)
        conn.rollback()
        app_logger.error(f"IntegrityError: {str(e)}")
        return jsonify({'success': False, 'error': 'Username already exists'}), 400
    except Exception as e:
        # Handle other database errors
        conn.rollback()
        app_logger.error(f"Database error during API user creation: {str(e)}")
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<username>/toggle-admin', methods=['POST'])
@login_required
@has_permission('manage_users')
def toggle_admin(username):
    # Don't allow changing own admin status
    if username == session['username']:
        return jsonify({'error': 'Cannot modify your own admin status'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # First check if user exists and get current admin status
        cursor.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        # Toggle admin status
        new_status = not bool(user[0])
        cursor.execute("""
            UPDATE users 
            SET is_admin = ?, is_approved = CASE WHEN ? = 1 THEN 1 ELSE is_approved END 
            WHERE username = ?
        """, (new_status, new_status, username))
        
        conn.commit()
        return jsonify({'success': True, 'is_admin': new_status})
    except Exception as e:
        conn.rollback()
        app_logger.error(f"Error toggling admin status: {str(e)}")
        return jsonify({'error': 'Database error occurred'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<username>/toggle-disabled', methods=['POST'])
@login_required
@has_permission('manage_users')
def toggle_disabled(username):
    app_logger.info(f"Received request to toggle disabled status for user: {username}")
    
    if not request.is_json:
        app_logger.error(f"Invalid request format for toggle_disabled: {request.data}")
        return jsonify({'error': 'Invalid request format'}), 400

    # Validate CSRF token
    token = request.json.get('csrf_token')
    if not token:
        app_logger.error("CSRF token missing in toggle_disabled request")
        return jsonify({'error': 'CSRF token is missing'}), 400

    if username == session.get('user_id'):
        app_logger.warning(f"User {username} attempted to disable their own account")
        return jsonify({'error': 'Cannot disable your own account'}), 400

    conn = get_db_connection()
    cursor = None
    try:
        cursor = conn.cursor()
        app_logger.info(f"Checking user status for: {username}")

        # Check if user exists and get current status
        cursor.execute("""
            SELECT username, is_admin, is_disabled 
            FROM users 
            WHERE username = ?
        """, (username,))
        user = cursor.fetchone()
        
        if not user:
            app_logger.error(f"User not found: {username}")
            return jsonify({'error': 'User not found'}), 404

        current_username, is_admin, is_disabled = user
        app_logger.info(f"Current status for {username}: admin={is_admin}, disabled={is_disabled}")
        
        # Prevent disabling admin users
        if is_admin:
            app_logger.warning(f"Attempt to disable admin user: {username}")
            return jsonify({'error': 'Cannot disable admin users'}), 403

        # Toggle disabled status
        new_status = not is_disabled
        app_logger.info(f"Updating disabled status for {username} to: {new_status}")
        
        cursor.execute("""
            UPDATE users 
            SET is_disabled = ? 
            WHERE username = ?
        """, (new_status, username))
        
        rows_affected = cursor.rowcount
        app_logger.info(f"Update affected {rows_affected} rows")
        
        # Log out user if being disabled
        if new_status:
            app_logger.info(f"Deleting sessions for disabled user: {username}")
            cursor.execute("DELETE FROM sessions WHERE username = ?", (username,))
            sessions_deleted = cursor.rowcount
            app_logger.info(f"Deleted {sessions_deleted} sessions for user {username}")
            
        conn.commit()
        app_logger.info(f"Successfully committed changes for user {username}")
        
        action = "disabled" if new_status else "enabled"
        return jsonify({
            'success': True,
            'message': f'User has been {action} successfully',
            'details': {
                'username': username,
                'new_status': new_status,
                'rows_affected': rows_affected
            }
        })

    except Exception as e:
        if cursor and conn:
            conn.rollback()
        app_logger.error(f"Error in toggle_disabled for {username}: {str(e)}", exc_info=True)
        return jsonify({'error': f'An error occurred while updating user status: {str(e)}'}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        app_logger.info(f"Completed toggle_disabled request for {username}")

@app.route('/admin/user/<username>/set-vacation', methods=['POST'])
@login_required
@has_permission('manage_users')
def set_vacation(username):
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Cannot set vacation for admin user'}), 400
        
    start_date = request.json.get('start_date')
    end_date = request.json.get('end_date')
    
    if not start_date or not end_date:
        return jsonify({'success': False, 'message': 'Start date and end date are required'}), 400
        
    try:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d')
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid date format. Use YYYY-MM-DD'}), 400
        
    if start_date > end_date:
        return jsonify({'success': False, 'message': 'Start date must be before end date'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if user exists
        cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        # Update vacation period
        cursor.execute('''
            UPDATE users 
            SET vacation_start = ?,
                vacation_end = ?
            WHERE username = ?
        ''', (start_date, end_date, username))
        
        conn.commit()
        return jsonify({
            'success': True, 
            'message': f'Vacation period set for {username} from {start_date.strftime("%Y-%m-%d")} to {end_date.strftime("%Y-%m-%d")}'
        })
        
    except Exception as e:
        conn.rollback()
        app_logger.error(f"Error setting vacation period: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<username>/clear-vacation', methods=['POST'])
@login_required
@has_permission('manage_users')
def clear_vacation(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE users 
            SET vacation_start = NULL,
                vacation_end = NULL
            WHERE username = ?
        ''', (username,))
        
        conn.commit()
        return jsonify({
            'success': True, 
            'message': f'Vacation period cleared for {username}'
        })
        
    except Exception as e:
        conn.rollback()
        app_logger.error(f"Error clearing vacation period: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/groups')
@login_required
@has_permission('manage_groups')
def manage_groups():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get all groups with their permissions
    cursor.execute('''
        SELECT 
            g.group_id,
            g.group_name,
            g.description,
            COALESCE(STRING_AGG(p.permission_name, ', '), '') as permissions
        FROM groups g
        LEFT JOIN group_permissions gp ON g.group_id = gp.group_id
        LEFT JOIN permissions p ON gp.permission_id = p.permission_id
        GROUP BY g.group_id, g.group_name, g.description
    ''')
    
    groups = cursor.fetchall()
    
    # Get all available permissions
    cursor.execute('SELECT permission_id, permission_name, description FROM permissions')
    permissions = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template('groups.html', groups=groups, permissions=permissions)

@app.route('/admin/groups/add', methods=['POST'])
@login_required
@has_permission('manage_groups')
def add_group():
    group_name = request.form.get('group_name')
    description = request.form.get('description')
    permissions = request.form.getlist('permissions')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Add new group
        cursor.execute('''
            INSERT INTO groups (group_name, description)
            OUTPUT INSERTED.group_id
            VALUES (?, ?)
        ''', (group_name, description))
        
        group_id = cursor.fetchone()[0]
        
        # Add permissions
        for permission_id in permissions:
            cursor.execute('''
                INSERT INTO group_permissions (group_id, permission_id)
                VALUES (?, ?)
            ''', (group_id, permission_id))
        
        conn.commit()
        flash('Group added successfully', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error adding group: {str(e)}', 'error')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('manage_groups'))

@app.route('/admin/groups/<int:group_id>/edit', methods=['POST'])
@login_required
@has_permission('manage_groups')
def edit_group(group_id):
    group_name = request.form.get('group_name')
    description = request.form.get('description')
    permissions = request.form.getlist('permissions')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Update group details
        cursor.execute('''
            UPDATE groups
            SET group_name = ?, description = ?
            WHERE group_id = ?
        ''', (group_name, description, group_id))
        
        # Remove existing permissions
        cursor.execute('DELETE FROM group_permissions WHERE group_id = ?', (group_id,))
        
        # Add new permissions
        for permission_id in permissions:
            cursor.execute('''
                INSERT INTO group_permissions (group_id, permission_id)
                VALUES (?, ?)
            ''', (group_id, permission_id))
        
        conn.commit()
        flash('Group updated successfully', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error updating group: {str(e)}', 'error')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('manage_groups'))

@app.route('/admin/groups/<int:group_id>/delete', methods=['POST'])
@login_required
@has_permission('manage_groups')
def delete_group(group_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Delete group (cascade will handle related records)
        cursor.execute('DELETE FROM groups WHERE group_id = ?', (group_id,))
        conn.commit()
        flash('Group deleted successfully', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting group: {str(e)}', 'error')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('manage_groups'))

@app.route('/admin/users/<username>/groups', methods=['POST'])
@login_required
@has_permission('manage_users')
def update_user_groups(username):
    groups = request.form.getlist('groups')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Remove existing group assignments
        cursor.execute('DELETE FROM user_groups WHERE username = ?', (username,))
        
        # Add new group assignments
        for group_id in groups:
            cursor.execute('''
                INSERT INTO user_groups (username, group_id)
                VALUES (?, ?)
            ''', (username, group_id))
        
        conn.commit()
        flash('User groups updated successfully', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error updating user groups: {str(e)}', 'error')
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            security_logger.warning('Unauthorized admin access attempt', extra={
                'user': session.get('user_id', 'unknown'),
                'ip': request.remote_addr,
                'endpoint': request.endpoint
            })
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def has_permission(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            username = session.get('user_id')
            if not username:
                security_logger.warning('Permission check failed - no user in session', extra={
                    'permission': permission_name,
                    'ip': request.remote_addr,
                    'endpoint': request.endpoint
                })
                return redirect(url_for('login'))
                
            conn = get_db_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    SELECT p.permission_name
                    FROM user_groups ug
                    JOIN group_permissions gp ON ug.group_id = gp.group_id
                    JOIN permissions p ON gp.permission_id = p.permission_id
                    WHERE ug.username = ?
                """, username)
                
                user_permissions = {row[0] for row in cursor.fetchall()}
                
                if permission_name not in user_permissions:
                    security_logger.warning('Permission denied', extra={
                        'user': username,
                        'permission': permission_name,
                        'ip': request.remote_addr,
                        'endpoint': request.endpoint
                    })
                    flash('You do not have permission to perform this action', 'danger')
                    return redirect(url_for('index'))
                    
                audit_logger.log_action('permission_check', username, details={'permission': permission_name})
                return f(*args, **kwargs)
                
            except Exception as e:
                error_logger.exception('Error checking permissions', extra={
                    'user': username,
                    'permission': permission_name
                })
                flash('An error occurred while checking permissions', 'danger')
                return redirect(url_for('index'))
            finally:
                cursor.close()
                conn.close()
                
        return decorated_function
    return decorator

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required', 'error')
            return redirect(url_for('change_password'))
            
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('change_password'))
            
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return redirect(url_for('change_password'))
            
        # Check current password and update
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT password FROM users WHERE username = ?", (session['user_id'],))
            result = cursor.fetchone()
            
            if not result or not check_password_hash(result[0], current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('change_password'))
            
            # Update password
            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", 
                         (hashed_password, session['user_id']))
            conn.commit()
            
            flash('Password changed successfully', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            conn.rollback()
            app_logger.error(f"Error changing password: {str(e)}")
            flash('An error occurred while changing password', 'error')
            return redirect(url_for('change_password'))
            
        finally:
            cursor.close()
            conn.close()
    
    return render_template('change_password.html')

@app.route('/admin/user/<username>/reset_password', methods=['POST'])
@login_required
@has_permission('manage_users')
def reset_user_password(username):
    if not request.is_json:
        return jsonify({'error': 'Invalid request format'}), 400
        
    new_password = request.json.get('new_password')
    if not new_password:
        return jsonify({'error': 'New password is required'}), 400
        
    # Validate password requirements
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
    if not (re.search(r'[A-Z]', new_password) and 
            re.search(r'[a-z]', new_password) and 
            re.search(r'\d', new_password) and 
            re.search(r'[@$!%*?&]', new_password)):
        return jsonify({'error': 'Password must contain uppercase, lowercase, number, and special character'}), 400
    
    conn = get_db_connection()
    cursor = None
    try:
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            return jsonify({'error': 'User not found'}), 404
            
        # Update password
        hashed_password = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", 
                      (hashed_password, username))
        conn.commit()
        
        audit_logger.log_action('reset_password', details={'target_user': username})
        return jsonify({'success': True, 'message': f'Password reset successful for user {username}'})
        
    except Exception as e:
        app_logger.error(f"Error resetting password for {username}: {str(e)}")
        if cursor:
            conn.rollback()
        return jsonify({'error': 'An error occurred while resetting the password'}), 500
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/search-page')
@login_required
def search_page():
    return render_template('search.html')

@app.route('/export', methods=['POST'])
@login_required
@has_permission('export_results')
def export_results():
    try:
        # Get search parameters (same as search route)
        op_number = request.args.get('op_number', '').strip()
        name = request.args.get('name', '').strip()
        id1 = request.args.get('id1', '').strip()
        id2 = request.args.get('id2', '').strip()
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        status = request.args.get('status')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build the base query (without pagination)
        query = """
            SELECT 
                r.op_number, r.name, r.id1, r.id2, 
                r.description, r.status, 
                r.created_at, u1.username as created_by,
                r.updated_at, u2.username as updated_by
            FROM records r
            LEFT JOIN users u1 ON r.created_by = u1.id
            LEFT JOIN users u2 ON r.updated_by = u2.id
            WHERE 1=1
        """
        params = []
        
        # Add search conditions
        if op_number:
            query += " AND CAST(r.op_number AS VARCHAR) LIKE ?"
            params.append(f'%{op_number}%')
            
        if name:
            query += " AND r.name LIKE ?"
            params.append(f'%{name}%')
            
        if id1:
            query += " AND r.id1 LIKE ?"
            params.append(f'%{id1}%')
            
        if id2:
            query += " AND r.id2 LIKE ?"
            params.append(f'%{id2}%')
            
        if date_from:
            query += " AND r.created_at >= ?"
            params.append(date_from)
            
        if date_to:
            query += " AND r.created_at <= ?"
            params.append(date_to)
            
        if status:
            query += " AND r.status = ?"
            params.append(status)
            
        query += " ORDER BY r.created_at DESC"
        
        cursor.execute(query, params)
        records = cursor.fetchall()
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow([
            'OP Number', 'Name', 'ID 1', 'ID 2', 
            'Description', 'Status', 
            'Created At', 'Created By',
            'Updated At', 'Updated By'
        ])
        
        # Write data
        for record in records:
            writer.writerow([
                record[0],  # op_number
                record[1],  # name
                record[2],  # id1
                record[3],  # id2
                record[4],  # description
                record[5],  # status
                record[6].strftime('%Y-%m-%d %H:%M:%S') if record[6] else '',  # created_at
                record[7],  # created_by
                record[8].strftime('%Y-%m-%d %H:%M:%S') if record[8] else '',  # updated_at
                record[9]   # updated_by
            ])
        
        # Prepare response
        output.seek(0)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=op_export_{timestamp}.csv'
            }
        )
        
    except Exception as e:
        app_logger.error(f"Export error: {str(e)}")
        return jsonify({'error': 'An error occurred during export'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/export-csv', methods=['GET'])
@login_required
@has_permission('export_results')
def export_csv():
    try:
        # Get search parameters (same as search_ops)
        op_number = request.args.get('op_number', '').strip()
        name = request.args.get('name', '').strip()
        id1 = request.args.get('id1', '').strip()
        id2 = request.args.get('id2', '').strip()
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build the base query
        query = """
            SELECT op_number, name, id1, id2, created_at
            FROM records
            WHERE 1=1
        """
        params = []
        
        # Add search conditions
        if op_number:
            query += " AND CAST(op_number AS VARCHAR) LIKE ?"
            params.append(f'%{op_number}%')
            
        if name:
            query += " AND name LIKE ?"
            params.append(f'%{name}%')
            
        if id1:
            query += " AND id1 LIKE ?"
            params.append(f'%{id1}%')
            
        if id2:
            query += " AND id2 LIKE ?"
            params.append(f'%{id2}%')
            
        if date_from:
            query += " AND created_at >= ?"
            params.append(date_from)
            
        if date_to:
            query += " AND created_at <= ?"
            params.append(date_to)
        
        # Add sorting
        sort_column = {
            'op_number': 'op_number',
            'name': 'name',
            'id1': 'id1',
            'id2': 'id2',
            'created_at': 'created_at'
        }.get(sort_by, 'created_at')
        
        query += f" ORDER BY {sort_column} {sort_order.upper()}"
        
        # Execute query
        cursor.execute(query, params)
        records = cursor.fetchall()
        
        # Create CSV in memory
        si = io.StringIO()
        csv_writer = csv.writer(si)
        
        # Write headers
        csv_writer.writerow(['OP Number', 'Name', 'ID1', 'ID2', 'Created At'])
        
        # Write data
        for record in records:
            csv_writer.writerow([
                record[0],
                record[1],
                record[2],
                record[3],
                record[4].strftime('%Y-%m-%d %H:%M:%S') if record[4] else ''
            ])
        
        # Create the response
        output = si.getvalue()
        si.close()
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'op_records_{timestamp}.csv'
        
        # Log the export
        audit_logger.log_action('export_csv', session['user_id'], 
                              details={'filename': filename, 'record_count': len(records)})
        
        # Return CSV file
        response = Response(output)
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        response.headers['Content-type'] = 'text/csv'
        return response
        
    except Exception as e:
        error_logger.exception("CSV export error")
        return jsonify({
            'success': False,
            'error': 'An error occurred while exporting data'
        }), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    init_db()  # This will recreate the table and sequence
    app.run(debug=True)
