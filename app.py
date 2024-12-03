from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from datetime import datetime
import pyodbc
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from functools import wraps
import os
import logging
from flask_restful import Api, Resource, reqparse
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask_apispec.extension import FlaskApiSpec
from flask_apispec.views import MethodResource
from flask_apispec import marshal_with, doc, use_kwargs
from marshmallow import Schema, fields
import io
import csv
from flask import Response

# Set up logging
logging.basicConfig(
    filename='api.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Load API token from environment
api_token = os.getenv('API_TOKEN')
if not api_token:
    api_token = 'your-secret-api-token'
    logging.warning(f"API_TOKEN not found in .env file. Using default token: {api_token}")
else:
    logging.info(f"Loaded API token from .env: {api_token}")

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
    username = fields.Str(required(True, metadata={'description': 'Username'})
    password = fields.Str(required=True, metadata={'description': 'Password'})
    full_name = fields.Str(required=True, metadata={'description': 'Full Name'})

class UserResponseSchema(Schema):
    success = fields.Bool()
    message = fields.Str()

# Database connection
def get_db_connection():
    server = os.getenv("DB_SERVER", "localhost")
    database = os.getenv("DB_NAME", "OpGenerator")
    conn_str = (
        f"Driver={{ODBC Driver 17 for SQL Server}};"
        f"Server={server};"
        f"Database={database};"
        "Trusted_Connection=yes;"
    )
    return pyodbc.connect(conn_str)

# Create table if not exists
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Drop existing tables to start fresh
        cursor.execute('''
            IF OBJECT_ID('records', 'U') IS NOT NULL DROP TABLE records;
            IF OBJECT_ID('users', 'U') IS NOT NULL DROP TABLE users;
            IF OBJECT_ID('api_users', 'U') IS NOT NULL DROP TABLE api_users;
        ''')
        
        # Create records table
        cursor.execute('''
            CREATE TABLE records (
                id INT IDENTITY(1,1) PRIMARY KEY,
                name NVARCHAR(100),
                id1 NVARCHAR(50),
                id2 NVARCHAR(50),
                op_number INT,
                created_at DATETIME DEFAULT GETDATE()
            )
        ''')
        
        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                id INT IDENTITY(1,1) PRIMARY KEY,
                username NVARCHAR(50) UNIQUE,
                password_hash NVARCHAR(200),
                full_name NVARCHAR(100),
                is_admin BIT DEFAULT 0,
                is_approved BIT DEFAULT 0,
                is_disabled BIT DEFAULT 0,
                vacation_start DATETIME NULL,
                vacation_end DATETIME NULL,
                created_at DATETIME DEFAULT GETDATE()
            )
        ''')

        # Create api_users table
        cursor.execute('''
            CREATE TABLE api_users (
                id INT IDENTITY(1,1) PRIMARY KEY,
                username NVARCHAR(50) UNIQUE,
                password_hash NVARCHAR(200),
                api_token NVARCHAR(200) UNIQUE,
                created_at DATETIME DEFAULT GETDATE()
            )
        ''')

        # Create sessions table
        cursor.execute('''
            CREATE TABLE sessions (
                id INT IDENTITY(1,1) PRIMARY KEY,
                user_id INT FOREIGN KEY REFERENCES users(id),
                ip_address NVARCHAR(50),
                computer_name NVARCHAR(100),
                login_time DATETIME,
                logout_time DATETIME NULL
            )
        ''')

        # Create default admin user (automatically approved)
        admin_password = generate_password_hash('admin')
        cursor.execute('''
            INSERT INTO users (username, password_hash, full_name, is_admin, is_approved)
            VALUES (?, ?, ?, 1, 1)
        ''', ('admin', admin_password, 'Administrator'))
        
        conn.commit()
        logging.info("Database initialized successfully with admin user")
        
    except Exception as e:
        logging.error(f"Error initializing database: {str(e)}")
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.close()

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
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
        logging.info(f"Received token: {token}")
        
        if not token:
            logging.warning("No token provided")
            return {'error': 'API token required'}, 401
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM api_users WHERE api_token = ?', (token,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user:
            logging.warning("Invalid token provided")
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
        'id2': fields.Str(required(False, metadata={'description': 'Second identifier to search for'})
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
        cursor.execute('SELECT id, password_hash FROM api_users WHERE username = ?', (username,))
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
            INSERT INTO api_users (username, password_hash)
            VALUES (?, ?)
        ''', (username, password_hash))
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT id, password_hash, is_admin, full_name, is_approved, is_disabled, vacation_start, vacation_end FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'error': 'Invalid username or password'}), 401
            
        if not check_password_hash(user[1], password):
            return jsonify({'error': 'Invalid username or password'}), 401
            
        if not user[4] and not user[2]:  # not approved and not admin
            return jsonify({'error': 'Your account is pending approval. Please contact the administrator.'}), 403
            
        if user[5]:  # is_disabled
            return jsonify({'error': 'Your account is disabled. Please contact the administrator.'}), 403
            
        # Check if user is on vacation
        current_time = datetime.now()
        if user[6] and user[7] and user[6] <= current_time <= user[7]:
            return jsonify({'error': f'Your account is on vacation until {user[7].strftime("%Y-%m-%d")}. Please contact the administrator.'}), 403
        
        session['user_id'] = user[0]
        session['is_admin'] = bool(user[2])
        session['username'] = username
        session['full_name'] = user[3]
        
        # Log IP address and computer name
        ip_address = request.remote_addr
        computer_name = request.user_agent.platform
        try:
            cursor.execute('''
                INSERT INTO sessions (user_id, ip_address, computer_name, login_time)
                VALUES (?, ?, ?, ?)
            ''', (user[0], ip_address, computer_name, datetime.now()))
            conn.commit()
        except Exception as e:
            logging.error(f"Error inserting session: {str(e)}")
            return jsonify({'error': 'Database error occurred'}), 500
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Login successful', 'is_admin': bool(user[2]), 'full_name': user[3]})
        else:
            return redirect(url_for('admin_dashboard' if bool(user[2]) else 'index'))
    
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Database error occurred'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
@login_required
def generate():
    data = request.json
    name = data.get('name')
    id1 = data.get('id1')
    id2 = data.get('id2')
    
    if not all([name, id1, id2]):
        return jsonify({'error': 'All fields are required'}), 400
    
    # Validate ID1 and ID2 are numbers only
    if not id1.isdigit() or not id2.isdigit():
        return jsonify({'error': 'ID1 and ID2 must contain numbers only'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if the same data exists
        cursor.execute(
            'SELECT op_number FROM records WHERE name = ? AND id1 = ? AND id2 = ?',
            (name, id1, id2)
        )
        existing_record = cursor.fetchone()
        
        if existing_record:
            return jsonify({
                'op_number': existing_record[0],
                'message': 'Record already exists'
            })
        
        # Get next OP number
        cursor.execute("SELECT NEXT VALUE FOR OpNumberSequence")
        op_number = cursor.fetchone()[0]
        
        # Insert new record
        cursor.execute(
            'INSERT INTO records (name, id1, id2, op_number) VALUES (?, ?, ?, ?)',
            (name, id1, id2, op_number)
        )
        conn.commit()
        
        return jsonify({
            'op_number': op_number,
            'message': 'New record created'
        })
    except pyodbc.Error as e:
        logging.error(f"Database error during generation: {str(e)}")
        conn.rollback()
        return jsonify({'error': 'Database error occurred'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/search', methods=['GET'])
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
        logging.error(f"Search error: {str(e)}")
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
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    full_name = data.get('full_name')
    
    if not username or not password or not full_name:
        return jsonify({'error': 'All fields are required'}), 400
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if username already exists
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Username already exists'}), 400
            
        # Create new user with is_approved = 0
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, password_hash, full_name)
            VALUES (?, ?, ?)
        ''', (username, password_hash, full_name))
        
        conn.commit()
        return jsonify({
            'success': True, 
            'message': 'Account created successfully. Please wait for administrator approval before logging in.'
        })
    
    except pyodbc.Error as e:
        logging.error(f"Database error during signup: {str(e)}")
        conn.rollback()
        return jsonify({'error': 'Database error occurred'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get regular users (excluding current admin)
        cursor.execute("""
            SELECT username, full_name, is_approved, is_admin, is_disabled 
            FROM users 
            WHERE username != ? 
            ORDER BY created_at DESC
        """, (session['username'],))
        users = [{
            'username': row[0], 
            'full_name': row[1], 
            'is_approved': bool(row[2]),
            'is_admin': bool(row[3]),
            'is_disabled': bool(row[4])
        } for row in cursor.fetchall()]
        
        # Get API users from api_users table
        cursor.execute("""
            SELECT username, api_token 
            FROM api_users 
            ORDER BY created_at DESC
        """)
        api_users = [{'username': row[0], 'token': row[1]} for row in cursor.fetchall()]
        
        # Get statistics
        cursor.execute("SELECT COUNT(*) FROM records")
        total_ops = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT COUNT(*) FROM records WHERE CAST(created_at AS DATE) = CAST(GETDATE() AS DATE)")
        today_ops = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT TOP 1 op_number FROM records ORDER BY op_number DESC")
        last_op_row = cursor.fetchone()
        last_op = last_op_row[0] if last_op_row else 0
        
        stats = {
            'total_ops': total_ops,
            'today_ops': today_ops,
            'last_op': last_op
        }

        # Get session information
        cursor.execute("""
            SELECT u.username, s.ip_address, s.computer_name, s.login_time
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.login_time DESC
        """)
        sessions = cursor.fetchall()
        
        return render_template('admin.html', users=users, api_users=api_users, stats=stats, sessions=sessions)
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<username>/approve', methods=['POST'])
@admin_required
def approve_user(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE users SET is_approved = 1 WHERE username = ? AND is_admin = 0", (username,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        conn.rollback()
        logging.error(f"Error approving user: {str(e)}")
        return jsonify({'error': 'Database error occurred'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM users WHERE username = ? AND is_admin = 0", (username,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/api-user/<username>', methods=['DELETE'])
@admin_required
def delete_api_user(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM api_users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/api-user/<username>/token', methods=['POST'])
@admin_required
def regenerate_token(username):
    new_token = secrets.token_hex(32)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("UPDATE api_users SET api_token = ? WHERE username = ?", (new_token, username))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/api-user', methods=['POST'])
@admin_required
def create_api_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Missing username or password'})
    
    hashed_password = generate_password_hash(password)
    api_token = secrets.token_hex(32)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """INSERT INTO api_users 
               (username, password_hash, api_token) 
               VALUES (?, ?, ?)""",
            (username, hashed_password, api_token)
        )
        conn.commit()
        return jsonify({'success': True, 'token': api_token})
    except pyodbc.IntegrityError:
        return jsonify({'success': False, 'error': 'Username already exists'})
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<username>/toggle-admin', methods=['POST'])
@admin_required
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
        logging.error(f"Error toggling admin status: {str(e)}")
        return jsonify({'error': 'Database error occurred'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<username>/toggle-disabled', methods=['POST'])
@admin_required
def toggle_disabled(username):
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Cannot disable admin user'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Get current disabled status
        cursor.execute('SELECT is_disabled FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        
        if not result:
            return jsonify({'success': False, 'message': 'User not found'}), 404
            
        new_status = not result[0]
        
        # Update disabled status
        cursor.execute('''
            UPDATE users 
            SET is_disabled = ?
            WHERE username = ?
        ''', (new_status, username))
        
        conn.commit()
        status_text = 'disabled' if new_status else 'enabled'
        return jsonify({
            'success': True, 
            'message': f'User {username} has been {status_text}',
            'is_disabled': new_status
        })
        
    except Exception as e:
        conn.rollback()
        logging.error(f"Error toggling user disabled status: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/search-page')
@login_required
def search_page():
    return render_template('search.html')

@app.route('/export')
@login_required
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
        logging.error(f"Export error: {str(e)}")
        return jsonify({'error': 'An error occurred during export'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<username>/set-vacation', methods=['POST'])
@admin_required
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
        logging.error(f"Error setting vacation period: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/user/<username>/clear-vacation', methods=['POST'])
@admin_required
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
        logging.error(f"Error clearing vacation period: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    init_db()  # This will recreate the table and sequence
    app.run(debug=True)
