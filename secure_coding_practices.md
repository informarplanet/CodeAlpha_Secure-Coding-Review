# Secure Coding Practices Guide

## 1. Input Validation and Sanitization

### Bad Practice:
```python
# Vulnerable to SQL injection
query = f"SELECT * FROM users WHERE username='{username}'"
```

### Good Practice:
```python
# Using parameterized queries
cursor.execute("SELECT * FROM users WHERE username=?", (username,))

# Using SQLAlchemy ORM
user = User.query.filter_by(username=username).first()
```

## 2. Password Security

### Bad Practice:
```python
# Weak hashing
password_hash = hashlib.md5(password.encode()).hexdigest()
```

### Good Practice:
```python
# Using bcrypt for secure password hashing
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)
```

## 3. Secure File Operations

### Bad Practice:
```python
# Vulnerable to path traversal
file_path = f"user_files/{filename}"
with open(file_path, 'r') as f:
    data = f.read()
```

### Good Practice:
```python
from pathlib import Path
import os

def safe_file_read(filename, base_dir):
    try:
        # Resolve the full path and check if it's within base_dir
        file_path = Path(base_dir) / filename
        safe_path = file_path.resolve()
        if not str(safe_path).startswith(str(Path(base_dir).resolve())):
            raise ValueError("Invalid file path")
        return safe_path.read_text()
    except (IOError, ValueError) as e:
        logging.error(f"File access error: {e}")
        raise
```

## 4. Session Management

### Bad Practice:
```python
# Insecure session configuration
app.secret_key = "hardcoded_secret"
```

### Good Practice:
```python
# Secure session configuration
app.config.update(
    SECRET_KEY=os.urandom(24),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)
```

## 5. Error Handling

### Bad Practice:
```python
try:
    # some code
except Exception as e:
    return str(e)  # Exposes internal details
```

### Good Practice:
```python
import logging

try:
    # some code
except Exception as e:
    logging.error(f"Internal error: {str(e)}")
    return {"error": "An internal error occurred"}, 500
```

## 6. API Security

### Bad Practice:
```python
@app.route('/api/data')
def get_data():
    return sensitive_data
```

### Good Practice:
```python
from functools import wraps
from flask import request

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or not validate_api_key(api_key):
            return {'error': 'Invalid API key'}, 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/data')
@require_api_key
def get_data():
    return jsonify(data)
```

## 7. Rate Limiting

### Good Practice:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route("/login")
@limiter.limit("5 per minute")
def login():
    # login logic
```

## 8. Secure Headers

### Good Practice:
```python
from flask_talisman import Talisman

Talisman(app,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'",
    },
    force_https=True
)
```

## 9. Logging Best Practices

### Good Practice:
```python
import logging

logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_activity(user_id, action):
    logging.info(f"User {user_id} performed {action}")
    # Don't log sensitive data like passwords
```

## 10. Input Validation Decorators

### Good Practice:
```python
from functools import wraps
from marshmallow import Schema, fields, ValidationError

class UserSchema(Schema):
    username = fields.Str(required=True)
    email = fields.Email(required=True)

def validate_json(schema):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                schema.load(request.get_json())
            except ValidationError as err:
                return {"errors": err.messages}, 400
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/user', methods=['POST'])
@validate_json(UserSchema())
def create_user():
    # Process validated data
```

## Security Checklist

1. **Authentication**
   - ✓ Use strong password hashing (bcrypt/Argon2)
   - ✓ Implement MFA where possible
   - ✓ Set secure session configurations
   - ✓ Use rate limiting for login attempts

2. **Data Protection**
   - ✓ Use parameterized queries
   - ✓ Encrypt sensitive data
   - ✓ Validate file uploads
   - ✓ Implement proper access controls

3. **Error Handling**
   - ✓ Use try-except blocks
   - ✓ Log errors securely
   - ✓ Return generic error messages
   - ✓ Set up proper logging

4. **Configuration**
   - ✓ Use environment variables
   - ✓ Implement secure headers
   - ✓ Enable HTTPS
   - ✓ Set secure cookie flags

5. **Code Quality**
   - ✓ Use static code analysis
   - ✓ Regular security updates
   - ✓ Code review process
   - ✓ Security testing
