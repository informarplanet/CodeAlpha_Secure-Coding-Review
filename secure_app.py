from flask import Flask, request, render_template, session, abort
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
import bcrypt
from pathlib import Path

app = Flask(__name__)
# Secure: Environment variable for secret key
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return abort(401)
        return f(*args, **kwargs)
    return decorated_function

def hash_password(password):
    # Secure: Using bcrypt for password hashing
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    # Secure: Proper password verification
    return bcrypt.checkpw(password.encode(), hashed)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Secure: Using SQLAlchemy ORM to prevent SQL injection
        user = User.query.filter_by(username=username).first()
        
        if user and check_password(password, user.password):
            session['username'] = username
            return render_template('welcome.html', username=username)
    
    # Secure: Using proper template file
    return render_template('login.html')

@app.route('/user_data')
@login_required  # Secure: Authentication required
def user_data():
    filename = request.args.get('filename')
    if not filename:
        return abort(400)
    
    # Secure: Safe file path handling
    safe_path = Path('user_data') / filename
    try:
        safe_path = safe_path.resolve()
        if not str(safe_path).startswith(str(Path('user_data').resolve())):
            return abort(403)
        
        with open(safe_path, 'r') as f:
            return f.read()
    except (IOError, ValueError):
        return abort(404)

if __name__ == '__main__':
    # Secure: Debug mode disabled in production
    is_development = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=is_development)
