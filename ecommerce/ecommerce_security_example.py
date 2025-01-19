from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import re
from typing import Optional
from dataclasses import dataclass
from decimal import Decimal

app = Flask(__name__)

# Secure configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24)),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///ecommerce.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

db = SQLAlchemy(app)
limiter = Limiter(app, key_func=get_remote_address)

# Secure logging configuration
logging.basicConfig(
    filename='ecommerce.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

@dataclass
class User(db.Model):
    id: int
    email: str
    username: str
    role: str
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='customer')
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime)

@dataclass
class Product(db.Model):
    id: int
    name: str
    price: Decimal
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock = db.Column(db.Integer, nullable=False)

@dataclass
class Order(db.Model):
    id: int
    user_id: int
    total: Decimal
    status: str
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Security Middleware
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No authorization token provided'}), 401
        
        try:
            # Remove 'Bearer ' prefix
            token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                raise ValueError('User not found')
            return f(current_user, *args, **kwargs)
        except Exception as e:
            logging.error(f"Auth error: {str(e)}")
            return jsonify({'error': 'Invalid token'}), 401
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No authorization token provided'}), 401
        
        try:
            token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user or current_user.role != 'admin':
                raise ValueError('Unauthorized')
            return f(current_user, *args, **kwargs)
        except Exception as e:
            logging.error(f"Admin auth error: {str(e)}")
            return jsonify({'error': 'Unauthorized'}), 403
    return decorated

# Input validation
def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password: str) -> bool:
    # At least 12 characters, 1 uppercase, 1 lowercase, 1 number, 1 special char
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

# Rate limiting for authentication endpoints
@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        username = data.get('username')

        # Input validation
        if not all([email, password, username]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if not validate_password(password):
            return jsonify({'error': 'Password does not meet security requirements'}), 400

        # Check for existing user
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 409

        # Secure password hashing
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        new_user = User(email=email, username=username, password=hashed)
        db.session.add(new_user)
        db.session.commit()
        
        logging.info(f"New user registered: {email}")
        return jsonify({'message': 'Registration successful'}), 201

    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not all([email, password]):
            return jsonify({'error': 'Missing required fields'}), 400

        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        # Check for account lockout
        if user.failed_login_attempts >= 5:
            if user.last_login_attempt and \
               datetime.utcnow() - user.last_login_attempt < timedelta(minutes=15):
                return jsonify({'error': 'Account temporarily locked'}), 403

            # Reset counter after lockout period
            user.failed_login_attempts = 0

        # Verify password
        if not bcrypt.checkpw(password.encode(), user.password):
            user.failed_login_attempts += 1
            user.last_login_attempt = datetime.utcnow()
            db.session.commit()
            return jsonify({'error': 'Invalid credentials'}), 401

        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.last_login_attempt = datetime.utcnow()
        db.session.commit()

        # Generate JWT token
        token = jwt.encode(
            {
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(hours=1)
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        logging.info(f"User logged in: {email}")
        return jsonify({'token': token})

    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

# Protected routes
@app.route('/api/products', methods=['GET'])
@require_auth
def get_products(current_user):
    try:
        products = Product.query.all()
        return jsonify(products)
    except Exception as e:
        logging.error(f"Error fetching products: {str(e)}")
        return jsonify({'error': 'Failed to fetch products'}), 500

@app.route('/api/orders', methods=['POST'])
@require_auth
@limiter.limit("30 per minute")
def create_order(current_user):
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)

        if not product_id:
            return jsonify({'error': 'Product ID required'}), 400

        # Input validation
        try:
            quantity = int(quantity)
            if quantity <= 0:
                raise ValueError
        except ValueError:
            return jsonify({'error': 'Invalid quantity'}), 400

        # Get product and check stock
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        if product.stock < quantity:
            return jsonify({'error': 'Insufficient stock'}), 400

        # Calculate total
        total = product.price * quantity

        # Create order in transaction
        try:
            order = Order(
                user_id=current_user.id,
                total=total,
                status='pending'
            )
            product.stock -= quantity
            
            db.session.add(order)
            db.session.commit()
            
            logging.info(f"Order created: {order.id} by user {current_user.id}")
            return jsonify({'message': 'Order created', 'order_id': order.id}), 201

        except Exception as e:
            db.session.rollback()
            logging.error(f"Order creation failed: {str(e)}")
            return jsonify({'error': 'Order creation failed'}), 500

    except Exception as e:
        logging.error(f"Order error: {str(e)}")
        return jsonify({'error': 'Order processing failed'}), 500

# Admin routes
@app.route('/api/admin/products', methods=['POST'])
@require_admin
def add_product(current_user):
    try:
        data = request.get_json()
        name = data.get('name')
        price = data.get('price')
        stock = data.get('stock')

        if not all([name, price, stock]):
            return jsonify({'error': 'Missing required fields'}), 400

        # Validate price and stock
        try:
            price = Decimal(price)
            stock = int(stock)
            if price <= 0 or stock < 0:
                raise ValueError
        except ValueError:
            return jsonify({'error': 'Invalid price or stock value'}), 400

        product = Product(name=name, price=price, stock=stock)
        db.session.add(product)
        db.session.commit()

        logging.info(f"Product added: {name} by admin {current_user.id}")
        return jsonify({'message': 'Product added', 'product_id': product.id}), 201

    except Exception as e:
        logging.error(f"Product addition error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to add product'}), 500

@app.route('/api/admin/orders', methods=['GET'])
@require_admin
def get_all_orders(current_user):
    try:
        orders = Order.query.all()
        return jsonify(orders)
    except Exception as e:
        logging.error(f"Error fetching orders: {str(e)}")
        return jsonify({'error': 'Failed to fetch orders'}), 500

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Enable HTTPS
