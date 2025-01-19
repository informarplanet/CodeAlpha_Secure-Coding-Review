from flask import Flask, request, jsonify, session
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = "mysecretkey123"  # Vulnerable: Hardcoded secret key

# Database connection - Vulnerable to SQL injection
def get_db():
    return sqlite3.connect('shop.db')

# Vulnerable: Weak password hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerable: SQL Injection in login
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Vulnerable: Direct string concatenation
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hash_password(password)}'"
    
    conn = get_db()
    cursor = conn.cursor()
    user = cursor.execute(query).fetchone()
    
    if user:
        session['user_id'] = user[0]
        return jsonify({"message": "Login successful"})
    return jsonify({"message": "Invalid credentials"}), 401

# Vulnerable: No input validation
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    
    # Vulnerable: No password strength check
    hashed_password = hash_password(password)
    
    conn = get_db()
    cursor = conn.cursor()
    # Vulnerable: SQL Injection
    query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{hashed_password}', '{email}')"
    cursor.execute(query)
    conn.commit()
    
    return jsonify({"message": "Registration successful"})

# Vulnerable: No authentication check
@app.route('/profile/<user_id>')
def get_profile(user_id):
    # Vulnerable: IDOR (Insecure Direct Object Reference)
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id={user_id}"
    user = cursor.execute(query).fetchone()
    
    if user:
        # Vulnerable: Sensitive data exposure
        return jsonify({
            "id": user[0],
            "username": user[1],
            "password": user[2],  # Exposing hashed password
            "email": user[3],
            "credit_card": user[4]  # Exposing sensitive data
        })
    return jsonify({"message": "User not found"}), 404

# Vulnerable: Price manipulation
@app.route('/checkout', methods=['POST'])
def checkout():
    # Vulnerable: Trusting client-side data
    cart = request.json.get('cart', [])
    total = request.json.get('total')  # Accepting client-side total
    
    # Vulnerable: No server-side validation of prices
    payment_success = process_payment(total)
    
    if payment_success:
        return jsonify({"message": "Order placed successfully"})
    return jsonify({"message": "Payment failed"}), 400

# Vulnerable: File upload
@app.route('/upload-product-image', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({"message": "No image provided"}), 400
        
    image = request.files['image']
    # Vulnerable: No file type validation
    # Vulnerable: No file size check
    # Vulnerable: Unsafe file name
    filename = image.filename
    
    # Vulnerable: Path traversal
    image.save(f'uploads/{filename}')
    return jsonify({"message": "Image uploaded successfully"})

# Vulnerable: Mass assignment
@app.route('/products', methods=['POST'])
def create_product():
    # Vulnerable: No role check
    # Vulnerable: Mass assignment
    product_data = request.json
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Vulnerable: SQL injection
    fields = ', '.join(product_data.keys())
    values = ', '.join(f"'{v}'" for v in product_data.values())
    query = f"INSERT INTO products ({fields}) VALUES ({values})"
    
    cursor.execute(query)
    conn.commit()
    
    return jsonify({"message": "Product created successfully"})

# Vulnerable: XSS in product search
@app.route('/search')
def search_products():
    query = request.args.get('q', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Vulnerable: SQL injection
    sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
    results = cursor.execute(sql).fetchall()
    
    # Vulnerable: XSS (Cross-Site Scripting)
    return f"""
    <h1>Search Results for: {query}</h1>
    <ul>
        {''.join(f'<li>{result[1]}</li>' for result in results)}
    </ul>
    """

# Vulnerable: Race condition in stock management
@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    product_id = request.json.get('product_id')
    quantity = request.json.get('quantity', 1)
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Vulnerable: Race condition
    query = f"SELECT stock FROM products WHERE id={product_id}"
    current_stock = cursor.execute(query).fetchone()[0]
    
    if current_stock >= quantity:
        # Vulnerable: Time-of-check to time-of-use (TOCTOU)
        new_stock = current_stock - quantity
        cursor.execute(f"UPDATE products SET stock={new_stock} WHERE id={product_id}")
        conn.commit()
        return jsonify({"message": "Added to cart"})
    
    return jsonify({"message": "Insufficient stock"}), 400

# Vulnerable: Session management
@app.route('/change-password', methods=['POST'])
def change_password():
    # Vulnerable: No CSRF protection
    # Vulnerable: No current password verification
    new_password = request.json.get('new_password')
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({"message": "Not logged in"}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Vulnerable: Weak password hashing
    hashed_password = hash_password(new_password)
    
    # Vulnerable: SQL injection
    query = f"UPDATE users SET password='{hashed_password}' WHERE id={user_id}"
    cursor.execute(query)
    conn.commit()
    
    return jsonify({"message": "Password updated"})

# Vulnerable: Error handling
@app.errorhandler(Exception)
def handle_error(error):
    # Vulnerable: Exposing stack trace
    return jsonify({
        "error": str(error),
        "stack_trace": str(error.__traceback__)
    }), 500

if __name__ == '__main__':
    # Vulnerable: Debug mode in production
    app.run(debug=True)

"""
Vulnerabilities demonstrated:

1. SQL Injection
   - String concatenation in queries
   - No parameter binding
   - Direct user input in queries

2. Authentication & Authorization
   - Weak password hashing (MD5)
   - No password complexity requirements
   - No rate limiting
   - No session timeout
   - Hardcoded secret key

3. IDOR (Insecure Direct Object Reference)
   - Direct access to user profiles
   - No authorization checks
   - Sensitive data exposure

4. XSS (Cross-Site Scripting)
   - Unescaped user input in HTML
   - Direct rendering of search queries

5. CSRF (Cross-Site Request Forgery)
   - No CSRF tokens
   - No origin validation

6. File Upload Vulnerabilities
   - No file type validation
   - No size limits
   - Path traversal possible
   - Unsafe filenames

7. Mass Assignment
   - Direct object creation from user input
   - No field filtering

8. Race Conditions
   - Stock management vulnerability
   - TOCTOU (Time of check to time of use)

9. Error Handling
   - Stack trace exposure
   - Detailed error messages

10. Security Misconfigurations
    - Debug mode enabled
    - Hardcoded credentials
    - Weak session management

11. Sensitive Data Exposure
    - Password hashes visible
    - Credit card info exposed
    - Detailed error messages

12. Business Logic Flaws
    - Price manipulation possible
    - Client-side total acceptance
    - No server-side validation

To exploit these vulnerabilities:

1. SQL Injection:
   username: admin' OR '1'='1
   password: anything

2. IDOR:
   Access /profile/1, /profile/2 etc.

3. XSS:
   Search: <script>alert('xss')</script>

4. Path Traversal:
   filename: ../../../etc/passwd

5. Price Manipulation:
   Modify cart total in request

6. Mass Assignment:
   Add admin fields in product creation

7. Race Condition:
   Concurrent add-to-cart requests
"""
