from flask import Flask, request, render_template_string, session
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = "mysecretkey123"  # Vulnerable: Hardcoded secret key

# Vulnerable: SQL injection possible
def get_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()

# Vulnerable: Weak password hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerable: Direct use of user input in SQL query
        user = get_user(username, password)
        
        if user:
            session['username'] = username
            return f"Welcome {username}!"
    
    # Vulnerable: Template injection
    return render_template_string('''
        <form method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit" value="Login">
        </form>
    ''' + request.args.get('message', ''))

@app.route('/user_data')
def user_data():
    # Vulnerable: No authentication check
    filename = request.args.get('filename')
    # Vulnerable: Path traversal
    with open(filename, 'r') as f:
        return f.read()

if __name__ == '__main__':
    app.run(debug=True)  # Vulnerable: Debug mode enabled in production
