# E-commerce Application Vulnerabilities

## 1. Price Manipulation Vulnerability

### Vulnerable Code:
```python
@app.route('/api/checkout', methods=['POST'])
def process_checkout():
    cart_items = request.json.get('items', [])
    total = request.json.get('total')  # Vulnerable: Client-sent total
    
    # Process payment with client-sent total
    process_payment(total)
```

### Secure Code:
```python
@app.route('/api/checkout', methods=['POST'])
@require_auth
def process_checkout():
    cart_items = request.json.get('items', [])
    
    # Recalculate total on server
    total = Decimal('0.0')
    for item in cart_items:
        product = Product.query.get(item['product_id'])
        if not product:
            return jsonify({'error': 'Invalid product'}), 400
        total += product.price * Decimal(str(item['quantity']))
    
    # Process payment with server-calculated total
    process_payment(total)
```

## 2. Race Condition in Stock Management

### Vulnerable Code:
```python
@app.route('/api/purchase', methods=['POST'])
def purchase_item():
    product_id = request.json.get('product_id')
    quantity = request.json.get('quantity')
    
    product = Product.query.get(product_id)
    if product.stock >= quantity:
        product.stock -= quantity
        db.session.commit()
        return jsonify({'success': True})
```

### Secure Code:
```python
from sqlalchemy import and_
from contextlib import contextmanager

@contextmanager
def db_transaction():
    try:
        yield
        db.session.commit()
    except:
        db.session.rollback()
        raise

@app.route('/api/purchase', methods=['POST'])
def purchase_item():
    product_id = request.json.get('product_id')
    quantity = request.json.get('quantity')
    
    with db_transaction():
        # Lock the row for update
        product = Product.query.with_for_update().get(product_id)
        if not product or product.stock < quantity:
            return jsonify({'error': 'Insufficient stock'}), 400
            
        product.stock -= quantity
        create_order(product_id, quantity)
```

## 3. Insecure Direct Object Reference (IDOR)

### Vulnerable Code:
```python
@app.route('/api/orders/<order_id>')
def get_order(order_id):
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())
```

### Secure Code:
```python
@app.route('/api/orders/<order_id>')
@require_auth
def get_order(current_user, order_id):
    order = Order.query.filter_by(
        id=order_id, 
        user_id=current_user.id
    ).first()
    
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    return jsonify(order.to_dict())
```

## 4. SQL Injection in Search

### Vulnerable Code:
```python
@app.route('/api/products/search')
def search_products():
    query = request.args.get('q')
    sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
    results = db.engine.execute(sql)
    return jsonify([dict(row) for row in results])
```

### Secure Code:
```python
@app.route('/api/products/search')
def search_products():
    query = request.args.get('q', '')
    products = Product.query.filter(
        Product.name.ilike(f'%{query}%')
    ).all()
    return jsonify(products)
```

## 5. Cross-Site Request Forgery (CSRF)

### Vulnerable Code:
```python
@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    user = get_current_user()
    user.email = request.form['email']
    db.session.commit()
```

### Secure Code:
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

@app.route('/api/update-profile', methods=['POST'])
@csrf.exempt
@require_auth
def update_profile(current_user):
    if not validate_email(request.json.get('email')):
        return jsonify({'error': 'Invalid email'}), 400
        
    current_user.email = request.json['email']
    db.session.commit()
```

## 6. Sensitive Data Exposure in Orders

### Vulnerable Code:
```python
@app.route('/api/orders/<order_id>')
def get_order_details(order_id):
    order = Order.query.get(order_id)
    return jsonify({
        'id': order.id,
        'user': order.user.to_dict(),  # Exposes all user data
        'payment': order.payment_details,  # Exposes payment info
        'items': order.items
    })
```

### Secure Code:
```python
@app.route('/api/orders/<order_id>')
@require_auth
def get_order_details(current_user, order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id
    ).first()
    
    if not order:
        return jsonify({'error': 'Order not found'}), 404
        
    return jsonify({
        'id': order.id,
        'status': order.status,
        'total': str(order.total),
        'items': [{
            'product_name': item.product.name,
            'quantity': item.quantity,
            'price': str(item.price)
        } for item in order.items]
    })
```

## 7. Mass Assignment Vulnerability

### Vulnerable Code:
```python
@app.route('/api/products', methods=['POST'])
def create_product():
    product = Product(**request.json)
    db.session.add(product)
    db.session.commit()
```

### Secure Code:
```python
@app.route('/api/products', methods=['POST'])
@require_admin
def create_product(current_user):
    allowed_fields = {'name', 'price', 'stock'}
    product_data = {
        k: v for k, v in request.json.items() 
        if k in allowed_fields
    }
    
    if not all(k in product_data for k in allowed_fields):
        return jsonify({'error': 'Missing required fields'}), 400
        
    try:
        product = Product(
            name=product_data['name'],
            price=Decimal(str(product_data['price'])),
            stock=int(product_data['stock'])
        )
        db.session.add(product)
        db.session.commit()
    except (ValueError, decimal.InvalidOperation):
        return jsonify({'error': 'Invalid data format'}), 400
```

## 8. Improper Inventory Management

### Vulnerable Code:
```python
@app.route('/api/cart/add', methods=['POST'])
def add_to_cart():
    product_id = request.json.get('product_id')
    quantity = request.json.get('quantity', 1)
    
    cart = session.get('cart', {})
    cart[product_id] = cart.get(product_id, 0) + quantity
    session['cart'] = cart
```

### Secure Code:
```python
@app.route('/api/cart/add', methods=['POST'])
@require_auth
def add_to_cart(current_user):
    product_id = request.json.get('product_id')
    quantity = request.json.get('quantity', 1)
    
    try:
        quantity = int(quantity)
        if quantity <= 0:
            return jsonify({'error': 'Invalid quantity'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid quantity'}), 400
        
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
        
    if product.stock < quantity:
        return jsonify({'error': 'Insufficient stock'}), 400
        
    cart = CartItem.query.filter_by(
        user_id=current_user.id,
        product_id=product_id
    ).first()
    
    if cart:
        if cart.quantity + quantity > product.stock:
            return jsonify({'error': 'Insufficient stock'}), 400
        cart.quantity += quantity
    else:
        cart = CartItem(
            user_id=current_user.id,
            product_id=product_id,
            quantity=quantity
        )
        db.session.add(cart)
    
    db.session.commit()
```

## Security Recommendations

1. **Input Validation**
   - Validate all user inputs
   - Use type conversion for numeric values
   - Implement proper sanitization

2. **Authentication & Authorization**
   - Implement proper user authentication
   - Use role-based access control
   - Validate user permissions

3. **Session Management**
   - Use secure session storage
   - Implement proper session timeout
   - Protect against session fixation

4. **Data Protection**
   - Use HTTPS for all transactions
   - Encrypt sensitive data
   - Implement proper access controls

5. **Database Security**
   - Use parameterized queries
   - Implement proper transaction management
   - Protect against SQL injection

6. **Error Handling**
   - Implement proper error handling
   - Don't expose sensitive information in errors
   - Log errors securely

7. **Rate Limiting**
   - Implement rate limiting for APIs
   - Protect against brute force attacks
   - Monitor for unusual activity

8. **Payment Security**
   - Use secure payment gateways
   - Implement proper validation
   - Monitor for fraudulent activity
