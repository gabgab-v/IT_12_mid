from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from functools import wraps
from datetime import datetime, timedelta
from sqlalchemy import extract, func

# Initialize Flask and extensions
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dadadada'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # No need for 'main_routes.login'

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'cashier', 'inventory'

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    products = db.relationship('Product', backref='category', lazy=True)

    def __repr__(self):
        return f"Category('{self.name}')"

# Updated Product model with purchase_location
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)  # Selling price
    original_price = db.Column(db.Float, nullable=False)  # Original cost price
    stock = db.Column(db.Integer, nullable=False)
    purchase_location = db.Column(db.String(100), nullable=True)  # e.g., 'Supermarket A', 'Market B'
    is_voided = db.Column(db.Boolean, default=False)  # For voiding items
    deleted = db.Column(db.Boolean, default=False)  # For archiving
    expiration_date = db.Column(db.Date, nullable=True)  # New field for expiration date
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

    def __repr__(self):
        return f"Product('{self.name}', '{self.price}', '{self.original_price}', '{self.stock}', '{self.purchase_location}', '{self.is_voided}', '{self.deleted}', '{self.expiration_date}')"

# Transaction model remains the same
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # For product transactions
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    product = db.relationship('Product', backref='transactions', lazy=True)
    quantity = db.Column(db.Integer, nullable=True)

    # For print service transactions
    print_service_id = db.Column(db.Integer, db.ForeignKey('print_service.id'), nullable=True)
    print_service = db.relationship('PrintService', backref='transactions', lazy=True)
    pages = db.Column(db.Integer, nullable=True)
    back_to_back = db.Column(db.Boolean, default=False)

    # For both product and loading transactions
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

    # New fields for loading transactions
    is_loading = db.Column(db.Boolean, default=False)
    service_provider = db.Column(db.String(50), nullable=True)
    amount_loaded = db.Column(db.Float, nullable=True)

    # Foreign keys to the new models
    transaction_type_id = db.Column(db.Integer, db.ForeignKey('transaction_type.id'), nullable=True)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=True)

    def __init__(self, user_id, total_price, is_loading=False, product_id=None, quantity=None, print_service_id=None, pages=None, back_to_back=False, service_provider=None, amount_loaded=None, transaction_type_id=None, location_id=None):
        self.user_id = user_id
        self.total_price = total_price
        self.is_loading = is_loading
        self.product_id = product_id
        self.quantity = quantity
        self.print_service_id = print_service_id
        self.pages = pages
        self.back_to_back = back_to_back
        self.service_provider = service_provider
        self.amount_loaded = amount_loaded
        self.transaction_type_id = transaction_type_id
        self.location_id = location_id


class ArchivedProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    original_price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    purchase_location = db.Column(db.String(100), nullable=True)
    deleted = db.Column(db.Boolean, default=True)  # Indicates if this product was archived
    
    def __repr__(self):
        return f"ArchivedProduct('{self.name}', '{self.price}', '{self.original_price}', '{self.stock}', '{self.purchase_location}', '{self.deleted}')"

# Table for transaction types (e.g., 'normal', 'gcash')
class TransactionType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)  # e.g., 'normal', 'gcash'
    
    def __repr__(self):
        return f"TransactionType('{self.name}')"

# Table for locations (e.g., where the loading took place)
class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)  # e.g., 'Shop A', 'Mall B'

    def __repr__(self):
        return f"Location('{self.name}')"

class LoadingTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount_loaded = db.Column(db.Float, nullable=False)
    service_provider = db.Column(db.String(100), nullable=False)  # 'Globe', 'Smart', 'GCash'
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

    # Foreign key to transaction type
    transaction_type_id = db.Column(db.Integer, db.ForeignKey('transaction_type.id'), nullable=False)
    transaction_type = db.relationship('TransactionType', backref='loading_transactions', lazy=True)

    # Foreign key to location (nullable)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=True)
    location = db.relationship('Location', backref='loading_transactions', lazy=True)

    # Foreign key to restock event (nullable)
    restock_id = db.Column(db.Integer, db.ForeignKey('restock.id'), nullable=True)
    restock = db.relationship('Restock', backref='load_transactions', lazy=True)

    def __repr__(self):
        return f"LoadingTransaction('{self.amount_loaded}', '{self.service_provider}', '{self.transaction_type.name}', '{self.timestamp}')"

class LoadBalance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    normal_load = db.Column(db.Float, nullable=False, default=0.0)  # Track normal load balance
    gcash_balance = db.Column(db.Float, nullable=False, default=0.0)  # Track GCash balance

    def __repr__(self):
        return f"LoadBalance('Normal Load: {self.normal_load}', 'GCash: {self.gcash_balance}')"


class PrintService(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_type = db.Column(db.String(100), nullable=False)  # e.g., 'Photocopy', 'Black and White Print'
    price_per_page = db.Column(db.Float, nullable=False)
    admin_price_override = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

    def __repr__(self):
        return f"PrintService('{self.service_type}', '{self.price_per_page}', '{self.admin_price_override}', '{self.timestamp}')"


class InkInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # e.g., 'Black Ink', 'Colored Ink'
    stock = db.Column(db.Integer, nullable=False)  # Number of ink cartridges/bottles
    amount_spent = db.Column(db.Float, nullable=False)  # Total cost for the ink purchase
    purchase_location = db.Column(db.String(100), nullable=False)  # Where the ink was bought
    last_restock_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

    def __repr__(self):
        return f"InkInventory('{self.name}', '{self.stock}', '{self.amount_spent}', '{self.purchase_location}', '{self.last_restock_date}')"


class PaperInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rim_count = db.Column(db.Integer, nullable=False)  # Number of full paper rims
    individual_paper_count = db.Column(db.Integer, nullable=False)  # Track per sheet
    amount_spent = db.Column(db.Float, nullable=False)  # Total cost for the paper purchase
    last_restock_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    
    # Foreign key to track the paper type
    paper_type_id = db.Column(db.Integer, db.ForeignKey('paper_type.id'), nullable=False)
    paper_type = db.relationship('PaperType', backref='inventory_items', lazy=True)
    
    # Foreign key to location where paper was purchased
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    location = db.relationship('Location', backref='paper_inventory', lazy=True)

    def __repr__(self):
        return f"PaperInventory('{self.paper_type.size}', '{self.rim_count}', '{self.individual_paper_count}', '{self.amount_spent}', '{self.location.name}', '{self.last_restock_date}')"

class PrintTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_type = db.Column(db.String(50), nullable=False)  # Type of service (e.g., photocopy, black & white print)
    pages = db.Column(db.Integer, nullable=False)  # Number of pages/sheets used
    back_to_back = db.Column(db.Boolean, default=False)  # Whether printing is back-to-back
    total_price = db.Column(db.Float, nullable=False)  # Total price charged to the customer
    profit = db.Column(db.Float, nullable=False)  # Profit from the transaction
    ink_used = db.Column(db.Float, nullable=False)  # Amount of ink used in this transaction
    paper_used = db.Column(db.Integer, nullable=False)  # Number of paper sheets used
    total_cost = db.Column(db.Float, nullable=False)  # Total cost of materials used
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"PrintTransaction('{self.service_type}', '{self.pages}', '{self.total_price}', '{self.profit}', '{self.timestamp}')"


class Restock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restock_amount = db.Column(db.Float, nullable=False)  # Amount of items restocked
    restock_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    amount_spent = db.Column(db.Float, nullable=False)  # Total cost of the restock
    restock_location = db.Column(db.String(100), nullable=False)  # Where the items were restocked

    # Foreign keys for both ink, paper, and product inventories, only one will be filled based on restock type
    ink_inventory_id = db.Column(db.Integer, db.ForeignKey('ink_inventory.id'), nullable=True)
    paper_inventory_id = db.Column(db.Integer, db.ForeignKey('paper_inventory.id'), nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)

    # Type of inventory being restocked (either 'ink', 'paper', or 'product')
    inventory_type = db.Column(db.String(20), nullable=False)  # 'ink', 'paper', 'product'

    # Relationships to InkInventory, PaperInventory, and Product models
    ink_inventory = db.relationship('InkInventory', backref=db.backref('restocks', lazy=True))
    paper_inventory = db.relationship('PaperInventory', backref=db.backref('restocks', lazy=True))
    product = db.relationship('Product', backref=db.backref('restocks', lazy=True))

    def __repr__(self):
        return f"Restock('{self.restock_amount}', '{self.restock_date}', '{self.amount_spent}', '{self.restock_location}', '{self.inventory_type}')"


class PaperType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    size = db.Column(db.String(20), nullable=False)  # e.g., 'A4', 'F4'
    description = db.Column(db.String(100), nullable=True)  # Additional description if needed (e.g., 'Bond Paper', 'Glossy')

    def __repr__(self):
        return f"PaperType('{self.size}', '{self.description}')"

# class LoadBalance(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     service_provider = db.Column(db.String(100), nullable=False)  # e.g., 'Globe', 'Smart'
#     balance = db.Column(db.Float, nullable=False)
#     last_updated = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())


   
# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Custom decorator to restrict access to admin users
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.role == 'admin':
            return f(*args, **kwargs)
        else:
            abort(403)  # Forbidden
    return decorated_function

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']  # Access username field directly
        password = request.form['password']  # Access password field directly
        
        # Look up the user by username instead of email
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(f'Welcome {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Check username and password', 'danger')
    
    # Check if any admin user exists
    admin_exists = User.query.filter_by(role='admin').first() is not None

    return render_template('login.html', admin_exists=admin_exists)


@app.route('/register', methods=['GET', 'POST'])
@login_required
@admin_required
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form.get('role')  # Get role from the form

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        # Check if the email already exists
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        # Hash the password and create a new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('register.html')  # Render the correct registration form


@app.route('/first_admin', methods=['GET', 'POST'])
def first_admin():
    # Check if an admin user already exists
    admin_exists = User.query.filter_by(role='admin').first() is not None

    # If an admin already exists, redirect to login or another page
    if admin_exists:
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('first_admin.html')

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with this email already exists.', 'danger')
            return render_template('first_admin.html')

        # Create the first admin user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_admin = User(username=username, email=email, password=hashed_password, role='admin')
        db.session.add(new_admin)
        db.session.commit()

        flash('Admin user created successfully. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('first_admin.html')



@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('another_dashboard'))
    elif current_user.role == 'cashier':
        return redirect(url_for('cashier_dashboard'))
    elif current_user.role == 'inventory':
        return redirect(url_for('inventory_dashboard'))
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/cashier_dashboard')
@login_required
def cashier_dashboard():
    return render_template('cashier_dashboard.html')

@app.route('/inventory_dashboard')
@login_required
def inventory_dashboard():
    return render_template('inventory_dashboard.html')

@app.route('/sidebar')
def sidebar():
    return render_template('sidebar.html')

@app.route('/manage_users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Logic for updating the user (e.g., changing username, email, role)
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))


@app.route('/manage_products')
@login_required
@admin_required
def manage_products():
    products = Product.query.filter_by(is_voided=False, deleted=False).all()
    return render_template('manage_products.html', products=products)

# Route to display the restock form and log restocks
@app.route('/product/<int:product_id>/restock', methods=['GET', 'POST'])
def restock_product(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        # Get form data
        restock_amount = int(request.form['restock_amount'])
        amount_spent = float(request.form['amount_spent'])
        restock_location = request.form['restock_location']

        # Update product stock
        product.stock += restock_amount
        product.purchase_location = restock_location

        # Log the restock event
        restock = Restock(
            restock_amount=restock_amount,
            amount_spent=amount_spent,
            restock_location=restock_location,
            product_id=product.id,
            inventory_type='product'
        )
        db.session.add(restock)
        db.session.commit()

        flash(f'Successfully restocked {product.name} by {restock_amount} units!', 'success')
        return redirect(url_for('restock_product', product_id=product_id))  # Redirect to the same page to see the updated log

    # Query restock log for this product
    restock_log = Restock.query.filter_by(product_id=product_id).all()

    # Render the restock form with the selected product and its restock log
    return render_template('product_restock.html', product=product, restock_log=restock_log)


#VOIDING PRODUCTS
@app.route('/void_product/<int:product_id>', methods=['POST'])
@login_required
@admin_required
def void_product(product_id):
    product = Product.query.get_or_404(product_id)

    # Mark the product as voided
    product.is_voided = True
    db.session.commit()

    flash(f'Product "{product.name}" has been voided successfully.', 'success')
    return redirect(url_for('manage_products'))

@app.route('/reduce_stock/<int:product_id>', methods=['POST'])
@login_required
@admin_required
def reduce_stock(product_id):
    # Get the product from the database
    product = Product.query.get_or_404(product_id)
    
    # Get the quantity to reduce from the form data
    reduce_quantity = int(request.form['reduce_quantity'])
    
    # Reduce the stock if the reduce quantity is valid
    if reduce_quantity > 0 and reduce_quantity <= product.stock:
        product.stock -= reduce_quantity
        db.session.commit()
        flash(f'{reduce_quantity} units of {product.name} have been deducted from stock.', 'success')
    else:
        flash('Invalid quantity specified.', 'danger')
    
    return redirect(url_for('manage_products'))


@app.route('/view_transactions')
@login_required
@admin_required
def view_transactions():
    # Fetch all product transactions and loading transactions separately
    product_transactions = Transaction.query.filter_by(is_loading=False, print_service_id=None).all()  # Non-loading product transactions
    loading_transactions = Transaction.query.filter_by(is_loading=True).all()  # Loading transactions
    print_transactions = Transaction.query.filter(Transaction.print_service_id.isnot(None)).all()  # Print service transactions

    return render_template('view_transactions.html', 
                           product_transactions=product_transactions, 
                           loading_transactions=loading_transactions,
                           print_transactions=print_transactions)  # Pass print transactions





# SALES REPORT
# Daily Sales with Revenue
def get_daily_sales_with_revenue(selected_date):
    return db.session.query(
        func.sum(Transaction.quantity * (Product.price - Product.original_price)).label('total_revenue')
    ).join(Product, Product.id == Transaction.product_id).filter(
        func.date(Transaction.timestamp) == selected_date.date()  # Compare only the date
    ).scalar() or 0


# Monthly Sales with Revenue
def get_monthly_sales_with_revenue(selected_date):
    return db.session.query(
        func.sum(Transaction.quantity * (Product.price - Product.original_price)).label('total_revenue')
    ).join(Product, Product.id == Transaction.product_id).filter(
        extract('month', Transaction.timestamp) == selected_date.month,
        extract('year', Transaction.timestamp) == selected_date.year
    ).scalar() or 0

# Quarterly Sales with Revenue
def get_quarterly_sales_with_revenue(selected_date):
    current_quarter = (selected_date.month - 1) // 3 + 1
    return db.session.query(
        func.sum(Transaction.quantity * (Product.price - Product.original_price)).label('total_revenue')
    ).join(Product, Product.id == Transaction.product_id).filter(
        (extract('month', Transaction.timestamp) - 1) // 3 + 1 == current_quarter,
        extract('year', Transaction.timestamp) == selected_date.year
    ).scalar() or 0

# Yearly Sales with Revenue
def get_yearly_sales_with_revenue(selected_date):
    return db.session.query(
        func.sum(Transaction.quantity * (Product.price - Product.original_price)).label('total_revenue')
    ).join(Product, Product.id == Transaction.product_id).filter(
        extract('year', Transaction.timestamp) == selected_date.year
    ).scalar() or 0


# Sales Route
@app.route('/sales_report', methods=['GET'])
def sales_report():
    filter_type = request.args.get('filter_type', 'daily')  # Default to daily if no filter
    filter_date = request.args.get('filter_date')

    # Parse filter_date if provided
    if filter_date:
        selected_date = datetime.strptime(filter_date, '%Y-%m-%d')
    else:
        selected_date = datetime.today()

    # Apply the correct query based on filter_type
    if filter_type == 'daily':
        total_revenue = get_daily_sales_with_revenue(selected_date)
    elif filter_type == 'monthly':
        total_revenue = get_monthly_sales_with_revenue(selected_date)
    elif filter_type == 'quarterly':
        total_revenue = get_quarterly_sales_with_revenue(selected_date)
    elif filter_type == 'yearly':
        total_revenue = get_yearly_sales_with_revenue(selected_date)
    else:
        total_revenue = 0

    return render_template('sales_report.html', 
                           filter_type=filter_type, 
                           total_revenue=total_revenue)

#Add Items
@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    categories = Category.query.all()  # Fetch all categories for the dropdown

    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        price = float(request.form['price'])
        original_price = float(request.form['original_price'])
        stock = int(request.form['stock'])
        purchase_location = request.form['purchase_location']
        expiration_date_str = request.form.get('expiration_date', None)
        category_id = request.form.get('category_id')  # Get the selected category

        # Convert expiration_date_str to a date object, or set to None if not provided
        expiration_date = None
        if expiration_date_str:
            try:
                expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid expiration date format. Please use YYYY-MM-DD.', 'danger')
                return redirect(url_for('add_product'))

        # Validate input
        if not name or price <= 0 or original_price <= 0 or stock < 0 or not category_id:
            flash('Please fill out all fields correctly and select a category.', 'danger')
            return redirect(url_for('add_product'))

        # Create a new Product instance
        new_product = Product(
            name=name,
            price=price,
            original_price=original_price,
            stock=stock,
            purchase_location=purchase_location,
            expiration_date=expiration_date,
            category_id=category_id  # Associate product with the selected category
        )

        # Add and commit to the database
        try:
            db.session.add(new_product)
            db.session.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('view_products'))  # Redirect to product list after adding
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding product: {e}', 'danger')
            return redirect(url_for('add_product'))

    return render_template('add_product.html', categories=categories)



# Read Products (View all Products)
@app.route('/products', methods=['GET'])
def view_products():
    products = Product.query.all()
    return render_template('manage_products.html', products=products)


# Update Product (Edit Product)
@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        # Get form data
        product.name = request.form['name']
        product.price = float(request.form['price'])
        product.original_price = float(request.form['original_price'])
        product.stock = int(request.form['stock'])
        product.purchase_location = request.form['purchase_location']

        # Validate input
        if not product.name or product.price <= 0 or product.original_price <= 0 or product.stock < 0:
            flash('Please fill out all fields correctly.', 'danger')
            return redirect(url_for('edit_product', product_id=product_id))

        # Update and commit to the database
        try:
            db.session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('view_products'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating product: {e}', 'danger')
            return redirect(url_for('edit_product', product_id=product_id))

    return render_template('edit_product.html', product=product)


# Delete Product
# Delete Product (Soft Delete and Archive)
@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Move product data to the ArchivedProduct table
    archived_product = ArchivedProduct(
        id=product.id,  # Keep the original ID
        name=product.name,
        price=product.price,
        original_price=product.original_price,
        stock=product.stock,
        purchase_location=product.purchase_location,
        deleted=True  # Set as deleted in the archive
    )
    db.session.add(archived_product)
    # Mark the product as deleted
    product.deleted = True
    db.session.commit()

    flash(f'Product "{product.name}" has been archived successfully.', 'success')
    return redirect(url_for('manage_products'))




# Restore Product (Undo Archiving)
# Restore Product (Undo Archiving)
@app.route('/restore_product/<int:product_id>', methods=['POST'])
@login_required
@admin_required
def restore_product(product_id):
    archived_product = ArchivedProduct.query.get_or_404(product_id)
    
    # Restore the original Product by updating its fields
    product = Product.query.get_or_404(archived_product.id)
    product.deleted = False  # Mark it as not deleted

    # Update the original product with the archived data
    product.name = archived_product.name
    product.price = archived_product.price
    product.original_price = archived_product.original_price
    product.stock = archived_product.stock
    product.purchase_location = archived_product.purchase_location

    # Remove the archived entry
    db.session.delete(archived_product)
    db.session.commit()

    flash(f'Product "{product.name}" has been restored successfully.', 'success')
    return redirect(url_for('manage_archived_products'))




#Archive Products View
@app.route('/manage_archived_products')
@login_required
@admin_required
def manage_archived_products():
    # Query the ArchivedProduct table instead
    archived_products = ArchivedProduct.query.all()
    return render_template('manage_archived_products.html', products=archived_products)



#Transaction
@app.route('/create_transaction', methods=['GET', 'POST'])
@login_required
def create_transaction():
    if request.method == 'POST':
        # Get form data
        product_id = request.form['product_id']
        quantity = int(request.form['quantity'])

        # Fetch product from the database
        product = Product.query.get(product_id)

        # Check if the product is valid, not archived, and has enough stock
        if product and not product.deleted:  # Check if product is not archived
            if quantity <= product.stock:
                # Deduct stock
                product.stock -= quantity

                # Calculate total price
                total_price = product.price * quantity

                # Add timestamp for the transaction
                timestamp = datetime.now()

                # Create a new transaction
                new_transaction = Transaction(
                    product_id=product.id,
                    user_id=current_user.id,  # Add current user as part of the transaction
                    quantity=quantity,
                    total_price=total_price,
                    timestamp=timestamp  # Add timestamp to the transaction
                )

                try:
                    # Add transaction to the database and commit both operations at once
                    db.session.add(new_transaction)
                    db.session.commit()

                    flash('Transaction completed successfully!', 'success')
                    return redirect(url_for('view_transactions'))
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error processing transaction: {e}', 'danger')
            else:
                flash('Insufficient stock!', 'danger')
        else:
            flash('Product not available for transaction (it might be archived or not found).', 'danger')

    # GET: Fetch all products that are not archived for the dropdown list
    products = Product.query.filter_by(deleted=False).all()  # Only get non-archived products
    return render_template('cashier.html', products=products)


#CATEGORY
# Route to list categories
@app.route('/categories')
def manage_categories():
    categories = Category.query.all()
    return render_template('manage_categories.html', categories=categories)

# Route to add a category
@app.route('/add_category', methods=['GET', 'POST'])
def add_category():
    if request.method == 'POST':
        category_name = request.form.get('name')
        if category_name:
            new_category = Category(name=category_name)
            db.session.add(new_category)
            db.session.commit()
            flash('Category added successfully!', 'success')
            return redirect(url_for('manage_categories'))
    return render_template('add_category.html')

# Route to edit a category
@app.route('/edit_category/<int:category_id>', methods=['GET', 'POST'])
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    if request.method == 'POST':
        category.name = request.form.get('name')
        db.session.commit()
        flash('Category updated successfully!', 'success')
        return redirect(url_for('manage_categories'))
    return render_template('edit_category.html', category=category)

# Route to delete a category
@app.route('/delete_category/<int:category_id>', methods=['POST'])
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('manage_categories'))

#DASHBOARD
@app.route('/another_dashboard')
def another_dashboard():
    total_products = Product.query.count()
    total_stock = db.session.query(func.sum(Product.stock)).scalar() or 0
    total_categories = Category.query.count()

    today = datetime.today().date()
    thirty_days_ago = today - timedelta(days=30)

    # Fetch low stock products (stock < 5, adjust as needed)
    low_stock_products = db.session.query(Product.id, Product.name, Product.stock).filter(Product.stock < 5).all()

    # Fetch data
    sales_data = db.session.query(
        func.date(Transaction.timestamp),
        func.sum(Transaction.quantity)
    ).filter(
        Transaction.timestamp >= thirty_days_ago
    ).group_by(func.date(Transaction.timestamp)).all()

    revenue_data = db.session.query(
        func.date(Transaction.timestamp),
        func.sum(Transaction.total_price)
    ).filter(
        Transaction.timestamp >= thirty_days_ago
    ).group_by(func.date(Transaction.timestamp)).all()

    profit_data = db.session.query(
        func.date(Transaction.timestamp),
        func.sum(Transaction.total_price - (Transaction.quantity * Product.original_price))
    ).join(Product).filter(
        Transaction.timestamp >= thirty_days_ago
    ).group_by(func.date(Transaction.timestamp)).all()

    # Debugging queries to ensure they're returning data
    print("Sales Data from DB:", sales_data)
    print("Revenue Data from DB:", revenue_data)
    print("Profit Data from DB:", profit_data)

    # Initialize lists with 30 zeros
    daily_sales_data = [0] * 30
    daily_revenue_data = [0] * 30
    daily_profit_data = [0] * 30

    # Populate the lists with data
    for sale in sales_data:
        sale_date = sale[0]
        if isinstance(sale_date, str):
            sale_date = datetime.strptime(sale_date, '%Y-%m-%d').date()

        # Calculate day_index
        day_index = (sale_date - thirty_days_ago).days

        # Adjust day_index if it equals 30 to fit in the 0-29 range
        if day_index == 30:
            day_index = 29

        print(f"Sale Date: {sale_date}, Thirty Days Ago: {thirty_days_ago}, Day Index: {day_index}")

        if 0 <= day_index < 30:
            daily_sales_data[day_index] = sale[1]

    # Repeat the same for revenue_data and profit_data
    for revenue in revenue_data:
        revenue_date = revenue[0]
        if isinstance(revenue_date, str):
            revenue_date = datetime.strptime(revenue_date, '%Y-%m-%d').date()

        day_index = (revenue_date - thirty_days_ago).days

        if day_index == 30:
            day_index = 29

        print(f"Revenue Date: {revenue_date}, Thirty Days Ago: {thirty_days_ago}, Day Index: {day_index}")

        if 0 <= day_index < 30:
            daily_revenue_data[day_index] = revenue[1]

    for profit in profit_data:
        profit_date = profit[0]
        if isinstance(profit_date, str):
            profit_date = datetime.strptime(profit_date, '%Y-%m-%d').date()

        day_index = (profit_date - thirty_days_ago).days

        if day_index == 30:
            day_index = 29

        print(f"Profit Date: {profit_date}, Thirty Days Ago: {thirty_days_ago}, Day Index: {day_index}")

        if 0 <= day_index < 30:
            daily_profit_data[day_index] = profit[1]

    # Debugging final data
    print("Final Daily Sales Data:", daily_sales_data)
    print("Final Daily Revenue Data:", daily_revenue_data)
    print("Final Daily Profit Data:", daily_profit_data)

    past_30_days_labels = [(thirty_days_ago + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(30)]

    return render_template(
        'dashboard.html',
        total_products=total_products,
        total_stock=total_stock,
        total_categories=total_categories,
        low_stock_products=low_stock_products,  # Pass low stock products to template
        past_30_days_labels=past_30_days_labels,
        daily_sales_data=daily_sales_data,
        daily_revenue_data=daily_revenue_data,
        daily_profit_data=daily_profit_data
    )

#Dashboard v2
@app.route('/api/chart-data')
def chart_data():
    today = datetime.today().date()
    thirty_days_ago = today - timedelta(days=30)

    # Fetch data
    sales_data = db.session.query(
        func.date(Transaction.timestamp),
        func.sum(Transaction.quantity)
    ).filter(Transaction.timestamp >= thirty_days_ago).group_by(func.date(Transaction.timestamp)).all()

    revenue_data = db.session.query(
        func.date(Transaction.timestamp),
        func.sum(Transaction.total_price)
    ).filter(Transaction.timestamp >= thirty_days_ago).group_by(func.date(Transaction.timestamp)).all()

    profit_data = db.session.query(
        func.date(Transaction.timestamp),
        func.sum(Transaction.total_price - (Transaction.quantity * Product.original_price))
    ).join(Product).filter(Transaction.timestamp >= thirty_days_ago).group_by(func.date(Transaction.timestamp)).all()

    # Initialize lists with 30 zeros
    daily_sales_data = [0] * 30
    daily_revenue_data = [0] * 30
    daily_profit_data = [0] * 30

    # Populate the lists with data
    for sale in sales_data:
        sale_date = sale[0]
    
    # Ensure sale_date is a date object
    if isinstance(sale_date, str):
        sale_date = datetime.strptime(sale_date, '%Y-%m-%d').date()

    day_index = (sale_date - thirty_days_ago).days
    if 0 <= day_index < 30:
        daily_sales_data[day_index] = sale[1]

    for revenue in revenue_data:
        revenue_date = revenue[0]
        
        # Ensure revenue_date is a date object
        if isinstance(revenue_date, str):
            revenue_date = datetime.strptime(revenue_date, '%Y-%m-%d').date()

        day_index = (revenue_date - thirty_days_ago).days
        if 0 <= day_index < 30:
            daily_revenue_data[day_index] = revenue[1]

    for profit in profit_data:
        profit_date = profit[0]
        
        # Ensure profit_date is a date object
        if isinstance(profit_date, str):
            profit_date = datetime.strptime(profit_date, '%Y-%m-%d').date()

        day_index = (profit_date - thirty_days_ago).days
        if 0 <= day_index < 30:
            daily_profit_data[day_index] = profit[1]


    past_30_days_labels = [(thirty_days_ago + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(30)]

    return jsonify({
        'daily_sales_data': daily_sales_data,
        'daily_revenue_data': daily_revenue_data,
        'daily_profit_data': daily_profit_data,
        'labels': past_30_days_labels
    })

@app.route('/cashier', methods=['GET', 'POST'])
def cashier():
    print_services = PrintService.query.all()
    paper_types = PaperInventory.query.all()
    load_balance = LoadBalance.query.first()
    products = Product.query.filter_by(deleted=False, is_voided=False).all()  # Fetch all valid products
    return render_template('cashier.html', products=products, print_services=print_services, paper_types=paper_types,
                           load_balance = load_balance)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    product_ids = request.form.getlist('product_ids[]')
    quantities = request.form.getlist('quantities[]')

    # Print service checkout handling
    print_service_id = request.form.get('print_service_id')
    pages = request.form.get('pages')
    back_to_back = request.form.get('back_to_back') == '1'
    paper_type_id = request.form.get('paper_type_id')

    total_sales = 0
    user_id = current_user.id  # Assuming you're using Flask-Login

    # Handle product checkout
    if product_ids and quantities:
        product_dict = {}

        for i in range(len(product_ids)):
            product_id = int(product_ids[i])
            quantity = int(quantities[i])

            product = Product.query.get(product_id)
            if not product:
                flash(f'Product with ID {product_id} does not exist!', 'danger')
                return redirect(url_for('cashier'))

            if quantity > product.stock:
                flash(f'Insufficient stock for {product.name}', 'danger')
                return redirect(url_for('cashier'))

            if product_id in product_dict:
                product_dict[product_id]['quantity'] += quantity
            else:
                product_dict[product_id] = {
                    'product': product,
                    'quantity': quantity,
                    'total_price': product.price * quantity
                }

        for product_id, product_data in product_dict.items():
            product = product_data['product']
            quantity = product_data['quantity']

            product.stock -= quantity
            total_sales += product.price * quantity

            new_transaction = Transaction(
                product_id=product.id,
                user_id=user_id,
                quantity=quantity,
                total_price=product.price * quantity,
            )
            db.session.add(new_transaction)

    # Handle print service checkout if applicable
    if print_service_id and pages and paper_type_id:
        try:
            total_price, total_cost = process_print_service_checkout(print_service_id, pages, back_to_back, paper_type_id, user_id)
            total_sales += total_price
        except ValueError as e:
            flash(str(e), 'danger')
            return redirect(url_for('cashier'))

    try:
        db.session.commit()
        flash(f'Transaction completed successfully! Total Sales: P{total_sales:.2f}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing checkout: {e}', 'danger')

    return redirect(url_for('cashier'))

@app.route('/unified_checkout', methods=['POST'])
@login_required
def unified_checkout():
    try:
        # Begin a single database transaction
        total_price = 0

        # Handle Product Checkout
        product_ids = request.form.getlist('product_ids[]')
        quantities = request.form.getlist('quantities[]')
        if product_ids and quantities:
            for product_id, quantity in zip(product_ids, quantities):
                product = Product.query.get(product_id)
                quantity = int(quantity)
                if product.stock < quantity:
                    flash(f'Not enough stock for {product.name}', 'danger')
                    return redirect(url_for('cashier'))  # Back to cashier on error

                # Deduct stock
                product.stock -= quantity
                total_price += product.price * quantity

                # Create product transaction
                new_product_transaction = Transaction(
                    user_id=current_user.id,
                    product_id=product.id,
                    quantity=quantity,
                    total_price=product.price * quantity
                )
                db.session.add(new_product_transaction)
        
        print('Form data:', request.form)

        # Handle Print Service Checkout
        service_ids = request.form.getlist('service_ids[]')
        pages = request.form.getlist('pages[]')
        paper_type_ids = request.form.getlist('paper_type_ids[]')
        back_to_back_list = request.form.getlist('back_to_back[]')

        if service_ids and pages:
            for service_id, page_count, paper_type_id, back_to_back in zip(service_ids, pages, paper_type_ids, back_to_back_list):
                service = PrintService.query.get(service_id)
                page_count = int(page_count)
                back_to_back = back_to_back == 'Yes'

                if back_to_back:
                    page_count = max(1, page_count // 2)

                # Paper inventory check and deduction
                paper_inventory = PaperInventory.query.filter_by(id=paper_type_id).first()
                if paper_inventory.individual_paper_count < page_count:
                    flash('Not enough paper in stock!', 'danger')
                    return redirect(url_for('cashier'))

                # Deduct paper stock
                paper_inventory.individual_paper_count -= page_count
                db.session.commit()

                total_price += service.price_per_page * page_count * (0.9 if back_to_back else 1)

                # Create print transaction
                new_print_transaction = Transaction(
                    user_id=current_user.id,
                    print_service_id=service.id,
                    pages=page_count,
                    back_to_back=back_to_back,
                    total_price=service.price_per_page * page_count
                )
                db.session.add(new_print_transaction)

        # Handle Load Transaction
        service_providers = request.form.getlist('service_providers[]')
        amount_loaded_list = request.form.getlist('amount_loaded[]')
        total_price_list = request.form.getlist('total_price[]')

        # Debugging: Print form data for load transactions
        print('Loading Services:', service_providers, amount_loaded_list, total_price_list)

        # Fetch the LoadBalance record, or create one if it doesn't exist
        load_balance = LoadBalance.query.first()
        if load_balance is None:
            # If no LoadBalance exists, initialize with 0 for both types of balances
            load_balance = LoadBalance(normal_load=0.0, gcash_balance=0.0)
            db.session.add(load_balance)
            db.session.commit()  # Save the new LoadBalance record

        # Check if there's any load transaction data
        if amount_loaded_list and service_providers:
            for amount_loaded_str, provider in zip(amount_loaded_list, service_providers):
                print("Processing load transactions...")
                try:
                    # Convert the loaded amount to float and validate
                    amount_loaded = float(amount_loaded_str)
                    if amount_loaded <= 0:
                        raise ValueError("Amount must be greater than zero.")
                except ValueError:
                    # If invalid, flash an error message and redirect to cashier page
                    flash("Invalid load amount entered.", "danger")
                    return redirect(url_for('cashier'))

                # Determine the balance to check based on the service provider
                if provider == "GCash":
                    balance = load_balance.gcash_balance
                else:
                    balance = load_balance.normal_load

                # Check if there's enough balance for the transaction
                if balance < amount_loaded:
                    flash(f"Insufficient {provider} balance", "danger")
                    return redirect(url_for('cashier'))

                # Calculate the total price with any additional fees
                if amount_loaded >= 1000:
                    # Apply a 2% increase for transactions >= 1000
                    total_price_with_fee = amount_loaded + (amount_loaded * 0.02)
                else:
                    # Apply a fixed 5 PHP charge for transactions < 1000
                    total_price_with_fee = amount_loaded + 5

                # Deduct only the original loaded amount from the corresponding balance
                if provider == "GCash":
                    load_balance.gcash_balance -= amount_loaded  # Deduct for GCash
                else:
                    load_balance.normal_load -= amount_loaded  # Deduct for normal load

                # Commit the balance update
                db.session.commit()
                print("Trying to add transaction")
                # Create a new load transaction
                try:
                    # Create a new load transaction
                    new_load_transaction = Transaction(
                        user_id=current_user.id,  # Logged-in user's ID
                        amount_loaded=amount_loaded,  # Original loaded amount
                        service_provider=provider,  # Provider (GCash, Globe, etc.)
                        total_price=total_price_with_fee,  # Total price including any fees
                        is_loading=True  # Mark this as a loading transaction
                    )
                    db.session.add(new_load_transaction)
                    print("Added transaction to the session")
                    db.session.commit()  # Commit the transaction to the database
                    print("Transaction committed")
                except Exception as e:
                    print(f"Error when adding or committing transaction: {e}")
                    db.session.rollback()  # Rollback in case of an error
                    flash("Error adding transaction", "danger")


                # Add the total price to the overall checkout total
                total_price += total_price_with_fee

        # Commit all changes to the database (both balances and transactions)
        db.session.commit()

        flash(f'Checkout successful! Total price: P{total_price}', 'success')
        return redirect(url_for('cashier'))

    except Exception as e:
        # Rollback the transaction in case of any error
        db.session.rollback()
        flash(f'Error during checkout: {str(e)}', 'danger')
        return redirect(url_for('cashier'))


# Manage Loading Services
@app.route('/manage_loading_services')
def manage_loading_services():
    loading_transactions = LoadingTransaction.query.all()
    return render_template('manage_loading_services.html', loading_transactions=loading_transactions)

@app.route('/add-loading-transaction', methods=['GET', 'POST'])
def add_loading_transaction():
    if request.method == 'POST':
        amount_loaded = float(request.form.get('amount_loaded'))
        service_provider = request.form.get('service_provider')
        transaction_type_id = request.form.get('transaction_type_id')

        transaction_type = TransactionType.query.get(transaction_type_id)
        if not transaction_type:
            flash('Invalid transaction type selected.', 'danger')
            return redirect(url_for('add_loading_transaction'))

        # Get the current load balance (assuming there's only one entry for now)
        load_balance = LoadBalance.query.first()

        # Check if it's a GCash or normal load transaction and validate balance
        if service_provider == 'GCash':
            if amount_loaded > load_balance.gcash_balance:
                flash('Insufficient GCash balance. Please restock first.', 'danger')
                return redirect(url_for('add_loading_transaction'))
            load_balance.gcash_balance -= amount_loaded
        else:  # Normal load
            if amount_loaded > load_balance.normal_load:
                flash('Insufficient load balance. Please restock first.', 'danger')
                return redirect(url_for('add_loading_transaction'))
            load_balance.normal_load -= amount_loaded

        # Create a new LoadingTransaction
        new_transaction = LoadingTransaction(
            amount_loaded=amount_loaded,
            service_provider=service_provider,
            transaction_type=transaction_type,
            location_id=None,  # Set to None
            restock_id=None  # Set to None
        )
        
        # Save the transaction and update the balance
        db.session.add(new_transaction)
        db.session.commit()

        flash('Loading transaction added successfully!', 'success')
        return redirect(url_for('manage_loading_services'))

    transaction_types = TransactionType.query.all()
    return render_template('add_loading_transaction.html', transaction_types=transaction_types)



# Add a Loading Transaction
@app.route('/add_loading_service', methods=['GET', 'POST'])
def add_loading_service():
    # Check if a LoadBalance record exists
    load_balance = LoadBalance.query.first()

    # If no LoadBalance record exists, create one with default values
    if load_balance is None:
        load_balance = LoadBalance(normal_load=0.0, gcash_balance=0.0)
        db.session.add(load_balance)
        db.session.commit()

    if request.method == 'POST':
        # Safely get the form data
        amount_loaded_str = request.form.get('amount_loaded')
        service_provider = request.form.get('service_provider')

        # Validate the input
        if not amount_loaded_str:
            flash("Amount Loaded is required", "danger")
            return redirect(url_for('add_loading_service'))

        try:
            # Convert to float
            amount_loaded = float(amount_loaded_str)
            if amount_loaded <= 0:
                raise ValueError("Amount must be greater than zero.")
        except ValueError:
            flash("Invalid amount entered. Please enter a valid number.", "danger")
            return redirect(url_for('add_loading_service'))

        # Logic to handle balance deduction based on service provider
        if service_provider == "GCash":
            balance = load_balance.gcash_balance
        else:
            balance = load_balance.normal_load

        # Check if balance is sufficient
        if balance < amount_loaded:
            flash("Insufficient balance", "danger")
            return redirect(url_for('add_loading_service'))

        # Determine total price based on the amount loaded
        if amount_loaded >= 1000:
            # Apply only 2% increase for amounts equal to or above ₱1000
            total_price = amount_loaded + (amount_loaded * 0.02)
        else:
            # Apply ₱5 fixed increase for amounts less than ₱1000
            total_price = amount_loaded + 5

        # Deduct only the original loaded amount from the respective balance
        if service_provider == "GCash":
            load_balance.gcash_balance -= amount_loaded  # Deduct original amount only
        else:
            load_balance.normal_load -= amount_loaded  # Deduct original amount only

        # Save the updated balance and transaction
        db.session.commit()  # Update the LoadBalance

        transaction = Transaction(
            user_id=current_user.id,
            total_price=total_price,  # Store the total price with increments
            is_loading=True,
            service_provider=service_provider,
            amount_loaded=amount_loaded  # Store original loaded amount
        )
        db.session.add(transaction)
        db.session.commit()

        flash("Loading transaction added successfully", "success")
        return redirect(url_for('add_loading_service'))

    # For GET request, fetch both product transactions and loading transactions
    transactions = Transaction.query.filter_by(is_loading=False).all()
    loading_transactions = Transaction.query.filter_by(is_loading=True).all()

    # Pass both the load balance and transactions to the template
    return render_template('add_loading_service.html', load_balance=load_balance, transactions=transactions, loading_transactions=loading_transactions)


# Manage Printing Services
@app.route('/manage_printing_services')
def manage_printing_services():
    print_services = PrintService.query.all()
    paper_types = PaperType.query.all()
    paper_inventory = PaperInventory.query.all()
    ink_inventory = InkInventory.query.all() 

    paper_data = []
    for paper_type in paper_types:
        inventory = PaperInventory.query.filter_by(paper_type_id=paper_type.id).first()
        paper_data.append({
            'type': f"{paper_type.size} - {paper_type.description}",
            'rim_count': inventory.rim_count if inventory else 0,
            'individual_paper_count': inventory.individual_paper_count if inventory else 0
        })
    
    return render_template('manage_printing_services.html', 
                           print_services=print_services, 
                           paper_inventory=paper_data,
                           ink_inventory=ink_inventory)

# @app.route('/manage_printing_services')
# def manage_printing_services():
#     # Fetch all print services
#     print_services = PrintService.query.all()

#     # Fetch paper inventory (join with PaperType for type and description)
#     paper_inventory = db.session.query(
#         PaperType.size, PaperType.description, PaperInventory.rim_count
#     ).join(PaperInventory, PaperType.id == PaperInventory.paper_type_id).all()

#     # Calculate total paper amount (rim_count * 500 sheets per rim)
#     paper_inventory_data = [
#         {
#             "type": f"{paper.size} - {paper.description}",
#             "total_amount": paper.rim_count * 500  # Assuming 500 sheets per rim
#         }
#         for paper in paper_inventory
#     ]

#     return render_template('manage_printing_services.html', print_services=print_services, paper_inventory=paper_inventory_data)



@app.route('/checkout_print_service', methods=['GET', 'POST'])
def checkout_print_service():
    if request.method == 'POST':
        service_id = request.form.get('service_id')
        pages = request.form.get('pages')
        back_to_back = request.form.get('back_to_back') == '1'  # Checkbox returns '1' if checked

        # Debugging
        print(f"Service ID: {service_id}, Pages: {pages}, Back-to-back: {back_to_back}")

        if not service_id or not pages:
            flash('Missing service ID or number of pages.', 'danger')
            return redirect(url_for('checkout_print_service'))

        try:
            pages = int(pages)
        except ValueError:
            flash('Invalid number of pages.', 'danger')
            return redirect(url_for('checkout_print_service'))

        # Adjust page count if back-to-back is selected (halves the page usage)
        if back_to_back:
            pages = max(1, pages // 2)
        print(f"Adjusted Pages (after back-to-back): {pages}")

        # Fetch the selected print service
        print_service = PrintService.query.get(service_id)

        if not print_service:
            flash('Selected print service not found.', 'danger')
            return redirect(url_for('checkout_print_service'))
        
        print(f"Print Service: {print_service.service_type} at {print_service.price_per_page}/page")

        # Fetch paper inventory details
        paper_type_id = request.form.get('paper_type_id')

        if not paper_type_id:
            flash('Paper type must be selected.', 'danger')
            return redirect(url_for('checkout_print_service'))

        # Get paper inventory
        paper_inventory = PaperInventory.query.filter_by(id=paper_type_id).first()

        # Check if paper inventory exists
        if not paper_inventory:
            flash('Selected paper type not found.', 'danger')
            return redirect(url_for('checkout_print_service'))

        # Debug paper inventory
        print(f"Paper Inventory: {paper_inventory.individual_paper_count} individual sheets, {paper_inventory.rim_count} rims")

        # Check if there is sufficient paper stock in individual sheets
        if paper_inventory.individual_paper_count < pages:
            needed_sheets = pages - paper_inventory.individual_paper_count

            if paper_inventory.rim_count > 0:
                # Convert rim into individual papers (assuming 500 sheets per rim)
                while needed_sheets > 0 and paper_inventory.rim_count > 0:
                    paper_inventory.rim_count -= 1
                    paper_inventory.individual_paper_count += 500
                    needed_sheets = pages - paper_inventory.individual_paper_count

            # Final check after converting rim to individual papers
            if paper_inventory.individual_paper_count < pages:
                flash('Not enough paper in stock after converting rims!', 'danger')
                return redirect(url_for('checkout_print_service'))

        # Deduct paper stock
        paper_inventory.individual_paper_count -= pages

        # Calculate the cost of paper used
        paper_cost_per_sheet = paper_inventory.amount_spent / ((paper_inventory.rim_count * 500) + paper_inventory.individual_paper_count)
        total_cost = paper_cost_per_sheet * pages

        # Debug total cost
        print(f"Total cost of resources: {total_cost}")

        # Calculate the total price
        total_price = print_service.price_per_page * pages

        # Handle back-to-back discount (if applicable, e.g., 10% discount)
        if back_to_back:
            total_price *= 0.9

        # Debugging price and profit
        print(f"Total Price: {total_price}")
        profit = total_price - total_cost
        print(f"Profit: {profit}")

        # Commit inventory changes to the database
        db.session.commit()

        # Create the print transaction in the unified Transaction table
        new_transaction = Transaction(
            user_id=current_user.id,  # Assuming you are using Flask-Login for user authentication
            total_price=total_price,
            print_service_id=print_service.id,
            pages=pages,
            back_to_back=back_to_back
        )

        # Add the new transaction to the Transaction table
        db.session.add(new_transaction)
        db.session.commit()

        flash(f'Print service checkout successful! Total price: P{total_price}', 'success')
        return redirect(url_for('checkout_print_service'))

    # Query all print services to show in the form
    print_services = PrintService.query.all()
    paper_types = PaperInventory.query.all()
    return render_template('check_print_service.html', print_services=print_services, paper_types=paper_types)

def process_print_service_checkout(service_id, pages, back_to_back, paper_type_id, user_id):
    # Validate and process the print service transaction
    try:
        pages = int(pages)
    except ValueError:
        raise ValueError('Invalid number of pages.')

    # Adjust pages if back-to-back is selected
    if back_to_back:
        pages = max(1, pages // 2)

    # Fetch the selected print service
    print_service = PrintService.query.get(service_id)
    if not print_service:
        raise ValueError('Selected print service not found.')

    # Fetch paper inventory
    paper_inventory = PaperInventory.query.filter_by(id=paper_type_id).first()
    if not paper_inventory:
        raise ValueError('Selected paper type not found.')

    # Check if there is enough paper stock
    if paper_inventory.individual_paper_count < pages:
        needed_sheets = pages - paper_inventory.individual_paper_count

        if paper_inventory.rim_count > 0:
            # Convert rims to individual sheets
            while needed_sheets > 0 and paper_inventory.rim_count > 0:
                paper_inventory.rim_count -= 1
                paper_inventory.individual_paper_count += 500
                needed_sheets = pages - paper_inventory.individual_paper_count

        if paper_inventory.individual_paper_count < pages:
            raise ValueError('Not enough paper in stock after converting rims.')

    # Deduct paper stock
    paper_inventory.individual_paper_count -= pages

    # Calculate paper cost
    paper_cost_per_sheet = paper_inventory.amount_spent / ((paper_inventory.rim_count * 500) + paper_inventory.individual_paper_count)
    total_cost = paper_cost_per_sheet * pages

    # Calculate total price
    total_price = print_service.price_per_page * pages
    if back_to_back:
        total_price *= 0.9

    # Commit inventory changes
    db.session.commit()

    # Create and save the print transaction
    new_transaction = Transaction(
        user_id=user_id,
        total_price=total_price,
        print_service_id=print_service.id,
        pages=pages,
        back_to_back=back_to_back
    )
    db.session.add(new_transaction)

    return total_price, total_cost


# Route for adding new ink type
@app.route('/add-ink-type', methods=['POST'])
def add_ink_type():
    if request.method == 'POST':
        new_ink_type_name = request.form.get('new_ink_type_name')
        
        if new_ink_type_name:
            # Add the new ink type to the database
            new_ink_type = InkInventory(name=new_ink_type_name, stock=0, amount_spent=0, purchase_location='', last_restock_date=None)
            db.session.add(new_ink_type)
            db.session.commit()
            flash('New Ink Type added successfully!', 'success')
        else:
            flash('Ink Type name is required!', 'danger')
            
    return redirect(url_for('manage_printing_services'))  # Replace 'some_view' with the correct view for redirection

# Route for adding new paper type
@app.route('/add-paper-type', methods=['POST'])
def add_paper_type():
    if request.method == 'POST':
        size = request.form.get('size')
        description = request.form.get('description')

        # Debugging print
        print(f"Received size: {size}, description: {description}")

        if size:
            # Add the new paper type to the database
            new_paper_type = PaperType(size=size, description=description)
            db.session.add(new_paper_type)
            try:
                db.session.commit()
            except Exception as e:
                print(f"Error committing to the database: {e}")
                db.session.rollback()  # Rollback the transaction in case of an error
                flash('There was an issue adding the paper type.', 'danger')

            # Debugging: Print all paper types in the database to verify
            all_paper_types = PaperType.query.all()
            print("Current paper types in database:", all_paper_types)

            flash('New Paper Type added successfully!', 'success')
        else:
            flash('Paper size is required!', 'danger')

    return redirect(url_for('manage_printing_services'))



# Add a Printing Service
@app.route('/add_print_service', methods=['GET', 'POST'])
def add_print_service():
    if request.method == 'POST':
        service_type = request.form.get('service_type')
        price_per_page = request.form.get('price_per_page')
        admin_price_override = request.form.get('admin_price_override')

        if admin_price_override == '':
            admin_price_override = None
        else:
            admin_price_override = float(admin_price_override)  # Convert to float if it's not empty

        
        # Create new service
        new_service = PrintService(
            service_type=service_type,
            price_per_page=price_per_page,
            admin_price_override=admin_price_override
        )
        db.session.add(new_service)
        db.session.commit()
        flash('Print Service Added Successfully')
        return redirect(url_for('manage_printing_services'))
    
    return render_template('add_print_service.html')

@app.route('/add_location', methods=['GET', 'POST'])
@login_required
def add_location():
    if request.method == 'POST':
        location_name = request.form['location_name']
        
        # Check if the location already exists
        existing_location = Location.query.filter_by(name=location_name).first()
        if existing_location:
            flash('Location already exists', 'danger')
            return redirect(url_for('create_location'))
        
        # Add new location
        new_location = Location(name=location_name)
        try:
            db.session.add(new_location)
            db.session.commit()
            flash(f'Location "{location_name}" added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding location: {e}', 'danger')
        
        return redirect(url_for('add_location'))
    
    # For GET request, render the create location form
    locations = Location.query.all()
    return render_template('create_location.html', locations=locations)

@app.route('/add_transaction_type', methods=['GET', 'POST'])
@login_required
def add_transaction_type():
    if request.method == 'POST':
        transaction_type_name = request.form['transaction_type_name']
        
        # Check if the transaction type already exists
        existing_transaction_type = TransactionType.query.filter_by(name=transaction_type_name).first()
        if existing_transaction_type:
            flash('Transaction type already exists', 'danger')
            return redirect(url_for('add_transaction_type'))
        
        # Add new transaction type
        new_transaction_type = TransactionType(name=transaction_type_name)
        try:
            db.session.add(new_transaction_type)
            db.session.commit()
            flash(f'Transaction Type "{transaction_type_name}" added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding transaction type: {e}', 'danger')
        
        return redirect(url_for('add_transaction_type'))
    
    # For GET request, render the form to add a new transaction type
    transaction_types = TransactionType.query.all()
    return render_template('create_transaction_type.html', transaction_types=transaction_types)

@app.route('/manage_restock_events')
def manage_restock_events():
    restock_events = Restock.query.all()
    ink_inventory = InkInventory.query.all()
    paper_inventory = PaperInventory.query.all()
    paper_types = PaperType.query.all()
    products = Product.query.all()
    locations = Location.query.all()
    return render_template('manage_restock_events.html', restock_events=restock_events,ink_inventory=ink_inventory, paper_inventory=paper_inventory, 
                           paper_types=paper_types,products=products, locations=locations)


@app.route('/add_loading_restock', methods=['GET', 'POST'])
def add_loading_restock():
    if request.method == 'POST':
        # Retrieve data from the form
        restock_amount = request.form['restock_amount']
        amount_spent = request.form['amount_spent']
        restock_location = request.form['restock_location']

        # Create a new Restock instance specific to loading
        new_restock = Restock(
            restock_amount=restock_amount,
            amount_spent=amount_spent,
            restock_location=restock_location,
            inventory_type='loading'  # Specific to loading restock
        )

        # Add the restock event to the database
        try:
            db.session.add(new_restock)
            db.session.commit()
            flash('Loading restock event added successfully!', 'success')
            return redirect(url_for('manage_loading_restock_events'))
        except Exception as e:
            print(e)  # For debugging purposes
            flash('There was an issue adding the loading restock event', 'danger')
            return redirect(url_for('add_loading_restock'))

    return render_template('add_loading_restock.html')

@app.route('/manage_loading_restock_events')
def manage_loading_restock_events():
    restock_events = Restock.query.filter_by(inventory_type='loading').all()
    return render_template('manage_loading_restock_events.html', restock_events=restock_events)

@app.route('/add-restock', methods=['POST'])
def add_restock():
    # Extract form data
    restock_amount = float(request.form['restock_amount'])  # Amount of rims for paper or units for ink
    restock_location = request.form['restock_location']  # Store or location from where it was restocked
    amount_spent = float(request.form['amount_spent'])  # Cost of the restock
    restock_type = request.form['restock_type']  # Type of item being restocked (ink, paper, load, gcash)

    # Create a new Restock entry
    new_restock = Restock(
        restock_amount=restock_amount,
        restock_location=restock_location,
        amount_spent=amount_spent,
        inventory_type=restock_type,  # Track whether it is ink, paper, load, etc.
        restock_date=datetime.utcnow()
    )
    db.session.add(new_restock)

    # Handle paper restock
    if restock_type == 'paper':
        paper_type_id = request.form.get('paper_type_id')  # Paper type selected

        if not paper_type_id:
            flash('Please select a paper type!', 'danger')
            return redirect(url_for('manage_restock_events'))

        # Fetch the paper inventory by paper_type_id
        paper_inventory = PaperInventory.query.filter_by(paper_type_id=paper_type_id).first()

        # Update or create a paper inventory entry
        if paper_inventory:
            # Update the existing paper inventory
            paper_inventory.rim_count += restock_amount  # Adding restocked rims
            paper_inventory.individual_paper_count += restock_amount * 500  # Adding the total sheets
            paper_inventory.amount_spent += amount_spent  # Updating total amount spent
            paper_inventory.last_restock_date = datetime.utcnow()  # Updating last restock date
        else:
            # Create a new paper inventory entry
            paper_inventory = PaperInventory(
                rim_count=restock_amount,  # Set initial rim count
                individual_paper_count=restock_amount * 500,  # Set total sheets based on rim count (500 sheets per rim)
                amount_spent=amount_spent,
                paper_type_id=paper_type_id,  # Set the selected paper type
                location_id=restock_location  # Set restock location
            )
            db.session.add(paper_inventory)

    # Handle ink restock
    elif restock_type == 'ink':
        ink_type_id = request.form['ink_type_id']  # Selected ink type
        ink_inventory = InkInventory.query.get(ink_type_id)

        if ink_inventory:
            # Update the existing ink inventory
            ink_inventory.stock += restock_amount
            ink_inventory.amount_spent += amount_spent
            ink_inventory.purchase_location = restock_location
            ink_inventory.last_restock_date = datetime.utcnow()
        else:
            # Create a new ink inventory entry
            ink_inventory = InkInventory(
                name=request.form['ink_name'],
                stock=restock_amount,
                amount_spent=amount_spent,
                purchase_location=restock_location
            )
            db.session.add(ink_inventory)

    # Handle load and GCash restocks
    elif restock_type in ['load', 'gcash']:
        load_balance = LoadBalance.query.first()

        if load_balance is None:
            load_balance = LoadBalance(normal_load=0.0, gcash_balance=0.0)
            db.session.add(load_balance)
            db.session.commit()

        if restock_type == 'load':
            load_balance.normal_load += restock_amount
        elif restock_type == 'gcash':
            load_balance.gcash_balance += restock_amount

    # Commit changes to the database
    db.session.commit()

    flash('Restock added successfully!', 'success')
    return redirect(url_for('manage_restock_events'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# Run the app
if __name__ == '__main__':
    app.run(port=5001, debug=True)
