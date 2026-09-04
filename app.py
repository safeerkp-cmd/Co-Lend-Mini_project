from flask import Flask, request, render_template, redirect, url_for, session, flash, abort
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import random
import secrets
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment configuration from .env file if present
_env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
if os.path.exists(_env_file):
    with open(_env_file, 'r', encoding='utf-8') as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith('#') and '=' in _line:
                _k, _v = _line.split('=', 1)
                os.environ.setdefault(_k.strip(), _v.strip())

# Validate essential configuration variables
SECRET_KEY = os.environ.get('SECRET_KEY')
DB_PASSWORD = os.environ.get('DB_PASSWORD')

if not SECRET_KEY:
    raise RuntimeError("Configuration Error: SECRET_KEY environment variable is missing. Set it in .env or system environment.")
if not DB_PASSWORD:
    raise RuntimeError("Configuration Error: DB_PASSWORD environment variable is missing. Set it in .env or system environment.")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# CSRF Protection Helpers
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)

@app.before_request
def check_csrf():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        expected_token = session.get('_csrf_token')
        if not expected_token or not token or not secrets.compare_digest(expected_token, token):
            abort(400, description="CSRF token missing or invalid.")

# Database connection helper using environment configuration
def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        database=os.environ.get('DB_NAME', 'colend_db'),
        user=os.environ.get('DB_USER', 'postgres'),
        password=os.environ.get('DB_PASSWORD'),
        port=os.environ.get('DB_PORT', '5432')
    )

# Prevent caching of authenticated views (Security requirement)
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# 1. Login page route (GET /)
@app.route('/')
def index():
    return render_template("login.html")

# 2. Signup page route (GET /signup)
@app.route('/signup', methods=['GET'])
def signup_ui():
    return render_template("signup.html")

# 3. Process resident registration (POST /signup)
@app.route('/signup', methods=['POST'])
def signup_process():
    association_id = request.form.get('association_id')
    password = request.form.get('password')
    full_name = request.form.get('full_name')
    house_name_number = request.form.get('house_name_number')
    street_address = request.form.get('street_address')
    city = request.form.get('city')
    pincode = request.form.get('pincode')
    phone_number = request.form.get('phone_number')
    
    # Input validation
    if not association_id or not password or not full_name or not house_name_number or not street_address or not street_address.strip() or not city or not city.strip() or not pincode or not phone_number:
        return render_template("signup.html", error="All required fields must be populated.")
        
    if len(street_address.strip()) > 255:
        return render_template("signup.html", error="Street address must not exceed 255 characters.")
        
    if len(city.strip()) > 100:
        return render_template("signup.html", error="City must not exceed 100 characters.")
        
    if not pincode.isdigit() or len(pincode) != 6:
        return render_template("signup.html", error="Pincode must be exactly 6 digits.")
        
    if not phone_number.isdigit() or len(phone_number) < 10 or len(phone_number) > 12:
        return render_template("signup.html", error="Phone number must be a valid 10 to 12 digit number.")
        
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Check if user already exists
    cursor.execute("SELECT id FROM users WHERE username = %s;", (association_id,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        cursor.close()
        conn.close()
        return render_template("signup.html", error="Association ID is already registered!")
        
    try:
        # Generate random verification token for approvals
        token = f"TK-{random.randint(1000, 9999)}"
        
        # Insert credentials with PENDING status (securely hashed password)
        hashed_password = generate_password_hash(password)
        insert_user = """
            INSERT INTO users (username, password_hash, role, status)
            VALUES (%s, %s, 'resident', 'PENDING') RETURNING id;
        """
        cursor.execute(insert_user, (association_id, hashed_password))
        new_user_id = cursor.fetchone()['id']
        
        # Insert profile details
        insert_profile = """
            INSERT INTO resident_profiles (user_id, full_name, house_name_number, street_address, city, pincode, phone_number)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
        """
        cursor.execute(insert_profile, (new_user_id, full_name, house_name_number, street_address.strip(), city.strip(), pincode, phone_number))
        conn.commit()
        
        flash(f"Registration Successful! Verification Token: {token}. Pending Admin approval.", "success")
        
    except Exception:
        conn.rollback()
        cursor.close()
        conn.close()
        return render_template("signup.html", error="A database error occurred during registration. Please try again.")
        
    cursor.close()
    conn.close()
    return redirect(url_for('index'))

# 4. Handle login verification (GET & POST /login)
@app.route('/login', methods=['GET', 'POST'])
def login_process():
    if request.method == 'GET':
        return redirect(url_for('index'))
        
    association_id = request.form.get('association_id')
    password = request.form.get('password')
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    # Validate login credentials against database
    cursor.execute("SELECT * FROM users WHERE username = %s;", (association_id,))
    user = cursor.fetchone()
    
    is_authenticated = False
    if user:
        # Check using secure password hash
        try:
            if check_password_hash(user['password_hash'], password):
                is_authenticated = True
        except Exception:
            pass
            
        # Backward-compatibility fallback for pre-existing plaintext passwords
        if not is_authenticated and user['password_hash'] == password:
            is_authenticated = True
            # Transparently upgrade legacy plaintext password to secure hash in DB
            try:
                upgrade_cursor = conn.cursor()
                upgrade_cursor.execute(
                    "UPDATE users SET password_hash = %s WHERE id = %s;",
                    (generate_password_hash(password), user['id'])
                )
                conn.commit()
                upgrade_cursor.close()
            except Exception:
                conn.rollback()

    cursor.close()
    conn.close()
    
    if is_authenticated:
        # Check if the registration is pending admin approval
        if user['status'] == 'PENDING':
            flash("Your account is pending admin approval.", "error")
            return redirect(url_for('index'))
            
        # Store user details in session
        session['logged_in'] = True
        session['user_id'] = user['id']
        session['association_id'] = user['username']
        session['role'] = user['role'] # Fetch directly from DB result
        session['_csrf_token'] = secrets.token_hex(32) # Rotate CSRF token on privilege transition
        
        # Automatic Role-Based Redirection
        if user['role'].lower() == 'admin':
            return redirect(url_for('admin_ui'))
        elif user['role'].lower() == 'resident':
            return redirect(url_for('resident_ui'))
        else:
            flash("Invalid role assignment.", "error")
            return redirect(url_for('index'))
            
    return render_template("login.html", error="Invalid Credentials")

# 5. Resident Dashboard (GET /resident)
@app.route('/resident')
def resident_ui():
    if not session.get('logged_in') or session.get('role', '').lower() != 'resident':
        flash("Unauthorized Access: Please log in first.", "error")
        return redirect(url_for('index'))
        
    association_id = session.get('association_id')
    user_id = session.get('user_id')
    selected_category = request.args.get('category', '')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Fetch resident profile details
        cursor.execute("""
            SELECT full_name, house_name_number, street_address, city, pincode, phone_number 
            FROM resident_profiles 
            WHERE user_id = %s;
        """, (user_id,))
        profile_data = cursor.fetchone()
        
        profile = {
            "association_id": association_id,
            "full_name": profile_data['full_name'] if profile_data else "N/A",
            "house_name_number": profile_data['house_name_number'] if profile_data else "N/A",
            "street_address": profile_data['street_address'] if profile_data else "N/A",
            "city": profile_data['city'] if profile_data else "N/A",
            "pincode": profile_data['pincode'] if profile_data else "N/A",
            "phone_number": profile_data['phone_number'] if profile_data else "N/A"
        }
        
        # Fetch assets from database
        if selected_category:
            cursor.execute(
                "SELECT id, name as asset_name, category as asset_category, total_qty, available_qty, daily_rent FROM assets WHERE category = %s;",
                (selected_category,)
            )
        else:
            cursor.execute("SELECT id, name as asset_name, category as asset_category, total_qty, available_qty, daily_rent FROM assets;")
        filtered_assets = cursor.fetchall()
        
        # Fetch active resident bookings
        active_query = """
            SELECT b.id as booking_id, a.name as asset_name, b.booked_qty as quantity, 
                   b.duration_days, TO_CHAR(b.booking_date, 'YYYY-MM-DD') as booking_date,
                   TO_CHAR(b.booking_date + (b.duration_days || ' days')::interval, 'YYYY-MM-DD') AS return_deadline,
                   b.status, b.payment_status
            FROM bookings b
            JOIN assets a ON b.asset_id = a.id
            WHERE b.resident_id = %s AND b.status = 'Active';
        """
        cursor.execute(active_query, (user_id,))
        active_bookings = cursor.fetchall()

        # Fetch past returned bookings & associated fines
        past_query = """
            SELECT b.id as booking_id, a.name as asset_name, b.booked_qty as quantity,
                   b.duration_days, TO_CHAR(b.booking_date, 'YYYY-MM-DD') as booking_date,
                   (b.booked_qty * a.daily_rent * b.duration_days) as total_rental_price,
                   f.fine_amount,
                   f.payment_status as fine_payment_status,
                   b.payment_status as booking_payment_status
            FROM bookings b
            JOIN assets a ON b.asset_id = a.id
            LEFT JOIN fines f ON b.id = f.booking_id
            WHERE b.resident_id = %s AND b.status = 'Returned';
        """
        cursor.execute(past_query, (user_id,))
        past_bookings = cursor.fetchall()
        
        cursor.close()
        conn.close()
    except Exception as e:
        if app.debug:
            raise e
        flash("Service temporarily unavailable. Please try again later.", "error")
        return render_template("login.html", error="Database service unavailable.")
    
    return render_template("resident_dashboard.html", assets=filtered_assets, profile=profile, selected_category=selected_category, active_bookings=active_bookings, past_bookings=past_bookings)

# 6. Admin Dashboard (GET /admin)
@app.route('/admin', methods=['GET'])
def admin_ui():
    if not session.get('logged_in'):
        flash("Unauthorized Access: Please log in first.", "error")
        return redirect(url_for('index'))
    if session.get('role', '').lower() != 'admin':
        flash("Unauthorized Access: You do not have permission to access the Admin dashboard.", "error")
        if session.get('role', '').lower() == 'resident':
            return redirect(url_for('resident_ui'))
        return redirect(url_for('index'))
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Fetch all assets
        cursor.execute("SELECT id, name as asset_name, category as asset_category, total_qty, available_qty, daily_rent FROM assets;")
        all_assets = cursor.fetchall()
        
        # Fetch pending resident registrations
        pending_query = """
            SELECT u.id as user_id, u.username as association_id, 
                   p.full_name, p.house_name_number, p.street_address, p.city, p.pincode, p.phone_number 
            FROM users u
            JOIN resident_profiles p ON u.id = p.user_id
            WHERE u.status = 'PENDING' AND u.role = 'resident';
        """
        cursor.execute(pending_query)
        pending_residents = cursor.fetchall()
        
        # Fetch all currently leased assets
        leased_query = """
            SELECT b.id as booking_id, a.name as asset_name, p.full_name as resident_name, 
                   p.house_name_number, p.phone_number, b.booked_qty as quantity, 
                   TO_CHAR(b.booking_date, 'YYYY-MM-DD') as borrowed_date,
                   TO_CHAR(b.booking_date + (b.duration_days || ' days')::interval, 'YYYY-MM-DD') AS due_date,
                   (b.booked_qty * a.daily_rent * b.duration_days) as total_rental_price,
                   b.payment_status
            FROM bookings b
            JOIN users u ON b.resident_id = u.id
            JOIN resident_profiles p ON u.id = p.user_id
            JOIN assets a ON b.asset_id = a.id
            WHERE b.status = 'Active';
        """
        cursor.execute(leased_query)
        leased_assets = cursor.fetchall()
        
        # Fetch historical returned bookings (Completed & Overdue Ledger Log)
        completed_query = """
            SELECT b.id as booking_id, p.full_name as resident_name, a.name as asset_name, 
                   TO_CHAR(b.booking_date + (b.duration_days || ' days')::interval, 'YYYY-MM-DD') AS due_date,
                   TO_CHAR(b.booking_date + (b.duration_days || ' days')::interval, 'YYYY-MM-DD') AS return_date,
                   b.duration_days,
                   (b.booked_qty * a.daily_rent * b.duration_days) as total_rental_price,
                   f.id as fine_id,
                   f.fine_amount,
                   f.payment_status,
                   b.payment_status as booking_payment_status
            FROM bookings b
            JOIN users u ON b.resident_id = u.id
            JOIN resident_profiles p ON u.id = p.user_id
            JOIN assets a ON b.asset_id = a.id
            LEFT JOIN fines f ON b.id = f.booking_id
            WHERE b.status = 'Returned';
        """
        cursor.execute(completed_query)
        completed_ledger = cursor.fetchall()
        
        # Fetch all resident complaints
        complaints_query = """
            SELECT c.id as complaint_id, c.description, c.status, a.name as asset_name, 
                   p.full_name as resident_name, p.house_name_number
            FROM complaints c
            JOIN bookings b ON c.booking_id = b.id
            JOIN users u ON b.resident_id = u.id
            JOIN resident_profiles p ON u.id = p.user_id
            JOIN assets a ON b.asset_id = a.id;
        """
        cursor.execute(complaints_query)
        all_complaints = cursor.fetchall()
        
        cursor.close()
        conn.close()
    except Exception as e:
        if app.debug:
            raise e
        flash("Service temporarily unavailable. Please try again later.", "error")
        return render_template("login.html", error="Database service unavailable.")
    
    return render_template(
        "add_asset.html", 
        assets=all_assets, 
        pending_residents=pending_residents,
        leased_assets=leased_assets,
        completed_ledger=completed_ledger,
        complaints=all_complaints
    )

# 7. Add new asset (POST /admin)
@app.route('/admin', methods=['POST'])
def admin_add_asset():
    if not session.get('logged_in') or session.get('role', '').lower() != 'admin':
        flash("Unauthorized Access", "error")
        return redirect(url_for('index'))
        
    name = request.form.get('asset_name')
    category = request.form.get('asset_category')
    qty_raw = request.form.get('total_qty')
    rent_raw = request.form.get('daily_rent')
    
    # Form input validation
    if not name or not category or not qty_raw or not rent_raw:
        flash("Error: All fields are required to register an asset.", "error")
        return redirect(url_for('admin_ui'))
        
    try:
        qty = int(qty_raw)
        rent = float(rent_raw)
        if qty <= 0:
            flash("Error: Total quantity must be a positive integer.", "error")
            return redirect(url_for('admin_ui'))
        if rent < 0.00:
            flash("Error: Daily rent fee cannot be negative.", "error")
            return redirect(url_for('admin_ui'))
    except ValueError:
        flash("Error: Quantity and Daily Rent must be valid numeric values.", "error")
        return redirect(url_for('admin_ui'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Insert new asset record
        insert_query = """
            INSERT INTO assets (name, category, total_qty, available_qty, daily_rent)
            VALUES (%s, %s, %s, %s, %s);
        """
        cursor.execute(insert_query, (name.strip(), category, qty, qty, rent))
        conn.commit()
        flash("Asset successfully added to catalog.", "success")
    except Exception:
        conn.rollback()
        flash("A database error occurred while registering the asset.", "error")
        
    cursor.close()
    conn.close()
    return redirect(url_for('admin_ui'))

# 7.5. Delete an asset (POST /admin/delete_asset/<asset_id>)
@app.route('/admin/delete_asset/<int:asset_id>', methods=['POST'])
def admin_delete_asset(asset_id):
    if not session.get('logged_in') or session.get('role', '').lower() != 'admin':
        flash("Unauthorized Access", "error")
        return redirect(url_for('index'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if asset exists
        cursor.execute("SELECT name FROM assets WHERE id = %s;", (asset_id,))
        asset = cursor.fetchone()
        if not asset:
            flash("Error: Asset not found.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('admin_ui'))
            
        # Check for active bookings
        cursor.execute(
            "SELECT COUNT(*) FROM bookings WHERE asset_id = %s AND status = 'Active';",
            (asset_id,)
        )
        active_count = cursor.fetchone()[0]
        if active_count > 0:
            flash(
                f"Error: Cannot delete '{asset[0]}'. It currently has {active_count} active booking(s). Ensure all units are returned before deletion.",
                "error"
            )
            cursor.close()
            conn.close()
            return redirect(url_for('admin_ui'))
            
        # Delete the asset item from the assets table
        cursor.execute("DELETE FROM assets WHERE id = %s;", (asset_id,))
        conn.commit()
        flash("Asset deleted successfully!", "success")
    except Exception:
        conn.rollback()
        flash("An error occurred while deleting the asset from database.", "error")
        
    cursor.close()
    conn.close()
    return redirect(url_for('admin_ui'))

# 8. Approve pending resident registration (POST /admin/approve_resident/<user_id>)
@app.route('/admin/approve_resident/<int:user_id>', methods=['POST'])
def admin_approve_resident(user_id):
    if not session.get('logged_in') or session.get('role', '').lower() != 'admin':
        flash("Unauthorized Access", "error")
        return redirect(url_for('index'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Update resident status to APPROVED
        cursor.execute("UPDATE users SET status = 'APPROVED' WHERE id = %s AND role = 'resident';", (user_id,))
        conn.commit()
        flash("Resident registration approved successfully!", "success")
    except Exception:
        conn.rollback()
        flash("A database error occurred during approval verification.", "error")
        
    cursor.close()
    conn.close()
    return redirect(url_for('admin_ui'))

# 9. Book an asset (POST /book_asset/<asset_id>)
@app.route('/book_asset/<int:asset_id>', methods=['POST'])
def book_asset(asset_id):
    if not session.get('logged_in') or session.get('role', '').lower() != 'resident':
        flash("Unauthorized Access", "error")
        return redirect(url_for('index'))
        
    user_id = session.get('user_id')
    
    quantity_raw = request.form.get('quantity')
    duration_raw = request.form.get('duration_days')
    
    # Strict validations
    if not quantity_raw or not quantity_raw.isdigit() or int(quantity_raw) <= 0:
        flash("Error: Booking quantity must be a positive integer.", "error")
        return redirect(url_for('resident_ui'))
    if not duration_raw or not duration_raw.isdigit():
        flash("Error: Lease duration must be a valid positive integer.", "error")
        return redirect(url_for('resident_ui'))
        
    quantity_requested = int(quantity_raw)
    duration_days = int(duration_raw)
    
    if duration_days < 1 or duration_days > 30:
        flash("Error: Lease duration must be between 1 and 30 days.", "error")
        return redirect(url_for('resident_ui'))
    
    payment_status = request.form.get('payment_status', 'Pending')
    if payment_status not in ['Paid', 'Pending']:
        payment_status = 'Pending'
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Use select for update to lock the row and prevent race conditions
        cursor.execute("SELECT available_qty FROM assets WHERE id = %s FOR UPDATE;", (asset_id,))
        asset = cursor.fetchone()
        
        if asset and asset['available_qty'] >= quantity_requested:
            # Deduct quantity from inventory
            cursor.execute("UPDATE assets SET available_qty = available_qty - %s WHERE id = %s;", (quantity_requested, asset_id))
            
            # Insert booking transaction
            booking_query = """
                INSERT INTO bookings (resident_id, asset_id, booked_qty, duration_days, status, payment_status)
                VALUES (%s, %s, %s, %s, 'Active', %s);
            """
            cursor.execute(booking_query, (user_id, asset_id, quantity_requested, duration_days, payment_status))
            conn.commit()
            
            flash(f"Success: Booking confirmed for {quantity_requested} unit(s)!", "success")
        else:
            flash("Error: Requested quantity is not available!", "error")
    except Exception:
        conn.rollback()
        flash("An error occurred while confirming the booking.", "error")
        
    cursor.close()
    conn.close()
    return redirect(url_for('resident_ui'))

# 9.5. Return an asset (POST /admin/return_asset/<booking_id>)
@app.route('/admin/return_asset/<int:booking_id>', methods=['POST'])
def return_asset(booking_id):
    if not session.get('logged_in') or session.get('role', '').lower() != 'admin':
        flash("Unauthorized Access: Only administrators can check in assets.", "error")
        return redirect(url_for('index'))
        
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Fetch active booking details
        cursor.execute("SELECT * FROM bookings WHERE id = %s AND status = 'Active';", (booking_id,))
        booking = cursor.fetchone()
        
        if not booking:
            flash("Error: Active booking not found.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('admin_ui'))
            
        # Lock asset for update
        cursor.execute("SELECT * FROM assets WHERE id = %s FOR UPDATE;", (booking['asset_id'],))
        asset = cursor.fetchone()
        
        if asset:
            # Calculate actual elapsed days
            booking_date = booking['booking_date']
            elapsed_time = datetime.now() - booking_date
            elapsed_days = elapsed_time.days
            
            overdue_days = elapsed_days - booking['duration_days']
            
            # If overdue, compute fine
            if overdue_days > 0:
                fine_amount = overdue_days * booking['booked_qty'] * 20
                # Insert fine record
                cursor.execute(
                    "INSERT INTO fines (booking_id, fine_amount, payment_status) VALUES (%s, %s, 'Pending');",
                    (booking_id, fine_amount)
                )
                flash(f"Return completed with overdue fine of ₹{fine_amount:.2f} logged.", "warning")
            else:
                flash("Asset returned on time. No fine generated.", "success")
                
            # Restore stock
            cursor.execute(
                "UPDATE assets SET available_qty = available_qty + %s WHERE id = %s;",
                (booking['booked_qty'], booking['asset_id'])
            )
            
            # Mark booking status as Returned
            cursor.execute("UPDATE bookings SET status = 'Returned' WHERE id = %s;", (booking_id,))
            conn.commit()
            
    except Exception:
        conn.rollback()
        flash("A database error occurred while checking back the asset.", "error")
        
    cursor.close()
    conn.close()
    return redirect(url_for('admin_ui'))

# 10.5. Report a complaint (POST /report_complaint)
@app.route('/report_complaint', methods=['POST'])
def report_complaint():
    if not session.get('logged_in') or session.get('role', '').lower() != 'resident':
        flash("Unauthorized Access", "error")
        return redirect(url_for('index'))
        
    user_id = session.get('user_id')
    booking_id_raw = request.form.get('booking_id')
    description = request.form.get('description')
    
    if not booking_id_raw or not booking_id_raw.isdigit() or not description or not description.strip():
        flash("Error: Missing booking selection or complaint details.", "error")
        return redirect(url_for('resident_ui'))
        
    booking_id = int(booking_id_raw)
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify ownership: booking must exist and belong to the authenticated resident
        cursor.execute("SELECT id FROM bookings WHERE id = %s AND resident_id = %s;", (booking_id, user_id))
        owned_booking = cursor.fetchone()
        
        if not owned_booking:
            flash("Error: Booking record not found or access denied.", "error")
            cursor.close()
            conn.close()
            return redirect(url_for('resident_ui'))

        cursor.execute(
            "INSERT INTO complaints (booking_id, description, status) VALUES (%s, %s, 'Pending');",
            (booking_id, description.strip())
        )
        conn.commit()
        flash("Complaint logged successfully! The management team will review it.", "success")
    except Exception:
        conn.rollback()
        flash("An error occurred while logging the complaint details.", "error")
        
    cursor.close()
    conn.close()
    return redirect(url_for('resident_ui'))

# 10.6. Resolve a complaint (POST /admin/resolve_complaint/<complaint_id>)
@app.route('/admin/resolve_complaint/<int:complaint_id>', methods=['POST'])
def resolve_complaint(complaint_id):
    if not session.get('logged_in') or session.get('role', '').lower() != 'admin':
        flash("Unauthorized Access", "error")
        return redirect(url_for('index'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE complaints SET status = 'Resolved' WHERE id = %s;", (complaint_id,))
        conn.commit()
        flash("Complaint marked as resolved.", "success")
    except Exception:
        conn.rollback()
        flash("An error occurred while resolving the complaint.", "error")
        
    cursor.close()
    conn.close()
    return redirect(url_for('admin_ui'))

# 10.7. Settle a pending fine (POST /admin/pay_fine/<fine_id>)
@app.route('/admin/pay_fine/<int:fine_id>', methods=['POST'])
def pay_fine(fine_id):
    if not session.get('logged_in') or session.get('role', '').lower() != 'admin':
        flash("Unauthorized Access", "error")
        return redirect(url_for('index'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE fines SET payment_status = 'Paid' WHERE id = %s;", (fine_id,))
        conn.commit()
        flash("Fine marked as paid successfully.", "success")
    except Exception:
        conn.rollback()
        flash("An error occurred while settling the fine.", "error")
        
    cursor.close()
    conn.close()
    return redirect(url_for('admin_ui'))

# 11. Logout (GET /logout)
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# 11.5. Dedicated Profile Page (GET /profile)
@app.route('/profile', methods=['GET'])
def profile_ui():
    if not session.get('logged_in'):
        flash("Unauthorized Access: Please log in first.", "error")
        return redirect(url_for('index'))
        
    user_id = session.get('user_id')
    role = session.get('role', '').lower()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Fetch user account details
        cursor.execute("SELECT username as association_id, role, status FROM users WHERE id = %s;", (user_id,))
        user_account = cursor.fetchone()
        
        profile = None
        if role == 'resident':
            cursor.execute("""
                SELECT full_name, house_name_number, street_address, city, pincode, phone_number 
                FROM resident_profiles 
                WHERE user_id = %s;
            """, (user_id,))
            profile = cursor.fetchone()
            
        cursor.close()
        conn.close()
    except Exception as e:
        if app.debug:
            raise e
        flash("Service temporarily unavailable. Please try again later.", "error")
        return render_template("login.html", error="Database service unavailable.")
        
    return render_template("profile.html", profile=profile, role=role, user_account=user_account)

# 12. Update resident profile (POST /profile/update)
@app.route('/profile/update', methods=['POST'])
def profile_update():
    if not session.get('logged_in') or session.get('role', '').lower() != 'resident':
        flash("Unauthorized Access", "error")
        return redirect(url_for('index'))
        
    user_id = session.get('user_id')
    full_name = request.form.get('full_name')
    house_name_number = request.form.get('house_name_number')
    phone_number = request.form.get('phone_number')
    street_address = request.form.get('street_address')
    city = request.form.get('city')
    pincode = request.form.get('pincode')
    
    if not full_name or not house_name_number or not phone_number or not pincode:
        flash("Error: Missing required fields.", "error")
        return redirect(url_for('profile_ui'))
        
    if not pincode.isdigit() or len(pincode) != 6:
        flash("Error: Pincode must be exactly 6 digits.", "error")
        return redirect(url_for('profile_ui'))
        
    if not phone_number.isdigit() or len(phone_number) < 10 or len(phone_number) > 12:
        flash("Error: Phone number must be a valid 10-12 digit number.", "error")
        return redirect(url_for('profile_ui'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        update_query = """
            UPDATE resident_profiles 
            SET full_name = %s, house_name_number = %s, phone_number = %s, 
                street_address = %s, city = %s, pincode = %s 
            WHERE user_id = %s;
        """
        cursor.execute(
            update_query, 
            (full_name.strip(), house_name_number.strip(), phone_number.strip(), 
             street_address.strip(), city.strip(), pincode.strip(), user_id)
        )
        conn.commit()
        flash("Profile updated successfully.", "success")
    except Exception:
        conn.rollback()
        flash("A database error occurred while updating your profile.", "error")
        
    cursor.close()
    conn.close()
    return redirect(url_for('profile_ui'))

# 13. Secure Change Password (POST /change_password)
@app.route('/change_password', methods=['POST'])
def change_password():
    if not session.get('logged_in'):
        flash("Unauthorized Access: Please log in first.", "error")
        return redirect(url_for('index'))
        
    user_id = session.get('user_id')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_password or not new_password or not confirm_password:
        flash("Error: All password fields are required.", "error")
        return redirect(url_for('profile_ui'))
        
    if new_password != confirm_password:
        flash("Error: New passwords do not match.", "error")
        return redirect(url_for('profile_ui'))
        
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Fetch existing user details
        cursor.execute("SELECT * FROM users WHERE id = %s;", (user_id,))
        user = cursor.fetchone()
        
        current_matches = False
        if user:
            try:
                if check_password_hash(user['password_hash'], current_password):
                    current_matches = True
            except Exception:
                pass
            if not current_matches and user['password_hash'] == current_password:
                current_matches = True
        
        if user and current_matches:
            # Change password with secure hash
            hashed_new_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s;", (hashed_new_password, user_id))
            conn.commit()
            flash("Password updated successfully.", "success")
        else:
            flash("Error: Incorrect current password.", "error")
            
    except Exception:
        conn.rollback()
        flash("A database error occurred while updating the password.", "error")
        
    cursor.close()
    conn.close()
    return redirect(url_for('profile_ui'))

# Production Error Handlers (BUG-012)
@app.errorhandler(400)
def handle_bad_request(e):
    return render_template("login.html", error=getattr(e, 'description', "Bad Request.")), 400

@app.errorhandler(404)
def handle_not_found(e):
    return render_template("login.html", error="The requested page or resource could not be found."), 404

@app.errorhandler(500)
def handle_internal_error(e):
    if app.debug:
        raise e
    return render_template("login.html", error="An internal server error occurred. Please contact the administrator."), 500

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() in ('true', '1', 't')
    app.run(debug=debug_mode)