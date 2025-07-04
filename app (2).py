from flask import Flask, render_template, request, redirect, url_for, flash, session
import psycopg2
from psycopg2 import sql, Error
import bcrypt
from datetime import datetime, date, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a random string

# PostgreSQL configuration
db = psycopg2.connect(
    host="localhost",
    database="bloodbank",
    user="postgres",  # Replace with your PostgreSQL username
    password="postgres",  # Replace with your PostgreSQL password
    port="5432"
)

@app.route('/')
def index():
    if 'user_id' in session and 'role' in session:
        role = session['role']
        print(f"User {session['user_id']} logged in as {role}, redirecting to {role.lower().replace(' ', '')}_dashboard")
        return redirect(url_for(f"{role.lower().replace(' ', '')}_dashboard"))
    print("No session, rendering login.html")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        blood_type = request.form['blood_type']
        city_id = request.form['city_id']
        dob = request.form['dob']
        contact = request.form['contact']
        password = request.form['password']
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        cursor = db.cursor()
        try:
            query = sql.SQL("""
                INSERT INTO users (name, blood_type, city_id, dob, contact, password_hash)
                VALUES (%s, %s, %s, %s, %s, %s)
            """)
            cursor.execute(query, (name, blood_type, city_id, dob, contact, hashed_password.decode('utf-8')))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('index'))
        except psycopg2.Error as e:
            db.rollback()
            error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
            flash(f'Registration error: {error_msg}', 'error')
            print(f"Register error: {error_msg} | Full error: {e}")
            return render_template('register.html')
        finally:
            cursor.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session and 'role' in session:
        role = session['role']
        print(f"User {session['user_id']} already logged in as {role}, redirecting to {role.lower().replace(' ', '')}_dashboard")
        return redirect(url_for(f"{role.lower().replace(' ', '')}_dashboard"))

    if request.method == 'POST':
        role = request.form['role'].strip()
        user_id = request.form['user_id']
        password = request.form['password'].encode('utf-8')
        
        role = ' '.join(word.capitalize() for word in role.split())
        print(f"Login attempt: user_id={user_id}, role={role}")
        
        cursor = db.cursor()
        try:
            if role == 'User':
                query = sql.SQL("SELECT password_hash, name, blood_type, city_id FROM users WHERE user_id = %s")
                cursor.execute(query, (user_id,))
                result = cursor.fetchone()
                print(f"User query result: {result}")
                if result and bcrypt.checkpw(password, result[0].encode('utf-8')):
                    if result[3] is None:
                        flash('Your account is missing a city. Please update your profile.', 'error')
                        print(f"User {user_id} has no city_id")
                        return redirect(url_for('index'))
                    session['user_id'] = user_id
                    session['name'] = result[1] or 'User'
                    session['role'] = 'user'
                    session['user_blood_type'] = result[2]
                    session['city_id'] = result[3]
                    session.permanent = True
                    print(f"User {user_id} logged in as user, name: {session['name']}, city_id: {session['city_id']}")
                    return redirect(url_for('user_dashboard'))
                else:
                    flash('Invalid user ID or password for user role.', 'error')
                    print(f"Failed user login for user_id: {user_id}")
            
            elif role in ('Admin', 'Camp Coordinator', 'Registrar'):
                query = sql.SQL("""
                    SELECT u.password_hash, u.name, e.employee_id, u.city_id
                    FROM employees e
                    JOIN users u ON e.user_id = u.user_id
                    WHERE e.user_id = %s AND e.role = %s
                """)
                cursor.execute(query, (user_id, role))
                result = cursor.fetchone()
                print(f"Employee query result for role {role}: {result}")
                if result and bcrypt.checkpw(password, result[0].encode('utf-8')):
                    if result[3] is None:
                        flash('Your account is missing a city. Please contact an admin.', 'error')
                        print(f"Employee {user_id} has no city_id")
                        return redirect(url_for('index'))
                    session['user_id'] = user_id
                    session['name'] = result[1] or f'{role} User'
                    session['role'] = role
                    session['employee_id'] = result[2]
                    session['city_id'] = result[3]
                    session.permanent = True
                    print(f"User {user_id} logged in as {role}, name: {session['name']}, employee_id: {session['employee_id']}, city_id: {session['city_id']}")
                    return redirect(url_for(f"{role.lower().replace(' ', '')}_dashboard"))
                else:
                    flash(f'Invalid user ID, password, or role for {role}.', 'error')
                    print(f"Failed {role} login for user_id: {user_id}")
            
            else:
                flash('Invalid role selected.', 'error')
                print(f"Invalid role: {role}")
            
        except Exception as e:
            flash(f'Login error: {str(e)}', 'error')
            print(f"Login error: {e}")
        finally:
            cursor.close()
        return redirect(url_for('index'))
    
    print("Rendering login.html for GET request")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    print("Session cleared, redirecting to index")
    return redirect(url_for('index'))

@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'user_id' not in session or 'role' in session and session['role'] != 'user':
        session.clear()
        flash('Please log in as a user.', 'error')
        print("Invalid session or role for user_dashboard, redirecting to index")
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    user_name = session.get('name', 'User')
    
    cursor = db.cursor()
    
    try:
        if request.method == 'POST' and 'submit_donation' in request.form:
            donation_date_str = request.form['donation_date']
            try:
                donation_date = datetime.strptime(donation_date_str, '%Y-%m-%d').date()
                
                # Validate user and get blood_type, city_id
                cursor.execute("SELECT blood_type, city_id FROM users WHERE user_id = %s", (user_id,))
                user_data = cursor.fetchone()
                if not user_data:
                    flash('User not found.', 'error')
                    return redirect(url_for('user_dashboard'))
                
                blood_type, city_id = user_data
                
                # Validate and clean blood_type
                valid_blood_types = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
                blood_type = blood_type.strip()
                if blood_type not in valid_blood_types:
                    flash(f'Invalid blood type: {blood_type}. Must be one of {", ".join(valid_blood_types)}.', 'error')
                    return redirect(url_for('user_dashboard'))
                
                # Find active camp in user's city
                cursor.execute("""
                    SELECT camp_id
                    FROM camp
                    WHERE city_id = %s
                    AND %s BETWEEN start_date AND end_date
                    LIMIT 1
                """, (city_id, donation_date))
                camp = cursor.fetchone()
                if not camp:
                    flash('No active camp found in your city for the selected date.', 'error')
                    return redirect(url_for('user_dashboard'))
                
                camp_id = camp[0]
                
                # Insert into inventory
                cursor.execute("""
                    INSERT INTO inventory (camp_id, blood_type, expiry_date, assigned)
                    VALUES (%s, %s, %s, %s)
                    RETURNING blood_id
                """, (camp_id, blood_type, donation_date + timedelta(days=42), 'no'))
                blood_id = cursor.fetchone()[0]
                
                # Insert into donates
                cursor.execute("""
                    INSERT INTO donates (user_id, blood_id, donation_date)
                    VALUES (%s, %s, %s)
                """, (user_id, blood_id, donation_date))
                
                db.commit()
                flash(f'Donation recorded successfully! Blood ID: {blood_id}', 'success')
                
            except ValueError:
                flash('Invalid date format.', 'error')
            except psycopg2.Error as e:
                db.rollback()
                error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
                flash(f'Donation error: {error_msg}', 'error')
                print(f"Donation error: {error_msg} | Full error: {e}")
        
        # Fetch user details using user_view_details
        cursor.execute("SELECT user_view_details(%s)", (user_id,))
        user_details = cursor.fetchone()[0]  # JSONB object
        print(f"Fetched user details for user_id {user_id}: {user_details}")
        
        return render_template('user_dashboard.html', user_details=user_details)
    
    except psycopg2.Error as e:
        db.rollback()
        error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
        flash(f'Error loading dashboard: {error_msg}', 'error')
        print(f"User dashboard error: {error_msg} | Full error: {e}")
        return render_template('user_dashboard.html', user_details={})
    
    finally:
        cursor.close()

@app.route('/campcoordinator_dashboard', methods=['GET', 'POST'])
def campcoordinator_dashboard():
    if 'user_id' not in session or 'role' not in session or session['role'] != 'Camp Coordinator':
        session.clear()
        flash('Please log in as a camp coordinator.', 'error')
        print("Invalid session or role for campcoordinator_dashboard, redirecting to index")
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    city_id = session.get('city_id')
    name = session.get('name', 'Camp Coordinator')
    
    if not city_id:
        flash('Your account is missing a city. Please contact an admin.', 'error')
        print(f"User {user_id} has no city_id in session")
        return redirect(url_for('index'))
    
    cursor = db.cursor()
    
    try:
        if request.method == 'POST' and 'add_camp' in request.form:
            start_date = request.form['start_date']
            end_date = request.form['end_date']
            try:
                start = datetime.strptime(start_date, '%Y-%m-%d')
                end = datetime.strptime(end_date, '%Y-%m-%d')
                cursor.execute("SELECT coordinator_add_camp(%s, %s, %s)", (city_id, start_date, end_date))
                camp_id = cursor.fetchone()[0]
                db.commit()
                flash(f'Camp {camp_id} added successfully!', 'success')
            except ValueError:
                flash('Invalid date format.', 'error')
            except psycopg2.Error as e:
                db.rollback()
                error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
                flash(f'Camp error: {error_msg}', 'error')
                print(f"Camp error: {error_msg} | Full error: {e}")
                
                
                
                # Check for expired blood
        cursor.execute("""
            SELECT COUNT(i.blood_id)
            FROM inventory i
            JOIN camp c ON i.camp_id = c.camp_id
            WHERE c.city_id = %s
            AND i.assigned = 'ex'
        """, (city_id,))
        expired_count = cursor.fetchone()[0]
        
        if expired_count > 0:
            flash(f'{expired_count} blood unit(s) have expired and are marked as ''ex''.', 'warning')
        
        cursor.execute("""
            SELECT r.request_id, r.user_id, u.name, r.blood_type, r.units_required,
                   rs.process_id, rs.blood_id, i.expiry_date
            FROM requests r
            JOIN request_status rs ON r.request_id = rs.request_id
            JOIN users u ON r.user_id = u.user_id
            JOIN inventory i ON rs.blood_id = i.blood_id
            WHERE rs.status = 'no'
            AND rs.blood_found = 'yes'
            AND rs.blood_id IS NOT NULL
            AND u.city_id = %s
        """, (city_id,))
        pending_requests = cursor.fetchall()
        
        if pending_requests:
            flash(f'{len(pending_requests)} pending request(s) with assigned blood need approval.', 'info')
        
        cursor.execute("""
            SELECT camp_id, start_date, end_date
            FROM camp
            WHERE city_id = %s
            ORDER BY start_date
        """, (city_id,))
        camps = cursor.fetchall()
        
        cursor.execute("""
            SELECT i.blood_type, COUNT(i.blood_id) AS blood_count, MIN(i.expiry_date) AS earliest_expiry
            FROM inventory i
            JOIN camp c ON i.camp_id = c.camp_id
            WHERE c.city_id = %s
            AND i.expiry_date > CURRENT_DATE
            GROUP BY i.blood_type
            ORDER BY i.blood_type
        """, (city_id,))
        inventory = cursor.fetchall()
        
        return render_template('campcoordinator_dashboard.html',
                             camps=camps,
                             pending_requests=pending_requests,
                             inventory=inventory,
                             city_id=city_id,
                             name=name)
    
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        print(f"Campcoordinator dashboard error: {e}")
        return render_template('campcoordinator_dashboard.html',
                             camps=[],
                             pending_requests=[],
                             inventory=[],
                             city_id=city_id,
                             name=name)
    
    finally:
        cursor.close()

@app.route('/approve_request/<int:process_id>', methods=['POST'])
def approve_request(process_id):
    if 'user_id' not in session or session['role'] != 'Camp Coordinator':
        flash('Unauthorized access.', 'error')
        return redirect(url_for('index'))
    
    cursor = db.cursor()
    try:
        cursor.execute("SELECT process_blood_request(%s, %s)", (process_id, 'approve'))
        db.commit()
        flash('Request approved successfully!', 'success')
    except psycopg2.Error as e:
        db.rollback()
        error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
        flash(f'Error approving request: {error_msg}', 'error')
        print(f"Approve request error: {error_msg} | Full error: {e}")
    finally:
        cursor.close()
    
    return redirect(url_for('campcoordinator_dashboard'))

@app.route('/reject_request/<int:process_id>', methods=['POST'])
def reject_request(process_id):
    if 'user_id' not in session or session['role'] != 'Camp Coordinator':
        session.clear()
        flash('Please log in as a camp coordinator.', 'error')
        print("Invalid session or role for reject_request, redirecting to index")
        return redirect(url_for('index'))
    
    cursor = db.cursor()
    try:
        cursor.execute("SELECT process_blood_request(%s, %s)", (process_id, 'reject'))
        db.commit()
        flash('Request rejected and blood unassigned.', 'success')
    except psycopg2.Error as e:
        db.rollback()
        error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
        flash(f'Error rejecting request: {error_msg}', 'error')
        print(f"Reject request error: {error_msg} | Full error: {e}")
    finally:
        cursor.close()
    return redirect(url_for('campcoordinator_dashboard'))

@app.route('/registrar_dashboard', methods=['GET', 'POST'])
def registrar_dashboard():
    if 'user_id' not in session or 'role' not in session or session['role'] != 'Registrar':
        session.clear()
        flash('Please log in as a registrar.', 'error')
        print("Invalid session or role for registrar_dashboard, redirecting to index")
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    employee_id = session.get('employee_id')
    name = session.get('name', 'Registrar')
    city_id = session.get('city_id')
    
    if not city_id:
        flash('Your account is missing a city. Please contact an admin.', 'error')
        print(f"User {user_id} has no city_id in session")
        return redirect(url_for('index'))
    
    cursor = db.cursor()
    
    try:
        cursor.execute("SELECT city_id, name FROM city ORDER BY name")
        cities = cursor.fetchall()
        
        selected_city_id = None
        inventory = []
        donations = []
        requests = []
        request_status = []
        filter_user_id = None
        
        if request.method == 'POST':
            if 'view_inventory' in request.form:
                selected_city_id = request.form.get('city_id')
                if selected_city_id:
                    cursor.execute("""
                        SELECT i.blood_type, COUNT(i.blood_id) as quantity, c.name, MIN(i.expiry_date) as earliest_expiry
                        FROM inventory i
                        JOIN camp ca ON i.camp_id = ca.camp_id
                        JOIN city c ON ca.city_id = c.city_id
                        WHERE ca.city_id = %s AND i.expiry_date > CURRENT_DATE
                        GROUP BY i.blood_type, c.name
                        ORDER BY i.blood_type
                    """, (selected_city_id,))
                    inventory = cursor.fetchall()
            
            elif 'request_blood' in request.form:
                recipient_user_id = request.form['recipient_user_id']
                blood_type = request.form['blood_type']
                units_required = request.form['units_required']
                request_date = request.form['request_date']
                
                try:
                    units_required = int(units_required)
                    datetime.strptime(request_date, '%Y-%m-%d')
                    cursor.execute("SELECT registrar_add_request(%s, %s, %s, %s, %s)",
                                  (recipient_user_id, employee_id, blood_type, units_required, request_date))
                    request_id = cursor.fetchone()[0]
                    db.commit()
                    flash(f'Blood request {request_id} submitted successfully!', 'success')
                except ValueError:
                    flash('Invalid units required or date format.', 'error')
                except psycopg2.Error as e:
                    db.rollback()
                    error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
                    flash(f'Request error: {error_msg}', 'error')
                    print(f"Request blood error: {error_msg} | Full error: {e}")
            
            elif 'filter_user' in request.form:
                filter_user_id = request.form.get('filter_user_id')
                if filter_user_id:
                    try:
                        filter_user_id = int(filter_user_id)
                        cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (filter_user_id,))
                        if not cursor.fetchone():
                            flash('Invalid user ID for filtering.', 'error')
                            filter_user_id = None
                    except ValueError:
                        flash('User ID must be a number.', 'error')
                        filter_user_id = None
        
        if filter_user_id:
            cursor.execute("""
                SELECT d.user_id, u.name, d.blood_id, i.blood_type, d.donation_date, c.name,u.contact
                FROM donates d
                JOIN users u ON d.user_id = u.user_id
                JOIN inventory i ON d.blood_id = i.blood_id
                JOIN camp ca ON i.camp_id = ca.camp_id
                JOIN city c ON ca.city_id = c.city_id
                WHERE d.user_id = %s
                ORDER BY d.donation_date DESC
            """, (filter_user_id,))
        else:
            cursor.execute("""
                SELECT d.user_id, u.name, d.blood_id, i.blood_type, d.donation_date, c.name,u.contact
                FROM donates d
                JOIN users u ON d.user_id = u.user_id
                JOIN inventory i ON d.blood_id = i.blood_id
                JOIN camp ca ON i.camp_id = ca.camp_id
                JOIN city c ON ca.city_id = c.city_id
                ORDER BY d.donation_date DESC
            """)
        donations = cursor.fetchall()
        
        if filter_user_id:
            cursor.execute("""
                SELECT r.request_id, r.user_id, u.name, r.employee_id, r.blood_type, r.units_required, r.request_date
                FROM requests r
                JOIN users u ON r.user_id = u.user_id
                WHERE r.user_id = %s
                ORDER BY r.request_date DESC
            """, (filter_user_id,))
        else:
            cursor.execute("""
                SELECT r.request_id, r.user_id, u.name, r.employee_id, r.blood_type, r.units_required, r.request_date
                FROM requests r
                JOIN users u ON r.user_id = u.user_id
                ORDER BY r.request_date DESC
            """)
        requests = cursor.fetchall()
        
        if filter_user_id:
            cursor.execute("""
                SELECT rs.process_id, rs.request_id, rs.blood_id, rs.status, rs.blood_found, rs.date_approved
                FROM request_status rs
                JOIN requests r ON rs.request_id = r.request_id
                WHERE r.user_id = %s
                ORDER BY rs.process_id
            """, (filter_user_id,))
        else:
            cursor.execute("""
                SELECT rs.process_id, rs.request_id, rs.blood_id, rs.status, rs.blood_found, rs.date_approved
                FROM request_status rs
                ORDER BY rs.process_id
            """)
        request_status = cursor.fetchall()
        
        return render_template('registrar_dashboard.html',
                             cities=cities,
                             selected_city_id=selected_city_id,
                             inventory=inventory,
                             donations=donations,
                             requests=requests,
                             request_status=request_status,
                             filter_user_id=filter_user_id,
                             name=name)
    
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        print(f"Registrar dashboard error: {e}")
        return render_template('registrar_dashboard.html',
                             cities=[],
                             selected_city_id=None,
                             inventory=[],
                             donations=[],
                             requests=[],
                             request_status=[],
                             filter_user_id=None,
                             name=name)
    
    finally:
        cursor.close()

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or 'role' not in session or session['role'] != 'Admin':
        session.clear()
        flash('Please log in as an admin.', 'error')
        print("Invalid session or role for admin_dashboard, redirecting to index")
        return redirect(url_for('index'))
    
    admin_user_id = session['user_id']
    admin_city_id = session.get('city_id')
    name = session.get('name', 'Admin')
    
    if not admin_city_id:
        flash('Your account is missing a city. Please contact an admin.', 'error')
        print(f"User {admin_user_id} has no city_id in session")
        return redirect(url_for('index'))
    
    cursor = db.cursor()
    
    try:
        if request.method == 'POST':
            if 'add_city' in request.form:
                city_name = request.form['city_name']
                longitude = request.form['longitude']
                latitude = request.form['latitude']
                try:
                    # Validate coordinates
                    longitude = float(longitude)
                    latitude = float(latitude)
                    cursor.execute("SELECT admin_add_city(%s, %s, %s)", (city_name, longitude, latitude))
                    city_id = cursor.fetchone()[0]
                    db.commit()
                    flash(f'City {city_name} (ID: {city_id}) added successfully!', 'success')
                except ValueError:
                    flash('Invalid longitude or latitude format.', 'error')
                except psycopg2.Error as e:
                    db.rollback()
                    error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
                    flash(f'City error: {error_msg}', 'error')
                    print(f"City error: {error_msg} | Full error: {e}")
            
            elif 'add_employee' in request.form:
                user_id = request.form['user_id']
                role = request.form['role']
                salary = request.form['salary']
                
                try: 
                    user_id = int(user_id)
                    salary = int(salary)
                    if salary <= 0:
                        flash('Salary must be positive.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    
                    cursor.execute("SELECT city_id FROM users WHERE user_id = %s", (user_id,))
                    user = cursor.fetchone()
                    if not user:
                        flash('Invalid user ID.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    if user[0] != admin_city_id:
                        flash('User is not in your city.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    
                    valid_roles = ['Camp Coordinator', 'Registrar']
                    if role not in valid_roles:
                        flash('Invalid role. Cannot assign Admin role.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    
                    cursor.execute("SELECT user_id FROM employees WHERE user_id = %s", (user_id,))
                    if cursor.fetchone():
                        flash('User is already an employee.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    
                    cursor.execute("""
                        INSERT INTO employees (role, user_id, salary)
                        VALUES (%s, %s, %s)
                    """, (role, user_id, salary))
                    db.commit()
                    flash('Employee added successfully!', 'success')
                
                except ValueError:
                    flash('User ID and salary must be numbers.', 'error')
                    return redirect(url_for('admin_dashboard'))
                except psycopg2.Error as e:
                    db.rollback()
                    error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
                    flash(f'Employee error: {error_msg}', 'error')
                    print(f"Add employee error: {error_msg} | Full error: {e}")
            
            elif 'update_employee' in request.form:
                employee_id = request.form['employee_id']
                role = request.form['role']
                salary = request.form['salary']
                
                try:
                    employee_id = int(employee_id)
                    salary = int(salary)
                    if salary <= 0:
                        flash('Salary must be positive.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    
                    valid_roles = ['Camp Coordinator', 'Registrar']
                    if role not in valid_roles:
                        flash('Invalid role. Cannot assign Admin role.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    
                    cursor.execute("""
                        SELECT e.role, u.city_id
                        FROM employees e
                        JOIN users u ON e.user_id = u.user_id
                        WHERE e.employee_id = %s
                    """, (employee_id,))
                    emp = cursor.fetchone()
                    if not emp:
                        flash('Invalid employee ID.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    if emp[0] == 'Admin':
                        flash('Cannot update another admin.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    if emp[1] != admin_city_id:
                        flash('Employee is not in your city.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    
                    cursor.execute("""
                        UPDATE employees
                        SET role = %s, salary = %s
                        WHERE employee_id = %s
                    """, (role, salary, employee_id))
                    db.commit()
                    flash('Employee updated successfully!', 'success')
                
                except ValueError:
                    flash('Employee ID and salary must be numbers.', 'error')
                    return redirect(url_for('admin_dashboard'))
                except psycopg2.Error as e:
                    db.rollback()
                    error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
                    flash(f'Employee error: {error_msg}', 'error')
                    print(f"Update employee error: {error_msg} | Full error: {e}")
            
            elif 'delete_employee' in request.form:
                employee_id = request.form['employee_id']
                
                try:
                    employee_id = int(employee_id)
                    
                    cursor.execute("""
                        SELECT e.role, u.city_id
                        FROM employees e
                        JOIN users u ON e.user_id = u.user_id
                        WHERE e.employee_id = %s
                    """, (employee_id,))
                    emp = cursor.fetchone()
                    if not emp:
                        flash('Invalid employee ID.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    if emp[0] == 'Admin':
                        flash('Cannot delete another admin.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    if emp[1] != admin_city_id:
                        flash('Employee is not in your city.', 'error')
                        return redirect(url_for('admin_dashboard'))
                    
                    cursor.execute("DELETE FROM employees WHERE employee_id = %s", (employee_id,))
                    db.commit()
                    flash('Employee deleted successfully!', 'success')
                
                except ValueError:
                    flash('Employee ID must be a number.', 'error')
                    return redirect(url_for('admin_dashboard'))
                except psycopg2.Error as e:
                    db.rollback()
                    error_msg = e.diag.message_primary if e.diag.message_primary else str(e)
                    flash(f'Employee error: {error_msg}', 'error')
                    print(f"Delete employee error: {error_msg} | Full error: {e}")
        
        cursor.execute("SELECT city_id, name FROM city ORDER BY name")
        cities = cursor.fetchall()
        
        cursor.execute("""
            SELECT e.employee_id, e.role, e.user_id, e.salary, u.name
            FROM employees e
            JOIN users u ON e.user_id = u.user_id
            WHERE e.role != 'Admin' AND u.city_id = %s
            ORDER BY e.employee_id
        """, (admin_city_id,))
        employees = cursor.fetchall()
        
        cursor.execute("SELECT COUNT(*) FROM donates")
        total_donations = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM requests")
        total_requests = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM request_status WHERE status = 'yes'")
        fulfilled_requests = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT i.blood_type, COUNT(i.blood_id) as quantity
            FROM inventory i
            WHERE i.expiry_date > CURRENT_DATE
            GROUP BY i.blood_type
            ORDER BY i.blood_type
        """)
        inventory_stats = cursor.fetchall()
        
        return render_template('admin_dashboard.html',
                             cities=cities,
                             employees=employees,
                             total_donations=total_donations,
                             total_requests=total_requests,
                             fulfilled_requests=fulfilled_requests,
                             inventory_stats=inventory_stats,
                             name=name)
    
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        print(f"Admin dashboard error: {e}")
        return render_template('admin_dashboard.html',
                             cities=[],
                             employees=[],
                             total_donations=0,
                             total_requests=0,
                             fulfilled_requests=0,
                             inventory_stats=[],
                             name=name)
    
    finally:
        cursor.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)