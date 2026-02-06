from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from functools import wraps
import os
from datetime import datetime
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

# Try PostgreSQL, fallback to SQLite
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    USE_POSTGRES = True
except ImportError:
    USE_POSTGRES = False
    print("PostgreSQL not available. Using SQLite for local development.")

app = Flask(__name__)
app.secret_key = 'academy_secret_key_2024'

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

def get_db():
    if USE_POSTGRES and DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    else:
        return sqlite3.connect('academy.db')

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    if USE_POSTGRES and DATABASE_URL:
        # PostgreSQL syntax
        c.execute('''CREATE TABLE IF NOT EXISTS admin_credentials
                     (id SERIAL PRIMARY KEY,
                      username VARCHAR(100) UNIQUE NOT NULL,
                      password_hash TEXT NOT NULL)''')
        
        c.execute('SELECT * FROM admin_credentials WHERE username = %s', ('admin',))
        if not c.fetchone():
            default_hash = generate_password_hash('admin123')
            c.execute('INSERT INTO admin_credentials (username, password_hash) VALUES (%s, %s)',
                      ('admin', default_hash))
        
        c.execute('''CREATE TABLE IF NOT EXISTS students
                     (id SERIAL PRIMARY KEY,
                      name VARCHAR(200) NOT NULL,
                      class VARCHAR(100) NOT NULL,
                      monthly_fee DECIMAL(10, 2) NOT NULL,
                      date_added DATE NOT NULL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS student_payments
                     (id SERIAL PRIMARY KEY,
                      student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
                      amount DECIMAL(10, 2) NOT NULL,
                      payment_method VARCHAR(50) NOT NULL,
                      payment_date DATE NOT NULL,
                      month_year VARCHAR(20) NOT NULL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS teachers
                     (id SERIAL PRIMARY KEY,
                      name VARCHAR(200) NOT NULL,
                      monthly_salary DECIMAL(10, 2) NOT NULL,
                      date_added DATE NOT NULL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS teacher_payments
                     (id SERIAL PRIMARY KEY,
                      teacher_id INTEGER REFERENCES teachers(id) ON DELETE CASCADE,
                      amount DECIMAL(10, 2) NOT NULL,
                      payment_date DATE NOT NULL,
                      month_year VARCHAR(20) NOT NULL)''')
    else:
        # SQLite syntax
        c.execute('''CREATE TABLE IF NOT EXISTS admin_credentials
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      password_hash TEXT NOT NULL)''')
        
        c.execute('SELECT * FROM admin_credentials WHERE username = ?', ('admin',))
        if not c.fetchone():
            default_hash = generate_password_hash('admin123')
            c.execute('INSERT INTO admin_credentials (username, password_hash) VALUES (?, ?)',
                      ('admin', default_hash))
        
        c.execute('''CREATE TABLE IF NOT EXISTS students
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      class TEXT NOT NULL,
                      monthly_fee REAL NOT NULL,
                      date_added TEXT NOT NULL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS student_payments
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      student_id INTEGER,
                      amount REAL NOT NULL,
                      payment_method TEXT NOT NULL,
                      payment_date TEXT NOT NULL,
                      month_year TEXT NOT NULL,
                      FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS teachers
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      monthly_salary REAL NOT NULL,
                      date_added TEXT NOT NULL)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS teacher_payments
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      teacher_id INTEGER,
                      amount REAL NOT NULL,
                      payment_date TEXT NOT NULL,
                      month_year TEXT NOT NULL,
                      FOREIGN KEY (teacher_id) REFERENCES teachers(id) ON DELETE CASCADE)''')
    
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        
        if USE_POSTGRES and DATABASE_URL:
            c = conn.cursor(cursor_factory=RealDictCursor)
            c.execute('SELECT * FROM admin_credentials WHERE username = %s', (username,))
            admin = c.fetchone()
        else:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM admin_credentials WHERE username = ?', (username,))
            admin = c.fetchone()
        
        conn.close()
        
        if admin and check_password_hash(admin['password_hash'], password):
            session['logged_in'] = True
            session['username'] = username
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    return render_template('login.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            return jsonify({'success': False, 'message': 'New passwords do not match'})
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'})
        
        conn = get_db()
        
        if USE_POSTGRES and DATABASE_URL:
            c = conn.cursor(cursor_factory=RealDictCursor)
            c.execute('SELECT * FROM admin_credentials WHERE username = %s', (session['username'],))
            admin = c.fetchone()
        else:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM admin_credentials WHERE username = ?', (session['username'],))
            admin = c.fetchone()
        
        if not admin or not check_password_hash(admin['password_hash'], current_password):
            conn.close()
            return jsonify({'success': False, 'message': 'Current password is incorrect'})
        
        new_hash = generate_password_hash(new_password)
        
        if USE_POSTGRES and DATABASE_URL:
            c.execute('UPDATE admin_credentials SET password_hash = %s WHERE username = %s',
                      (new_hash, session['username']))
        else:
            c.execute('UPDATE admin_credentials SET password_hash = ? WHERE username = ?',
                      (new_hash, session['username']))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM students')
    total_students = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM teachers')
    total_teachers = c.fetchone()[0]
    
    if USE_POSTGRES and DATABASE_URL:
        c.execute('SELECT COALESCE(SUM(amount), 0) FROM student_payments')
        total_collected = float(c.fetchone()[0])
        c.execute('SELECT COALESCE(SUM(amount), 0) FROM teacher_payments')
        total_salaries_paid = float(c.fetchone()[0])
    else:
        c.execute('SELECT SUM(amount) FROM student_payments')
        total_collected = c.fetchone()[0] or 0
        c.execute('SELECT SUM(amount) FROM teacher_payments')
        total_salaries_paid = c.fetchone()[0] or 0
    
    conn.close()
    
    return render_template('dashboard.html', 
                         total_students=total_students,
                         total_teachers=total_teachers,
                         total_collected=total_collected,
                         total_salaries_paid=total_salaries_paid)

@app.route('/students')
@login_required
def students():
    conn = get_db()
    
    if USE_POSTGRES and DATABASE_URL:
        c = conn.cursor(cursor_factory=RealDictCursor)
    else:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
    
    class_filter = request.args.get('class', '')
    
    if USE_POSTGRES and DATABASE_URL:
        if class_filter:
            c.execute('SELECT * FROM students WHERE class = %s ORDER BY name', (class_filter,))
        else:
            c.execute('SELECT * FROM students ORDER BY name')
    else:
        if class_filter:
            c.execute('SELECT * FROM students WHERE class = ? ORDER BY name', (class_filter,))
        else:
            c.execute('SELECT * FROM students ORDER BY name')
    
    students = c.fetchall()
    
    students_data = []
    for student in students:
        if USE_POSTGRES and DATABASE_URL:
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM student_payments WHERE student_id = %s', (student['id'],))
            total_paid = float(c.fetchone()[0])
            date_added = student['date_added']
        else:
            c.execute('SELECT SUM(amount) FROM student_payments WHERE student_id = ?', (student['id'],))
            total_paid = c.fetchone()[0] or 0
            date_added = datetime.strptime(student['date_added'], '%Y-%m-%d')
        
        months_enrolled = ((datetime.now().year - date_added.year) * 12 + 
                          datetime.now().month - date_added.month) + 1
        
        monthly_fee = float(student['monthly_fee'])
        total_due = monthly_fee * months_enrolled
        pending_amount = total_due - total_paid
        paid_months = int(total_paid / monthly_fee) if monthly_fee > 0 else 0
        pending_months = months_enrolled - paid_months
        
        students_data.append({
            'id': student['id'],
            'name': student['name'],
            'class': student['class'],
            'monthly_fee': monthly_fee,
            'total_paid': total_paid,
            'pending_amount': pending_amount,
            'paid_months': paid_months,
            'pending_months': pending_months
        })
    
    conn.close()
    
    classes = ['5th Grade', '6th Grade', '7th Grade', '8th Grade', '9th Grade', 
               '10th Grade', '11th Grade (1st Year)', '12th Grade (2nd Year)']
    
    return render_template('students.html', students=students_data, 
                         classes=classes, selected_class=class_filter)

@app.route('/students/add', methods=['POST'])
@login_required
def add_student():
    name = request.form.get('name')
    class_name = request.form.get('class')
    monthly_fee = float(request.form.get('monthly_fee'))
    
    conn = get_db()
    c = conn.cursor()
    
    if USE_POSTGRES and DATABASE_URL:
        c.execute('INSERT INTO students (name, class, monthly_fee, date_added) VALUES (%s, %s, %s, %s)',
                  (name, class_name, monthly_fee, datetime.now().date()))
    else:
        c.execute('INSERT INTO students (name, class, monthly_fee, date_added) VALUES (?, ?, ?, ?)',
                  (name, class_name, monthly_fee, datetime.now().strftime('%Y-%m-%d')))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/students/edit/<int:id>', methods=['POST'])
@login_required
def edit_student(id):
    name = request.form.get('name')
    class_name = request.form.get('class')
    monthly_fee = float(request.form.get('monthly_fee'))
    
    conn = get_db()
    c = conn.cursor()
    
    if USE_POSTGRES and DATABASE_URL:
        c.execute('UPDATE students SET name = %s, class = %s, monthly_fee = %s WHERE id = %s',
                  (name, class_name, monthly_fee, id))
    else:
        c.execute('UPDATE students SET name = ?, class = ?, monthly_fee = ? WHERE id = ?',
                  (name, class_name, monthly_fee, id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/students/delete/<int:id>', methods=['POST'])
@login_required
def delete_student(id):
    conn = get_db()
    c = conn.cursor()
    
    if USE_POSTGRES and DATABASE_URL:
        c.execute('DELETE FROM students WHERE id = %s', (id,))
    else:
        c.execute('DELETE FROM student_payments WHERE student_id = ?', (id,))
        c.execute('DELETE FROM students WHERE id = ?', (id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/students/<int:id>/payment', methods=['POST'])
@login_required
def add_student_payment(id):
    amount = float(request.form.get('amount'))
    payment_method = request.form.get('payment_method')
    month_year = request.form.get('month_year')
    
    conn = get_db()
    c = conn.cursor()
    
    if USE_POSTGRES and DATABASE_URL:
        c.execute('INSERT INTO student_payments (student_id, amount, payment_method, payment_date, month_year) VALUES (%s, %s, %s, %s, %s)',
                  (id, amount, payment_method, datetime.now().date(), month_year))
    else:
        c.execute('INSERT INTO student_payments (student_id, amount, payment_method, payment_date, month_year) VALUES (?, ?, ?, ?, ?)',
                  (id, amount, payment_method, datetime.now().strftime('%Y-%m-%d'), month_year))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/students/<int:id>/receipt')
@login_required
def student_receipt(id):
    conn = get_db()
    
    if USE_POSTGRES and DATABASE_URL:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT * FROM students WHERE id = %s', (id,))
        student = c.fetchone()
        c.execute('SELECT * FROM student_payments WHERE student_id = %s ORDER BY payment_date DESC', (id,))
        payments = c.fetchall()
        c.execute('SELECT COALESCE(SUM(amount), 0) FROM student_payments WHERE student_id = %s', (id,))
        total_paid = float(c.fetchone()[0])
    else:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM students WHERE id = ?', (id,))
        student = c.fetchone()
        c.execute('SELECT * FROM student_payments WHERE student_id = ? ORDER BY payment_date DESC', (id,))
        payments = c.fetchall()
        c.execute('SELECT SUM(amount) FROM student_payments WHERE student_id = ?', (id,))
        total_paid = c.fetchone()[0] or 0
    
    conn.close()
    
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    p.setFont("Helvetica-Bold", 24)
    p.drawString(1*inch, height - 1*inch, "Perfect Science Academy")
    
    p.setFont("Helvetica-Bold", 18)
    p.drawString(1*inch, height - 1.5*inch, "Student Fee Receipt")
    
    p.setFont("Helvetica-Bold", 12)
    y = height - 2.2*inch
    p.drawString(1*inch, y, f"Student Name: {student['name']}")
    y -= 0.3*inch
    p.drawString(1*inch, y, f"Class: {student['class']}")
    y -= 0.3*inch
    p.drawString(1*inch, y, f"Monthly Fee: Rs. {float(student['monthly_fee']):.2f}")
    y -= 0.3*inch
    p.drawString(1*inch, y, f"Total Paid: Rs. {total_paid:.2f}")
    
    y -= 0.6*inch
    p.setFont("Helvetica-Bold", 14)
    p.drawString(1*inch, y, "Payment History:")
    
    y -= 0.4*inch
    p.setFont("Helvetica", 10)
    for payment in payments:
        p.drawString(1*inch, y, f"{payment['payment_date']} - Rs. {float(payment['amount']):.2f} - {payment['payment_method']} - {payment['month_year']}")
        y -= 0.25*inch
        if y < 1*inch:
            break
    
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f'receipt_{student["name"]}.pdf', mimetype='application/pdf')

@app.route('/teachers')
@login_required
def teachers():
    conn = get_db()
    
    if USE_POSTGRES and DATABASE_URL:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT * FROM teachers ORDER BY name')
        teachers = c.fetchall()
    else:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM teachers ORDER BY name')
        teachers = c.fetchall()
    
    teachers_data = []
    for teacher in teachers:
        if USE_POSTGRES and DATABASE_URL:
            c.execute('SELECT COALESCE(SUM(amount), 0) FROM teacher_payments WHERE teacher_id = %s', (teacher['id'],))
            total_paid = float(c.fetchone()[0])
            date_added = teacher['date_added']
        else:
            c.execute('SELECT SUM(amount) FROM teacher_payments WHERE teacher_id = ?', (teacher['id'],))
            total_paid = c.fetchone()[0] or 0
            date_added = datetime.strptime(teacher['date_added'], '%Y-%m-%d')
        
        months_employed = ((datetime.now().year - date_added.year) * 12 + 
                          datetime.now().month - date_added.month) + 1
        
        monthly_salary = float(teacher['monthly_salary'])
        total_due = monthly_salary * months_employed
        pending_amount = total_due - total_paid
        paid_months = int(total_paid / monthly_salary) if monthly_salary > 0 else 0
        pending_months = months_employed - paid_months
        
        teachers_data.append({
            'id': teacher['id'],
            'name': teacher['name'],
            'monthly_salary': monthly_salary,
            'total_paid': total_paid,
            'pending_amount': pending_amount,
            'paid_months': paid_months,
            'pending_months': pending_months
        })
    
    conn.close()
    
    return render_template('teachers.html', teachers=teachers_data)

@app.route('/teachers/add', methods=['POST'])
@login_required
def add_teacher():
    name = request.form.get('name')
    monthly_salary = float(request.form.get('monthly_salary'))
    
    conn = get_db()
    c = conn.cursor()
    
    if USE_POSTGRES and DATABASE_URL:
        c.execute('INSERT INTO teachers (name, monthly_salary, date_added) VALUES (%s, %s, %s)',
                  (name, monthly_salary, datetime.now().date()))
    else:
        c.execute('INSERT INTO teachers (name, monthly_salary, date_added) VALUES (?, ?, ?)',
                  (name, monthly_salary, datetime.now().strftime('%Y-%m-%d')))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/teachers/edit/<int:id>', methods=['POST'])
@login_required
def edit_teacher(id):
    name = request.form.get('name')
    monthly_salary = float(request.form.get('monthly_salary'))
    
    conn = get_db()
    c = conn.cursor()
    
    if USE_POSTGRES and DATABASE_URL:
        c.execute('UPDATE teachers SET name = %s, monthly_salary = %s WHERE id = %s',
                  (name, monthly_salary, id))
    else:
        c.execute('UPDATE teachers SET name = ?, monthly_salary = ? WHERE id = ?',
                  (name, monthly_salary, id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/teachers/delete/<int:id>', methods=['POST'])
@login_required
def delete_teacher(id):
    conn = get_db()
    c = conn.cursor()
    
    if USE_POSTGRES and DATABASE_URL:
        c.execute('DELETE FROM teachers WHERE id = %s', (id,))
    else:
        c.execute('DELETE FROM teacher_payments WHERE teacher_id = ?', (id,))
        c.execute('DELETE FROM teachers WHERE id = ?', (id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/teachers/<int:id>/payment', methods=['POST'])
@login_required
def add_teacher_payment(id):
    amount = float(request.form.get('amount'))
    month_year = request.form.get('month_year')
    
    conn = get_db()
    c = conn.cursor()
    
    if USE_POSTGRES and DATABASE_URL:
        c.execute('INSERT INTO teacher_payments (teacher_id, amount, payment_date, month_year) VALUES (%s, %s, %s, %s)',
                  (id, amount, datetime.now().date(), month_year))
    else:
        c.execute('INSERT INTO teacher_payments (teacher_id, amount, payment_date, month_year) VALUES (?, ?, ?, ?)',
                  (id, amount, datetime.now().strftime('%Y-%m-%d'), month_year))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/reports')
@login_required
def reports():
    conn = get_db()
    
    if USE_POSTGRES and DATABASE_URL:
        c = conn.cursor(cursor_factory=RealDictCursor)
    else:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
    
    classes = ['5th Grade', '6th Grade', '7th Grade', '8th Grade', '9th Grade', 
               '10th Grade', '11th Grade (1st Year)', '12th Grade (2nd Year)']
    
    class_summary = []
    for class_name in classes:
        if USE_POSTGRES and DATABASE_URL:
            c.execute('SELECT * FROM students WHERE class = %s', (class_name,))
        else:
            c.execute('SELECT * FROM students WHERE class = ?', (class_name,))
        
        students = c.fetchall()
        
        total_collected = 0
        total_pending = 0
        
        for student in students:
            if USE_POSTGRES and DATABASE_URL:
                c.execute('SELECT COALESCE(SUM(amount), 0) FROM student_payments WHERE student_id = %s', (student['id'],))
                paid = float(c.fetchone()[0])
                date_added = student['date_added']
            else:
                c.execute('SELECT SUM(amount) FROM student_payments WHERE student_id = ?', (student['id'],))
                paid = c.fetchone()[0] or 0
                date_added = datetime.strptime(student['date_added'], '%Y-%m-%d')
            
            total_collected += paid
            
            months_enrolled = ((datetime.now().year - date_added.year) * 12 + 
                              datetime.now().month - date_added.month) + 1
            total_due = float(student['monthly_fee']) * months_enrolled
            total_pending += (total_due - paid)
        
        if len(students) > 0:
            class_summary.append({
                'class': class_name,
                'students': len(students),
                'collected': total_collected,
                'pending': total_pending
            })
    
    conn.close()
    
    return render_template('reports.html', class_summary=class_summary)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)