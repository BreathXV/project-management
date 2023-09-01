from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
from datetime import datetime
import json
import logging

current_datetime = datetime.now()  # Keep it as a datetime object

date_string = current_datetime.strftime('%Y-%m-%d')  # You can format it to a string when needed
time_string = current_datetime.strftime('%H-%M-%S')

app = Flask(__name__)
app.secret_key = 'your_secret_key'

logging.basicConfig(filename=f'errors/logs/app{date_string}{time_string}.log', level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

with open('./errors/errors.json', 'r') as f:
    errors = json.load(f)

def saveError(errorMessage, functionName, errorCodeDisplayed):
    with open(f'./errors/logs/{functionName}_{date_string}{time_string}.txt', 'w') as f:
        f.write(f"SQLite Error recorded on {date_string} at {time_string} on {functionName}:\n\n{errorMessage}\n\nError Code is: {errorCodeDisplayed}\n")

def initialize_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY,
            project_name TEXT NOT NULL,
            project_tag TEXT,
            assignee TEXT UNIQUE NOT NULL,
            project_description TEXT,
            project_payment REAL,
            project_due_date TEXT,  -- Use TEXT data type for datetime
            project_platform TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("Database tables initialized successfully.")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def require_login():
    public_routes = ['login', 'error']

    if 'username' not in session and request.endpoint not in public_routes:
        return redirect(url_for('login'))

def create_user(username, password, role):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
    
        hashed_password = generate_password_hash(password, method='sha256')
        cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))


        conn.commit()
    except Exception as e:
        logging.error('An error occurred: %s', str(e))
    finally:
        if conn:
            conn.close()

def get_user(username):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        user = cursor.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    except Exception as e:
        logging.error('An error occurred: %s', str(e))
    finally:
        if conn:
            conn.close()
            return user

def create_project_in_database(project_data):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO projects (project_name, project_tag, assignee, project_description, project_payment, project_due_date, project_platform)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            project_data['project_name'], project_data['project_tag'], project_data['assignee'], project_data['project_description'],
            project_data['project_payment'], project_data['project_due_date'], project_data['project_platform']
        ))

        conn.commit()
    except Exception as e:
        logging.error('An error occurred: %s', str(e))
    finally:
        if conn:
            conn.close()

def get_user_projects(username):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        user_projects = cursor.execute('SELECT * FROM projects WHERE assignee = ?', (username,)).fetchall()
    except Exception as e:
        logging.error('An error occurred: %s', str(e))
    finally:
        if conn:
            conn.close()
            return user_projects

def get_project_by_id(project_id):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        project = cursor.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
    except Exception as e:
        logging.error('An error occurred: %s', str(e))
    finally:
        if conn:
            conn.close()
            return project

def fetch_projects():
    try:
        conn = sqlite3.connect('database.db')  # Update the database name if needed
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM projects')
        projects = cursor.fetchall()
        
        conn.close()
        
        return projects
    except sqlite3.Error as e:
        logging.error('An error occurred: %s', str(e))
        return []

def get_all_projects():
    try:
        conn = sqlite3.connect('your_database.db')  # Replace 'your_database.db' with your database file path
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM projects")

        all_projects = []
        for row in cursor.fetchall():
            project = {
                'id': row[0],
                'project_name': row[1],
                'project_tag': row[2],
                'assignee': row[3],
                'project_description': row[4],
                'project_payment': row[5],
                'project_due_date': row[6],
                'project_platform': row[7]
            }
            all_projects.append(project)

        conn.close()

        return all_projects

    except Exception as e:
        logging.error('An error occurred while fetching all projects: %s', str(e))
        return []

def delete_project_by_id(project_id):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        project = cursor.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
        if project:
            cursor.execute('DELETE FROM projects WHERE id = ?', (project_id,))
            conn.commit()
            conn.close()
            return True  # Deletion was successful
        else:
            conn.close()
            return False  # Project with the given ID doesn't exist

    except sqlite3.Error as e:
        logging.error('An error occurred: %s', str(e))
        return False  # An error occurred during deletion

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        
        if user and check_password_hash(user[2], password):
            session['username'] = username
            session['is_admin'] = (username == 'root')  # Set is_admin for root user
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    
    return render_template('login.html')

@app.before_request
def before_request():
    try:
        if 'username' not in session and request.endpoint not in ['login']:
            return redirect(url_for('login'))
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    projects = get_user_projects(username)
    return render_template('dashboard.html', projects=projects)

@app.route('/project_management')
@login_required
def project_management():
    try:
        if session.get('is_admin') or session.get('is_manager'):
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            users = cursor.execute('SELECT * FROM users').fetchall()
            conn.close()

            return render_template('project_management.html', users=users)
    except Exception as e:
        logging.error('An error occurred: %s', str(e))
        if conn:
            conn.close()
    else:
        try:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        except Exception as e:
            logging.error('An error occurred: %s', str(e))

@app.route('/create_project.html', methods=['GET', 'POST'])
@login_required
def create_project():
    try:
        if request.method == 'POST':
            project_data = {
                'project_name': request.form['project_name'],
                'project_tag': request.form['project_tag'],
                'assignee': 'Unassigned', # Unassigned untill assigned
                'project_description': request.form['project_description'],
                'project_payment': float(request.form['project_payment']),
                'project_due_date': request.form['project_due_date'],
                'project_platform': request.form['project_platform']
            }

            create_project_in_database(project_data)
            flash('Project created successfully!', 'success')
            return redirect(url_for('dashboard'))

        return render_template('create_project.html')
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

@app.route('/delete_project', methods=['POST'])
def delete_project():
    try:
        if 'username' not in session:
            flash('You need to log in first.', 'danger')
            return redirect(url_for('login'))
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

    try:
        if request.method == 'POST':
            project_id = request.form['project-id-delete']

            conn = sqlite3.connect('./database.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM projects WHERE id = ?', (project_id,))
            project = cursor.fetchone()
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

    try:
        if project:
            cursor.execute('DELETE FROM projects WHERE id = ?', (project_id,))
            conn.commit()
            conn.close()
            flash('Project deleted successfully.', 'success')
        else:
            flash('Project not found. Deletion failed.', 'danger')
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

    return redirect(url_for('project_management'))

@app.route('/assign_members', methods=['GET', 'POST'])
def assign_members():
    if 'username' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    if 'is_admin' not in session or not session['is_admin']:
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        project_id = request.form['project-id']
        members = request.form['member-username']

        member_list = [m.strip() for m in members.split(',')]

        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()

            for member_username in member_list:
                user = cursor.execute('SELECT * FROM users WHERE username = ?', (member_username,)).fetchone()
                if user:
                    cursor.execute('UPDATE projects SET assignee = ? WHERE id = ?', (member_username, project_id))
                else:
                    flash(f'Member username "{member_username}" does not exist.', 'danger')

            conn.commit()

            conn.close()

            flash('Member assigned to project successfully', 'success')

        except sqlite3.Error as e:
            flash(f'Error assigning member: {str(e)}', 'danger')
            logging.error('An error occurred: %s', str(e))

    try:
        projects = fetch_projects()
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

    try:
        return render_template('project_management.html', projects=projects)
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

@app.route('/projects/<project_type>')
@login_required
def projects(project_type):
    try:
        if 'username' in session:
            username = session['username']
            
            if project_type == 'user':
                user_projects = get_user_projects(username)
                return render_template('projects.html', projects=user_projects, project_type='user')
            elif project_type == 'all':
                all_projects = get_all_projects()  # Implement this function to get all projects from the database.
                return render_template('projects.html', projects=all_projects, project_type='all')
            else:
                flash('Invalid project type.', 'error')
                return redirect(url_for('dashboard'))
        else:
            flash('Please log in to access projects.', 'info')
            return redirect(url_for('login'))
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

@app.route('/project/<int:project_id>')
@login_required
def project_details(project_id):
    try:
        project = get_project_by_id(project_id)
        if project:
            return render_template('project_details.html', project=project)
        else:
            flash('Project not found.', 'danger')
            return redirect(url_for('projects'))
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

@app.route('/staff_management')
@login_required
def staff_management():
    try:
        if session.get('is_admin') or session.get('is_manager'):
            return render_template('staff_management.html')
        else:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

@app.route('/register_user', methods=['POST'])
@login_required
def register_user():
    try:
        if session.get('is_admin') or session.get('is_manager'):
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']

            hashed_password = generate_password_hash(password, method='sha256')

            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                        (username, hashed_password, role))
            conn.commit()
            conn.close()

            flash('User registered successfully.', 'success')
            return redirect(url_for('staff_management'))
        else:
            flash('You do not have permission to perform this action.', 'danger')
            return redirect(url_for('dashboard'))
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

@app.route('/error')
def error_page(errorIdentifier, errorMessage, errorFunction):
    try:
        saveError(errorMessage=errorMessage, functionName=errorFunction, errorCodeDisplayed=errorIdentifier)
        return render_template(url_for('error'), error=errorIdentifier)
    except Exception as e:
        logging.error('An error occurred: %s', str(e))

if __name__ == '__main__':
    initialize_database()
    app.run(debug=True)