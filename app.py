from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from email_validator import validate_email, EmailNotValidError
from flask_limiter.util import get_remote_address
from apscheduler.triggers.date import DateTrigger
from logging.handlers import RotatingFileHandler
from email.mime.multipart import MIMEMultipart
from password_strength import PasswordPolicy
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect
from email.mime.text import MIMEText
from flask_mail import Mail, Message
from bson.objectid import ObjectId
from flask_login import login_user
from flask_pymongo import PyMongo
from bson.errors import InvalidId
from flask_limiter import Limiter
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
from functools import wraps
from bson import json_util
from bson import ObjectId
import secrets
import logging
import smtplib
import bcrypt
import time
import html
import json
import pytz
import os
import re



app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#------------ My MongoDB --------------------------

#client = MongoClient('mongodb://localhost:27017/')
client = MongoClient('mongodb://jkldbc:wp9BuIzO0JLSOyYps1rcB1cLJadALea4tcH71WqlU2UC2frtSBVflYaUtkD0J06CVbXX1Gm5CM3BACDbQjmqBA==@jkldbc.mongo.cosmos.azure.com:10255/?ssl=true&retrywrites=false&replicaSet=globaldb&maxIdleTimeMS=120000&appName=@jkldbc@')
db = client['healthcare_db']
users_collection = db['users']
appointments_collection = db['appointments']
caregivers_collection = db['caregivers']
patients_collection = db['patients']
caregiverslist_collection = db['caregiverlist']
requests_collection = db['registration_requests']
rate_limit_collection = db['rate_limits']

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.role = user_data.get('role', 'user')

# ------------------ For Email----------------------------
load_dotenv()
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = os.getenv('EMAIL_SENDER')
SENDER_PASSWORD = os.getenv('EMAIL_PASSWORD')

@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

@app.route('/')
def index():
    return render_template('index/index.html')

# ------------------------ Admin Login ------------------------

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/user/role')
@login_required
def get_user_role():
    return jsonify({'role': current_user.role})

def init_admin():
    admin_username = "admin"
    admin_password = "admin@1337"
    
    admin_exists = users_collection.find_one({'username': admin_username, 'role': 'admin'})
    if not admin_exists:
        password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        users_collection.insert_one({
            'username': admin_username,
            'password_hash': password_hash,
            'role': 'admin'
        })
        print("Admin user created successfully")


# ------------------------ Register ------------------------


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:

            fullname = html.escape((request.form.get('fullname') or '').strip())[:50]
            username = html.escape((request.form.get('username') or '').strip())[:50]
            email = html.escape((request.form.get('email') or '').strip())[:50]
            password = (request.form.get('password') or '').strip()[:100]
            confirm_password = (request.form.get('confirm_password') or '').strip()[:100]
            role = html.escape((request.form.get('role') or '').strip())[:50]

            if not all([fullname, username, email, password, confirm_password, role]):
                flash("All fields are required", 'error')
                return redirect(url_for('register'))

            if not validate_username(username):
                flash("Username must be between 3-50 characters, start with a letter, and contain only letters, numbers, underscores, and hyphens", 'error')
                return redirect(url_for('register'))

            if users_collection.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}}):
                flash('Username or Email already exists', 'error')
                return redirect(url_for('register'))

            try:
                valid_email = validate_email(email, check_deliverability=True)
                email = valid_email.email.lower()
            except EmailNotValidError:
                flash("Invalid email address", 'error')
                return redirect(url_for('register'))

            if users_collection.find_one({'email': {'$regex': f'^{re.escape(email)}$', '$options': 'i'}}):
                flash('Username or Email already exists', 'error')
                return redirect(url_for('register'))

            if not validate_password(password):
                flash("Password must be at least 8 characters", 'error')
                return redirect(url_for('register'))

            if password != confirm_password:
                flash("Passwords do not match", 'error')
                return redirect(url_for('register'))

            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
            verification_token = secrets.token_urlsafe(32)
            
            registration_data = {
                'fullname': fullname,
                'username': username,
                'email': email,
                'password_hash': password_hash,
                'role': role,
                'status': 'pending',
                'verification_token': verification_token,
                'created_at': datetime.utcnow(),
                'last_modified': datetime.utcnow(),
                'registration_ip': request.remote_addr,
                'is_verified': False,
                'failed_login_attempts': 0,
                'last_login_attempt': None
            }

            try:
                result = requests_collection.insert_one(registration_data)
                if not result.acknowledged:
                    raise Exception("Failed to save registration data")
                
                logging.info(f"Successful registration request for user: {username}")
                
                flash('Registration request submitted successfully. Please verify your email and wait for admin approval.', 'success')
                return redirect(url_for('login'))

            except Exception as e:
                logging.error(f"Registration error: {str(e)}")
                flash('An error occurred during registration. Please try again.', 'error')
                return redirect(url_for('register'))

        except Exception as e:
            logging.error(f"Unexpected registration error: {str(e)}")
            flash('An unexpected error occurred. Please try again later.', 'error')
            return redirect(url_for('register'))

    return render_template('register/register.html')

def validate_username(username):
    username_pattern = r'^[a-zA-Z][a-zA-Z0-9_-]{2,49}$'
    return bool(re.match(username_pattern, username))

def validate_password(password):
    if len(password) < 8:
        return False
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    return all([has_upper, has_lower, has_digit, has_special])




#----------------------admin manage--------------------------------------------


@app.route('/admin/register-requests')
@role_required('admin')
def register_requests():
    requests = requests_collection.find({"status": "pending"})
    return render_template('register_requests/register_requests.html', requests=requests)


@app.route('/admin/approve-request/<id>')
@role_required('admin') 
def approve_request(id):
    try:
        request_doc = requests_collection.find_one({"_id": ObjectId(id)})
        if request_doc:

            user_doc = {
                "username": request_doc['username'],
                "email": request_doc['email'],
                "password_hash": request_doc['password_hash'],  
                "role": request_doc['role']
            }
            
            users_collection.insert_one(user_doc)
            requests_collection.update_one({"_id": ObjectId(id)}, {"$set": {"status": "approved"}})
            flash('User approved successfully!', 'success')
        return redirect(url_for('register_requests'))
    except Exception as e:
        flash(f'Error approving user: {str(e)}', 'error')
        return redirect(url_for('register_requests'))


@app.route('/admin/reject-request/<id>')
@role_required('admin')  
def reject_request(id):
    requests_collection.update_one({"_id": ObjectId(id)}, {"$set": {"status": "rejected"}})
    flash('User rejected successfully!', 'danger')
    return redirect(url_for('register_requests'))


# ------------------------ Login ------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'][:30]
        password = request.form['password'][:30]

        user_data = users_collection.find_one({'username': username})

        if user_data and user_data.get('password_hash'):
            if bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash']):
                user = User(user_data)
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('home'))

        flash('Invalid username or password', 'error')
    return render_template('login/login.html')


# ------------------------ Logout -------------------------------

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# ------------------------ Home Page After Login ------------------------

@app.route('/home')
@login_required
def home():
    today = datetime.today()
    week_later = today + timedelta(days=7)

    # Fetch appointments based on the user role
    appointments = []
    if current_user.role in ['admin', 'caregiver']:
        appointments = appointments_collection.find({'date': {'$gte': today, '$lte': week_later}})

    # Pass additional role information to the template
    return render_template(
        'home/home.html',
        username=current_user.username,
        role=current_user.role,
        appointments=list(appointments)
    )
#-----------------------------send_appointment_email-------------------------------------

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def convert_objectid_to_str(data):
    """
    Recursively convert all ObjectId instances to strings in any data structure
    """
    if isinstance(data, dict):
        return {key: convert_objectid_to_str(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_objectid_to_str(item) for item in data]
    elif isinstance(data, ObjectId):
        return str(data)
    return data

def send_appointment_email(patient_email, patient_name, caregiver_name, appointment_type, appointment_date):
    """Send appointment confirmation email"""
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = patient_email
        msg['Subject'] = 'JKL Healthcare - Appointment Confirmation'

        formatted_date = datetime.strptime(appointment_date, '%Y-%m-%dT%H:%M').strftime('%B %d, %Y at %I:%M %p')

        body = f"""
        Dear {patient_name},

        Your appointment has been successfully scheduled with JKL Healthcare.

        Appointment Details:
        Caregiver: {caregiver_name}
        Type: {appointment_type}
        Date and Time: {formatted_date}

        Location: JKL Healthcare Center
        
        Important Reminders:
        - Please arrive 15 minutes before your scheduled time
        - Bring any relevant medical records or documentation
        - If you need to reschedule, please contact us at least 24 hours in advance

        If you have any questions, please don't hesitate to contact us.

        Best regards,
        JKL Healthcare Team
        """

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return False


# ------------------------ Make Appointment ------------------------

@app.route('/makeappointment', methods=['GET', 'POST'])
def makeappointment():
    if request.method == 'POST':
        try:
            data = request.json 
            
            new_appointment = {
                'patientName': data.get('patientName'),
                'caregiverName': data.get('caregiverName'),
                'caregiverEmail': data.get('caregiverEmail'),
                'appointmentDate': data.get('appointmentDate'),
                'appointmentType': data.get('appointmentType'),
                'status': 'Scheduled'
            }

            result = appointments_collection.insert_one(new_appointment)
            
            email_sent = send_appointment_email(
                patient_email=data.get('caregiverEmail'),
                patient_name=data.get('patientName'),
                caregiver_name=data.get('caregiverName'),
                appointment_type=data.get('appointmentType'),
                appointment_date=data.get('appointmentDate')
            )

            return jsonify({
                'success': True,
                'appointment': {
                    **new_appointment,
                    '_id': str(result.inserted_id)
                },
                'email_sent': email_sent
            })

        except Exception as e:
            print(f"Error while booking appointment: {e}")
            return jsonify({
                'success': False,
                'message': f'Error booking appointment: {str(e)}'
            })

    caregivers = db.caregivers.find()
    caregivers_list = [{"_id": str(caregiver['_id']), "name": caregiver['name']} 
                       for caregiver in caregivers]
    return render_template('makeappointment/makeappointment.html', 
                         caregivers=caregivers_list)

app.json_encoder = JSONEncoder

# ------------------------ Search by Name or Appointment Number ------------------------
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        appointment_number = request.form.get('appointment_number')
        
        query = {}
        if full_name:
            query["full_name"] = full_name
        if appointment_number:
            query["appointment_number"] = int(appointment_number)

        results = list(appointments_collection.find(query))
        return render_template('search_results.html', results=results)

    return render_template('index/index.html')

#------------------------------Patient Dashboard-----------------------------------------------------

@app.route('/patientdashboard')
@role_required('admin', 'caregiver')
def patientdashboard():
    return render_template('patientdashboard/patientdashboard.html')


@app.route('/api/patients', methods=['GET'])
@role_required('admin', 'caregiver') 
def get_patients():
    patients = patients_collection.find()
    patient_list = [{
        '_id': str(patient['_id']),
        'name': patient['name'],
        'patient_id': patient['patient_id'],
        'location': patient['location'],
        'phone': patient['phone'],
        'email': patient.get('email', ''), 
        'age': patient['age'],
        'gender': patient['gender'],
        'blood_group': patient['blood_group']
    } for patient in patients]
    return jsonify(patient_list)


@app.route('/api/patients/<id>', methods=['GET'])
@role_required('admin', 'caregiver') 
def get_patient(id):
    patient = patients_collection.find_one({'_id': ObjectId(id)})
    if patient:
        return jsonify({
            '_id': str(patient['_id']),
            'name': patient['name'],
            'patient_id': patient['patient_id'],
            'location': patient['location'],
            'phone': patient['phone'],
            'email': patient.get('email', ''),
            'age': patient['age'],
            'gender': patient['gender'],
            'blood_group': patient['blood_group']
        })
    return jsonify({'message': 'Patient not found'}), 404

@app.route('/api/patients', methods=['POST'])
@role_required('admin', 'caregiver') 
def add_patient():
    data = request.json

    name = data['name'][:50]  
    location = data.get('location', '')[:30]  
    phone = ''.join(filter(str.isdigit, data.get('phone', '')))[:10]  
    email = data.get('email', '')[:30]
    age = min(int(data.get('age', 0)), 99) 
    blood_group = data.get('blood_group', '')[:3] 

    total_patients = patients_collection.count_documents({})
    new_patient_id = f"PID{total_patients + 1}"

    new_patient = {
        'name': name,
        'patient_id': new_patient_id,
        'location': location,
        'phone': phone,
        'email': email, 
        'age': age,
        'gender': data.get('gender', ''),
        'blood_group': blood_group
    }

    result = patients_collection.insert_one(new_patient)

    return jsonify({'message': 'Patient added successfully', 'id': str(result.inserted_id), 'patient_id': new_patient_id})


@app.route('/api/patients/<id>', methods=['PUT'])
@role_required('admin', 'caregiver') 
def update_patient(id):
    data = request.json

    name = data['name'][:50]  
    location = data.get('location', '')[:30]  
    phone = ''.join(filter(str.isdigit, data.get('phone', '')))[:10] 
    email = data.get('email', '')[:30]
    age = min(int(data.get('age', 0)), 99) 
    blood_group = data.get('blood_group', '')[:3] 

    updated_patient = {
        'name': name,
        'location': location,
        'phone': phone,
        'email': email,
        'age': age,
        'gender': data.get('gender', ''),
        'blood_group': blood_group
    }

    result = patients_collection.update_one({'_id': ObjectId(id)}, {'$set': updated_patient})
    if result.matched_count > 0:
        return jsonify({'message': 'Patient updated successfully'})
    return jsonify({'message': 'Patient not found'}), 404


@app.route('/api/patients/<id>', methods=['DELETE'])
@role_required('admin', 'caregiver') 
def delete_patient(id):
    result = patients_collection.delete_one({'_id': ObjectId(id)})
    if result.deleted_count > 0:
        return jsonify({'message': 'Patient deleted successfully'})
    return jsonify({'message': 'Patient not found'}), 404


#------------------------ Caregiver Dashboard --------------------------------------------

@app.route('/caregiverdashboard')
@role_required('admin', 'caregiver') 
def caregiverdashboard():
    return render_template('caregiverdashboard/caregiverdashboard.html')

@app.route('/api/patients', methods=['GET'])
@role_required('admin', 'caregiver')  
def get_patients_list():
    try:
        patients = patients_collection.find()
        patients_list = []

        for patient in patients:
            assigned_caregiver_id = patient.get('assigned_caregiver', None)
            caregiver_name = None

            if assigned_caregiver_id:
                caregiver = caregivers_collection.find_one({'caregiver_id': assigned_caregiver_id})
                caregiver_name = caregiver['name'] if caregiver else 'Unknown'

            patients_list.append({
                'patient_id': str(patient.get('patient_id', 'Unknown')), 
                'name': patient.get('name', 'Unknown'),
                'assigned_caregiver': caregiver_name or 'None',
                'status': patient.get('status', 'Pending')
            })

        return jsonify(patients_list), 200
    except Exception as e:
        print(f"Error fetching patients: {str(e)}")
        return jsonify({'message': 'Error fetching patients'}), 500



@app.route('/api/caregivers', methods=['GET'])
@role_required('admin', 'caregiver') 
def get_caregivers():
    try:
        caregivers = list(caregivers_collection.find({}, {'_id': 0}))
        return jsonify(caregivers)
    except Exception as e:
        return jsonify({'message': f'Error fetching caregivers: {str(e)}'}), 500


@app.route('/api/assign_caregiver', methods=['POST'])
@role_required('admin', 'caregiver') 
def assign_caregiver():
    try:
        data = request.json
        patient_id = data.get('patient_id')
        caregiver_id = data.get('caregiver_id')

        if not patient_id or not caregiver_id:
            return jsonify({'message': 'Patient ID and Caregiver ID are required'}), 400

        caregiver = caregivers_collection.find_one({'caregiver_id': caregiver_id})
        if not caregiver:
            return jsonify({'message': 'Caregiver not found'}), 404
        if not caregiver.get('available', False):
            return jsonify({'message': 'Caregiver is not available'}), 400

        patient = patients_collection.find_one({'patient_id': patient_id})
        if not patient:
            return jsonify({'message': 'Patient not found'}), 404

        if patient.get('assigned_caregiver') and patient.get('status') == 'Assigned':
            previous_caregiver_id = patient.get('assigned_caregiver')
            caregivers_collection.update_one(
                {'caregiver_id': previous_caregiver_id},
                {'$set': {'available': True}}
            )

        patients_collection.update_one(
            {'patient_id': patient_id},
            {'$set': {'assigned_caregiver': caregiver_id, 'status': 'Assigned'}}
        )

        caregivers_collection.update_one(
            {'caregiver_id': caregiver_id},
            {'$set': {'available': False}}
        )

        return jsonify({'message': 'Caregiver assigned successfully'}), 200

    except Exception as e:
        print(f"Error in assign_caregiver: {str(e)}")
        return jsonify({'message': f'Internal Server Error: {str(e)}'}), 500


@app.route('/api/remove_assignment/<patient_id>', methods=['DELETE'])
@role_required('admin', 'caregiver') 
def remove_assignment(patient_id):
    try:
        patient = patients_collection.find_one({'patient_id': patient_id})
        if not patient:
            return jsonify({'message': 'Patient not found'}), 404

        assigned_caregiver = patient.get('assigned_caregiver')

        patients_collection.update_one(
            {'patient_id': patient_id},
            {'$set': {'status': 'Pending'}, '$unset': {'assigned_caregiver': ''}} 
        )

        if assigned_caregiver:
            caregivers_collection.update_one(
                {'caregiver_id': assigned_caregiver},
                {'$set': {'available': True}}
            )

        return jsonify({'message': 'Caregiver removed successfully!'})
    except Exception as e:
        print(f"Error removing assignment: {str(e)}")
        return jsonify({'message': f'Internal Server Error: {str(e)}'}), 500


@app.route('/api/update_availability/<caregiver_id>', methods=['PUT'])
@role_required('admin', 'caregiver') 
def update_caregiver_availability(caregiver_id):
    try:
        if not caregiver_id.startswith('CG') or len(caregiver_id) != 5 or not caregiver_id[2:].isdigit():
            return jsonify({'message': 'Caregiver ID must be in the format "CG001"'}), 400

        data = request.get_json()
        available = data.get('available')
        if available is None:
            return jsonify({'message': 'Missing availability field'}), 400

        caregiver = caregivers_collection.find_one({'caregiver_id': caregiver_id})
        if caregiver:
            caregivers_collection.update_one(
                {'caregiver_id': caregiver_id},
                {'$set': {'available': available}}
            )
            return jsonify({'message': 'Caregiver availability updated successfully!'}), 200
        else:
            return jsonify({'message': 'Caregiver not found!'}), 404
    except Exception as e:
        return jsonify({'message': f'Internal Server Error: {str(e)}'}), 500



@app.route('/api/patients/<patient_id>/status', methods=['PUT'])
@role_required('admin', 'caregiver')
def update_patient_status(patient_id):
    data = request.json
    new_status = data.get('status')
    if not new_status:
        return jsonify({'message': 'Status is required'}), 400

    try:
        patients_collection.update_one(
            {'patient_id': patient_id},
            {'$set': {'status': new_status}}
        )
        return jsonify({'message': 'Patient status updated successfully!'}), 200
    except Exception as e:
        return jsonify({'message': f'Error updating status: {str(e)}'}), 500
    
    
#---------------------- Reminder Appointment ------------------------------------------------

scheduler = BackgroundScheduler()
scheduler.start()

def send_reminder_email(patient_email, patient_name, caregiver_name, appointment_type, appointment_date):
    """Send reminder email for upcoming appointment"""
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = patient_email
        msg['Subject'] = 'JKL Healthcare - Appointment Reminder'

        body = f"""
        Dear {patient_name},

        This is a reminder for your upcoming appointment at JKL Healthcare.

        Appointment Details:
        Time: {appointment_date.strftime('%B %d, %Y at %I:%M %p')}
        Caregiver: {caregiver_name}
        Type: {appointment_type}

        Location: JKL Healthcare Center

        Important Reminders:
        - Please arrive 15 minutes before your scheduled time
        - Bring any relevant medical records or documentation
        - If you need to reschedule, please contact us immediately

        We look forward to seeing you!

        Best regards,
        JKL Healthcare Team
        """

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        print(f"Reminder email sent successfully to {patient_email}")
        return True
    except Exception as e:
        print(f"Failed to send reminder email: {str(e)}")
        return False
    
def schedule_reminder_email(appointment):
    """Schedule a reminder email for 1 hour before the appointment"""
    try:
        appointment_date = datetime.strptime(appointment['appointmentDate'], '%Y-%m-%dT%H:%M')
        
        reminder_time = appointment_date - timedelta(hours=1)
        
        if reminder_time > datetime.now():
            scheduler.add_job(
                send_reminder_email,
                trigger=DateTrigger(run_date=reminder_time),
                args=[
                    appointment['email'],
                    appointment['patientName'],
                    appointment['caregiverName'],
                    appointment['appointmentType'],
                    appointment_date
                ],
                id=f"reminder_{str(appointment['_id'])}",
                replace_existing=True
            )
            print(f"Reminder scheduled for {appointment['patientName']} at {reminder_time}")
            return True
    except Exception as e:
        print(f"Error scheduling reminder: {str(e)}")
    return False


#-------------------------- Appointment ------------------------------------------------

@app.route('/appointment_scheduling')
@role_required('admin', 'caregiver')  
def appointment_scheduling():
    return render_template('appointment/appointment.html')

@app.route('/appointments', methods=['GET'])
@role_required('admin', 'caregiver')
def get_appointments():
    appointments = list(appointments_collection.find())
    for appointment in appointments:
        appointment['patientName'] = appointment.get('patient_name', appointment.get('patientName', 'N/A'))
        appointment['appointmentDate'] = appointment.get('date', appointment.get('appointmentDate', 'N/A'))
        appointment['appointmentType'] = appointment.get('appointment_type', appointment.get('appointmentType', 'N/A'))
        appointment['caregiverName'] = appointment.get('caregiver', {}).get('name', appointment.get('caregiverName', 'N/A'))
        appointment['caregiverEmail'] = appointment.get('email', appointment.get('caregiverEmail', 'N/A'))
        appointment['status'] = appointment.get('status', 'Scheduled')
        
        appointment['_id'] = str(appointment['_id'])

    return jsonify(appointments)

@app.route('/appointments', methods=['POST'])
@role_required('admin', 'caregiver')
def create_appointment():
    try:
        data = request.json
        print("Received data:", data)
        
        patient_name = data.get('patientName', '')[:50]
        caregiver_name = data.get('caregiverName', '')[:50]
        caregiver_email = data.get('caregiverEmail', '')
        appointment_date = data.get('appointmentDate', '')
        appointment_type = data.get('appointmentType', '')[:30]
        notes = data.get('notes', '')[:255]

        if not re.match(r"[^@]+@[^@]+\.[^@]+", caregiver_email):
            print(f"Invalid email format: {caregiver_email}")
            return jsonify({
                "success": False,
                "message": "Invalid email format"
            }), 400

        new_appointment = {
            "patientName": patient_name,
            "caregiverName": caregiver_name,
            "email": caregiver_email, 
            "appointmentDate": appointment_date,
            "appointmentType": appointment_type,
            "notes": notes,
            "status": "Scheduled"
        }

        result = appointments_collection.insert_one(new_appointment)
        new_appointment['_id'] = str(result.inserted_id)

        schedule_reminder_email(new_appointment)

        return jsonify({
            "success": True,
            "message": "Appointment created successfully and reminder scheduled",
            "appointment": new_appointment
        })

    except Exception as e:
        print(f"Error creating appointment: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Failed to create appointment: {str(e)}"
        }), 500


@app.route('/appointments/<id>', methods=['GET'])
@role_required('admin', 'caregiver')
def get_appointment(id):
    appointment = appointments_collection.find_one({"_id": ObjectId(id)})
    if appointment:
        appointment['_id'] = str(appointment['_id'])
        return jsonify(appointment)
    return jsonify({"msg": "Appointment not found"}), 404


#----------------------------- update appointment ------------------------------------

def send_appointment_email(patient_email, appointment_data, is_update=False):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = patient_email
        msg['Subject'] = "Appointment Update Notification" if is_update else "New Appointment Confirmation"
        try:
            appointment_date = datetime.strptime(
                appointment_data['appointmentDate'], 
                '%Y-%m-%dT%H:%M:%S.%fZ'
            )
        except ValueError:
            try:
                appointment_date = datetime.strptime(
                    appointment_data['appointmentDate'], 
                    '%Y-%m-%dT%H:%M'
                )
            except ValueError:
                appointment_date = datetime.strptime(
                    appointment_data['appointmentDate'], 
                    '%Y-%m-%d'
                )

        formatted_date = appointment_date.strftime('%B %d, %Y at %I:%M %p')

        body = f"""
        Dear {appointment_data['patientName']},

        {'Your appointment has been updated. ' if is_update else 'Your appointment has been scheduled. '}
        
        Appointment Details:
        Date and Time: {formatted_date}
        Type: {appointment_data['appointmentType']}
        Caregiver: {appointment_data['caregiverName']}
        
        Additional Notes: {appointment_data.get('notes', 'None')}

        If you need to make any changes, please contact us.

        Best regards,
        Your Healthcare Team
        """

        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

@app.route('/appointments/<id>', methods=['PUT'])
@role_required('admin', 'caregiver')
def update_appointment(id):
    try:
        data = request.json
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", data.get('caregiverEmail', '')):
            return jsonify({
                "success": False,
                "message": "Invalid email format"
            }), 400

        current_appointment = appointments_collection.find_one({"_id": ObjectId(id)})
        if not current_appointment:
            return jsonify({
                "success": False,
                "message": "Appointment not found"
            }), 404

        update_data = {
            "patientName": data.get('patientName', '')[:50],
            "caregiverName": data.get('caregiverName', '')[:50],
            "email": data.get('caregiverEmail', ''),
            "appointmentDate": data.get('appointmentDate', ''),
            "appointmentType": data.get('appointmentType', '')[:30],
            "notes": data.get('notes', '')[:255],
            "status": "Scheduled"
        }

        date_changed = current_appointment.get('appointmentDate') != update_data['appointmentDate']

        result = appointments_collection.update_one(
            {"_id": ObjectId(id)}, 
            {"$set": update_data}
        )

        if result.matched_count > 0:
            try:
                scheduler.remove_job(f"reminder_{id}")
            except:
                pass
            
            update_data['_id'] = id
            schedule_reminder_email(update_data)

            if date_changed:
                email_sent = send_appointment_email(
                    update_data['email'], 
                    update_data,
                    is_update=True
                )
                message = "Appointment updated successfully and notification sent" if email_sent else "Appointment updated but failed to send notification"
            else:
                message = "Appointment updated successfully"

            return jsonify({
                "success": True,
                "message": message
            })
            
        return jsonify({
            "success": False,
            "message": "Appointment not found"
        }), 404

    except Exception as e:
        print(f"Error updating appointment: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Failed to update appointment: {str(e)}"
        }), 500



@app.route('/appointments/<id>', methods=['DELETE'])
@role_required('admin', 'caregiver')
def delete_appointment(id):
    try:
        try:
            scheduler.remove_job(f"reminder_{id}")
        except:
            pass
        
        delete_result = appointments_collection.delete_one({"_id": ObjectId(id)})
        if delete_result.deleted_count == 1:
            return jsonify({"msg": "Appointment and reminder deleted successfully"})
        else:
            return jsonify({"msg": "Appointment not found"}), 404
    except Exception as e:
        return jsonify({"msg": f"Error deleting appointment: {str(e)}"}), 500


#-------------------- caregivers list-------------------------------------------
#-------------------- email: unit.tester850@gmail.com --------------------------
#-------------------- pass: youcatchme -----------------------------------------

@app.route('/caregiverlist')
@role_required('admin')  
def caregiverlist():
    return render_template('caregiverslist/caregiverlist.html')

@app.route('/api/caregiverslist', methods=['GET'])
@role_required('admin') 
def get_caregiverslist():
    caregiverslist = caregivers_collection.find()
    caregiverslist = [{
        '_id': str(caregiver['_id']),
        'name': caregiver.get('name', 'Unknown'),
        'caregiver_id': caregiver.get('caregiver_id', ''),
        'location': caregiver.get('location', 'N/A'),
        'phone': caregiver.get('phone', 'N/A'),
        'age': caregiver.get('age', 'N/A'),
        'gender': caregiver.get('gender', 'N/A'),
        'specializations': caregiver.get('specializations', [])
    } for caregiver in caregiverslist]
    return jsonify(caregiverslist)


@app.route('/api/caregiverslist', methods=['POST'])
@role_required('admin') 
def add_caregiver():
    data = request.json
    total_caregivers = caregivers_collection.count_documents({})
    new_caregiver_id = f"CG{total_caregivers + 1:03d}" 

    name = data['name'][:50]  
    location = data.get('location', '')[:30]  
    phone = ''.join(filter(str.isdigit, data.get('phone', '')))[:10]  
    age = min(int(data.get('age', 0)), 99)  
    specializations = data.get('specializations', [])  
    gender = data.get('gender', '')  

    new_caregiver = {
        'name': name,
        'caregiver_id': new_caregiver_id, 
        'location': location,
        'phone': phone,
        'age': age,
        'gender': gender,
        'specializations': specializations,
        'available': data.get('available', False) 
    }

    result = caregivers_collection.insert_one(new_caregiver)
    return jsonify({'message': 'Caregiver added successfully', 'id': str(result.inserted_id), 'caregiver_id': new_caregiver_id})



@app.route('/api/caregiverslist/<id>', methods=['GET'])
@role_required('admin')  
def get_caregiver(id):
    caregiver = caregivers_collection.find_one({'_id': ObjectId(id)})
    if caregiver:
        caregiver['_id'] = str(caregiver['_id'])  
        return jsonify(caregiver)
    return jsonify({'message': 'Caregiver not found'}), 404

@app.route('/api/caregiverslist/<id>', methods=['PUT'])
@role_required('admin') 
def update_caregiver(id):
    data = request.json

    name = data['name'][:50] 
    location = data.get('location', '')[:30] 
    phone = ''.join(filter(str.isdigit, data.get('phone', '')))[:10] 
    age = min(int(data.get('age', 0)), 99) 
    specializations = data.get('specializations', []) 
    gender = data.get('gender', '')

    updated_caregiver = {
        'name': name,
        'location': location,
        'phone': phone,
        'age': age,
        'gender': gender,
        'specializations': specializations
    }

    result = caregivers_collection.update_one({'_id': ObjectId(id)}, {'$set': updated_caregiver})
    if result.matched_count > 0:
        return jsonify({'message': 'Caregiver updated successfully'})
    return jsonify({'message': 'Caregiver not found'}), 404


@app.route('/api/caregiverslist/<id>', methods=['DELETE'])
@role_required('admin')
def delete_caregiver(id):
    result = caregivers_collection.delete_one({'_id': ObjectId(id)})
    if result.deleted_count > 0:
        return jsonify({'message': 'Caregiver deleted successfully'})
    return jsonify({'message': 'Caregiver not found'}), 404



#----------------------------------- Forget Password ----------------------------------------------

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        flash('Password reset instructions sent to your email', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password/forgot_password.html')

if __name__ == '__main__':
    app.run(debug=True)
