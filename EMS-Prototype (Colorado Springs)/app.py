from datetime import datetime, timedelta, timezone
from functools import wraps
import os
from flask import Flask, request, jsonify, abort, render_template, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import requests

# Basic configuration
app = Flask(__name__)
base_dir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, 'ems.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('EMS_SECRET_KEY', 'dev-secret-key')

db = SQLAlchemy(app)

# Files/uploads
UPLOAD_FOLDER = os.path.join(base_dir, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(50), default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {"id": self.id, "username": self.username, "email": self.email, "role": self.role}

class Equipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    location = db.Column(db.String(120))

    def to_dict(self):
        return {"id": self.id, "name": self.name, "quantity": self.quantity, "location": self.location}

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    owner = db.relationship('User', backref='events')

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "owner_id": self.owner_id,
        }

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref='reservations')
    equipment = db.relationship('Equipment', backref='reservations')

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "equipment_id": self.equipment_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
        }

class IncidentReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(40), nullable=False)
    emergency_type = db.Column(db.String(40), nullable=False)
    location = db.Column(db.String(80), nullable=False)
    severity_level = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text)  # New field for emergency description
    media_filename = db.Column(db.String(255))  # New field for uploaded photo/video filename
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    admin_reply = db.Column(db.Text)  # New field for admin reply

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'phone': self.phone,
            'emergency_type': self.emergency_type,
            'location': self.location,
            'severity_level': self.severity_level,
            'description': self.description,
            'media_filename': self.media_filename,
            'timestamp': self.timestamp.isoformat(),
            'admin_reply': self.admin_reply,  # Include admin reply in dict
        }

# Utility functions
def create_db():
    # Ensure we run within the Flask application context when creating DB
    with app.app_context():
        db.create_all()

def generate_token(user, expires_in=3600):
    # Use timezone-aware UTC datetimes and provide exp as a POSIX timestamp
    exp_dt = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    payload = {
        'user_id': user.id,
        'exp': int(exp_dt.timestamp())
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth = request.headers.get('Authorization')
            parts = auth.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                raise Exception('User not found')
        except Exception as e:
            return jsonify({'message': 'Token is invalid', 'error': str(e)}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Weather API config
# Set OpenWeatherMap API key directly in code (for local/testing only)
WEATHER_API_KEY = '8823ebdcc546e7e31b204b65d808f948'
WEATHER_URL = 'https://api.openweathermap.org/data/2.5/weather'
CO_SPRINGS_COORDS = {'lat': 38.8339, 'lon': -104.8214}

def get_weather():
    params = {
        'lat': CO_SPRINGS_COORDS['lat'],
        'lon': CO_SPRINGS_COORDS['lon'],
        'appid': WEATHER_API_KEY,
        'units': 'imperial'
    }
    try:
        resp = requests.get(WEATHER_URL, params=params, timeout=5)
        data = resp.json()
        icon = data['weather'][0]['icon'] if 'weather' in data and data['weather'] else None
        temp = data['main']['temp'] if 'main' in data else None
        desc = data['weather'][0]['description'] if 'weather' in data and data['weather'] else None
        return {'icon': icon, 'temp': temp, 'desc': desc}
    except Exception:
        return {'icon': None, 'temp': None, 'desc': None}

# Routes
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})


# --- Demo site routes (HTML pages) ---
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.utcnow().year}


# Simple in-memory demo buildings data used for the template views
DEMO_BUILDINGS = [
    {
        'id': 1,
        'name': 'Central Library',
        'address': '101 Main St',
        'city': 'Colorado Springs',
        'description': 'Municipal library with multiple meters and HVAC zones.',
        'photo': 'security_library.png',  # Updated image
        'meters': [
            {'name': 'Main Meter', 'latest_value': 1250, 'units': 'kWh'},
            {'name': 'HVAC', 'latest_value': 540, 'units': 'kWh'},
        ],
        'alerts': ['High HVAC usage on 2025-09-20'],
    'updated_at': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    },
    {
        'id': 2,
        'name': 'Community Center',
        'address': '500 Elm Ave',
        'city': 'Colorado Springs',
        'description': 'Gym and meeting rooms.',
        'photo': 'community_center.png',  # Updated image
        'meters': [
            {'name': 'Main Meter', 'latest_value': 980, 'units': 'kWh'}
        ],
        'alerts': [],
    'updated_at': (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    }
]


@app.route('/')
def index():
    return render_template('home.html', hide_navbar=True)


@app.route('/login', methods=['GET', 'POST'])
def web_login():
    if request.method == 'POST':
        # Simple demo behavior: accept any credentials and redirect to dashboard
        email = request.form.get('email') or request.form.get('username')
        flash(f'Signed in as {email}')
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    stats = {
        'total_energy': '123,456 kWh',
        'savings': '$12,345',
        'alerts': 2
    }
    return render_template('dashboard.html', stats=stats)


@app.route('/buildings')
def buildings():
    return render_template('buildings.html', buildings=DEMO_BUILDINGS)


@app.route('/building/<int:building_id>')
def building_detail(building_id):
    b = next((x for x in DEMO_BUILDINGS if x['id'] == building_id), None)
    if not b:
        abort(404)
    building = dict(b)
    photo_filename = building.get('photo')
    photo_url = None
    if photo_filename:
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
        if os.path.exists(upload_path):
            photo_url = url_for('uploaded_file', filename=photo_filename)
        else:
            photo_url = url_for('static', filename=f'images/{photo_filename}')
    else:
        photo_url = url_for('static', filename='images/placeholder.png')
    building['photo_url'] = photo_url
    return render_template('building_detail.html', building=building)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(dest)
        flash(f'Uploaded {filename}')
        return redirect(url_for('upload'))
    return render_template('upload.html', buildings=DEMO_BUILDINGS)


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')

# Auth: register & login
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if not username or not email or not password:
        return jsonify({'message': 'username, email and password are required'}), 400
    if User.query.filter((User.username==username)|(User.email==email)).first():
        return jsonify({'message': 'User with that username or email already exists'}), 400
    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    token = generate_token(user)
    return jsonify({'user': user.to_dict(), 'token': token})

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'username and password required'}), 400
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid credentials'}), 401
    token = generate_token(user)
    return jsonify({'user': user.to_dict(), 'token': token})

# User endpoints
@app.route('/users', methods=['GET'])
@token_required
def list_users(current_user):
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])

@app.route('/users/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

# Equipment endpoints
@app.route('/equipment', methods=['GET'])
@token_required
def list_equipment(current_user):
    items = Equipment.query.all()
    return jsonify([e.to_dict() for e in items])

@app.route('/equipment', methods=['POST'])
@token_required
def create_equipment(current_user):
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required'}), 403
    data = request.get_json() or {}
    name = data.get('name')
    quantity = int(data.get('quantity', 1))
    location = data.get('location')
    if not name:
        return jsonify({'message': 'name is required'}), 400
    eq = Equipment(name=name, quantity=quantity, location=location)
    db.session.add(eq)
    db.session.commit()
    return jsonify(eq.to_dict()), 201

@app.route('/equipment/<int:eq_id>', methods=['PUT'])
@token_required
def update_equipment(current_user, eq_id):
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required'}), 403
    eq = Equipment.query.get_or_404(eq_id)
    data = request.get_json() or {}
    eq.name = data.get('name', eq.name)
    eq.quantity = int(data.get('quantity', eq.quantity))
    eq.location = data.get('location', eq.location)
    db.session.commit()
    return jsonify(eq.to_dict())

@app.route('/equipment/<int:eq_id>', methods=['DELETE'])
@token_required
def delete_equipment(current_user, eq_id):
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required'}), 403
    eq = Equipment.query.get_or_404(eq_id)
    db.session.delete(eq)
    db.session.commit()
    return jsonify({'message': 'deleted'})

# Events endpoints
@app.route('/events', methods=['GET'])
@token_required
def list_events(current_user):
    events = Event.query.all()
    return jsonify([e.to_dict() for e in events])

@app.route('/events', methods=['POST'])
@token_required
def create_event(current_user):
    data = request.get_json() or {}
    title = data.get('title')
    description = data.get('description')
    start_time = data.get('start_time')
    end_time = data.get('end_time')
    if not title or not start_time or not end_time:
        return jsonify({'message': 'title, start_time and end_time required'}), 400
    try:
        st = datetime.fromisoformat(start_time)
        et = datetime.fromisoformat(end_time)
    except Exception:
        return jsonify({'message': 'Invalid datetime format. Use ISO format.'}), 400
    if et <= st:
        return jsonify({'message': 'end_time must be after start_time'}), 400
    event = Event(title=title, description=description, start_time=st, end_time=et, owner=current_user)
    db.session.add(event)
    db.session.commit()
    return jsonify(event.to_dict()), 201

@app.route('/events/<int:event_id>', methods=['PUT'])
@token_required
def update_event(current_user, event_id):
    event = Event.query.get_or_404(event_id)
    if event.owner_id != current_user.id and current_user.role != 'admin':
        return jsonify({'message': 'Not authorized to edit this event'}), 403
    data = request.get_json() or {}
    event.title = data.get('title', event.title)
    event.description = data.get('description', event.description)
    if 'start_time' in data:
        try:
            event.start_time = datetime.fromisoformat(data['start_time'])
        except Exception:
            return jsonify({'message': 'Invalid start_time format'}), 400
    if 'end_time' in data:
        try:
            event.end_time = datetime.fromisoformat(data['end_time'])
        except Exception:
            return jsonify({'message': 'Invalid end_time format'}), 400
    if event.end_time <= event.start_time:
        return jsonify({'message': 'end_time must be after start_time'}), 400
    db.session.commit()
    return jsonify(event.to_dict())

@app.route('/events/<int:event_id>', methods=['DELETE'])
@token_required
def delete_event(current_user, event_id):
    event = Event.query.get_or_404(event_id)
    if event.owner_id != current_user.id and current_user.role != 'admin':
        return jsonify({'message': 'Not authorized to delete this event'}), 403
    db.session.delete(event)
    db.session.commit()
    return jsonify({'message': 'deleted'})

# Reservations endpoints
@app.route('/reservations', methods=['GET'])
@token_required
def list_reservations(current_user):
    if current_user.role == 'admin':
        res = Reservation.query.all()
    else:
        res = Reservation.query.filter_by(user_id=current_user.id).all()
    return jsonify([r.to_dict() for r in res])

@app.route('/reservations', methods=['POST'])
@token_required
def create_reservation(current_user):
    data = request.get_json() or {}
    equipment_id = data.get('equipment_id')
    start_time = data.get('start_time')
    end_time = data.get('end_time')
    if not equipment_id or not start_time or not end_time:
        return jsonify({'message': 'equipment_id, start_time and end_time required'}), 400
    equipment = Equipment.query.get_or_404(equipment_id)
    try:
        st = datetime.fromisoformat(start_time)
        et = datetime.fromisoformat(end_time)
    except Exception:
        return jsonify({'message': 'Invalid datetime format'}), 400
    if et <= st:
        return jsonify({'message': 'end_time must be after start_time'}), 400
    # Check for overlapping reservations for the same equipment
    overlapping = Reservation.query.filter(
        Reservation.equipment_id==equipment_id,
        Reservation.start_time < et,
        Reservation.end_time > st
    ).count()
    if overlapping >= equipment.quantity:
        return jsonify({'message': 'Equipment not available for the requested time range'}), 409
    res = Reservation(user=current_user, equipment=equipment, start_time=st, end_time=et)
    db.session.add(res)
    db.session.commit()
    return jsonify(res.to_dict()), 201

@app.route('/reservations/<int:res_id>', methods=['DELETE'])
@token_required
def delete_reservation(current_user, res_id):
    res = Reservation.query.get_or_404(res_id)
    if res.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'message': 'Not authorized to delete this reservation'}), 403
    db.session.delete(res)
    db.session.commit()
    return jsonify({'message': 'deleted'})

# Incident reporting endpoint
@app.route('/api/report-incident', methods=['POST'])
def report_incident():
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        # Handle file upload
        name = request.form.get('name')
        phone = request.form.get('phone')
        emergency_type = request.form.get('type')
        location = request.form.get('location')
        severity_level = request.form.get('severity')
        description = request.form.get('description')
        file = request.files.get('media')
        media_filename = None
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            media_filename = filename
    else:
        data = request.get_json() or {}
        name = data.get('name')
        phone = data.get('phone')
        emergency_type = data.get('type')
        location = data.get('location')
        severity_level = data.get('severity')
        description = data.get('description')
        media_filename = data.get('media_filename')
    try:
        severity_level = int(severity_level)
    except (TypeError, ValueError):
        return jsonify({'message': 'Severity level must be a number.'}), 400
    if not all([name, phone, emergency_type, location, severity_level]):
        return jsonify({'message': 'All fields are required.'}), 400
    report = IncidentReport(
        name=name,
        phone=phone,
        emergency_type=emergency_type,
        location=location,
        severity_level=severity_level,
        description=description,
        media_filename=media_filename
    )
    db.session.add(report)
    db.session.commit()
    return jsonify({'message': 'Incident reported successfully.'}), 201

@app.route('/incidents')
def list_incidents():
    incidents = IncidentReport.query.order_by(IncidentReport.timestamp.desc()).all()
    return render_template('incidents.html', incidents=incidents)

@app.route('/api/user-reports')
def user_reports():
    # For demo: filter by phone if user is logged in, else return all (in real app, use user id or session)
    phone = request.args.get('phone')
    # In a real app, use current_user or session info
    # Here, just return all reports for demo
    reports = IncidentReport.query.order_by(IncidentReport.timestamp.desc()).all()
    return jsonify([r.to_dict() for r in reports])

@app.route('/api/active-incidents')
def active_incidents():
    # For demo: map location names to coordinates (Colorado Springs neighborhoods)
    location_coords = {
        'Briargate': [38.9585, -104.7814],
        'Central': [38.8462, -104.8007],
        'Downtown': [38.8339, -104.8214],
        'East Colorado Springs': [38.8590, -104.7557],
        'Falcon': [38.9383, -104.6072],
        'Manitou Springs': [38.8597, -104.9172],
        'Northgate': [39.0167, -104.8208],
        'Old Colorado City': [38.8503, -104.8572],
        'Powers': [38.8837, -104.7169],
        'Rockrimmon': [38.9111, -104.8606],
        'Security-Widefield': [38.7472, -104.7358],
        'Southwest': [38.7916, -104.8769],
        'West Colorado Springs': [38.8590, -104.8769],
        'Other': [38.8339, -104.8214],
    }
    incidents = IncidentReport.query.order_by(IncidentReport.timestamp.desc()).limit(100).all()
    result = []
    for i in incidents:
        coords = location_coords.get(i.location)
        d = i.to_dict()
        d['location_coords'] = coords
        result.append(d)
    return jsonify(result)

@app.route('/api/active-incidents-count')
def active_incidents_count():
    count = IncidentReport.query.count()
    return jsonify({'count': count})

# CLI helper to initialize DB
@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    create_db()
    print('Initialized the database.')

@app.route('/incidents/<int:incident_id>/reply', methods=['POST'])
def admin_reply(incident_id):
    incident = IncidentReport.query.get_or_404(incident_id)
    reply = request.form.get('admin_reply')
    if reply is not None:
        incident.admin_reply = reply
        db.session.commit()
        flash('Reply sent.', 'success')
    else:
        flash('Reply cannot be empty.', 'danger')
    return redirect(url_for('list_incidents'))

DEVELOPMENT_MODE = True

@app.route('/incidents/<int:incident_id>/delete', methods=['POST'])
def delete_incident(incident_id):
    if not DEVELOPMENT_MODE:
        # Normally you'd check current_user.role
        return abort(403)

    incident = IncidentReport.query.get_or_404(incident_id)
    db.session.delete(incident)
    db.session.commit()
    flash('Incident deleted.', 'success')
    return redirect(url_for('list_incidents'))

@app.route('/api/weather')
def weather():
    return jsonify(get_weather())

if __name__ == '__main__':
    # Ensure DB exists
    if not os.path.exists(os.path.join(base_dir, 'ems.db')):
        create_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
