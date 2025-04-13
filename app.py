from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grades.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'dev-secret-key'  # Change this in production!
app.config['SECRET_KEY'] = 'another-dev-secret-key'  # For Flask sessions, CSRF, etc.

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)
jwt = JWTManager(app)

# Models definition (same as before)
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='student')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with enrollments
    enrollments = db.relationship('Enrollment', backref='student', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Class(db.Model):
    __tablename__ = 'classes'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    capacity = db.Column(db.Integer, default=30)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship with enrollments
    enrollments = db.relationship('Enrollment', backref='class_obj', lazy=True)
    
    def current_enrollment_count(self):
        return len(self.enrollments)
    
    def is_full(self):
        return self.current_enrollment_count() >= self.capacity
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'capacity': self.capacity,
            'current_enrollment': self.current_enrollment_count(),
            'is_full': self.is_full(),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'), nullable=False)
    grade = db.Column(db.String(5), default=None)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'student_id': self.student_id,
            'class_id': self.class_id,
            'grade': self.grade,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Set up Flask-Admin
admin = Admin(app, name='Grades App Admin', template_mode='bootstrap3')

# Create custom ModelView to control access
class SecureModelView(ModelView):
    def is_accessible(self):
        # In a real app, you'd check if the current user is an admin
        # For now, we'll leave it open for simplicity
        return True
    
    def inaccessible_callback(self, name, **kwargs):
        # Redirect to login page if user doesn't have access
        return redirect(url_for('login', next=request.url))

# Add model views
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Class, db.session))
admin.add_view(SecureModelView(Enrollment, db.session))

# Create a templates folder for our HTML files
os.makedirs('templates', exist_ok=True)

# Routes for the API (same as before)
@app.route('/api/users/register', methods=['POST'])
def api_register():
    data = request.get_json()
    
    # Check if required fields are provided
    if not all(k in data for k in ['name', 'email', 'password']):
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Check if user already exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'User already exists'}), 400
    
    # Create new user
    new_user = User(
        name=data['name'],
        email=data['email'],
        role=data.get('role', 'student')
    )
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    # Generate token
    access_token = create_access_token(identity=new_user.id)
    
    return jsonify({
        'message': 'User registered successfully',
        'user': new_user.to_dict(),
        'token': access_token
    }), 201

@app.route('/api/users/login', methods=['POST'])
def api_login():
    data = request.get_json()
    
    # Check if required fields are provided
    if not all(k in data for k in ['email', 'password']):
        return jsonify({'message': 'Missing email or password'}), 400
    
    # Find user by email
    user = User.query.filter_by(email=data['email']).first()
    
    # Check if user exists and password is correct
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    # Generate token
    access_token = create_access_token(identity=user.id)
    
    return jsonify({
        'message': 'Login successful',
        'user': user.to_dict(),
        'token': access_token
    }), 200

# Keep other API routes the same...

# Web routes for the frontend
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            # In a real app, you would use Flask-Login for session management
            # For simplicity, we'll just redirect to the dashboard
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid email or password'
    
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            error = 'Email already registered'
        else:
            new_user = User(name=name, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    
    return render_template('register.html', error=error)

@app.route('/dashboard')
def dashboard():
    # In a real app, you would check if the user is logged in
    # For simplicity, we'll just render the dashboard
    classes = Class.query.all()
    return render_template('dashboard.html', classes=classes)

# Create database tables
with app.app_context():
    db.create_all()

# Run the app
if __name__ == '__main__':
    app.run(debug=True)